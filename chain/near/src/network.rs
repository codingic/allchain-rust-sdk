//! 网络端点与 RPC 客户端构造。
//!
//! ## 归档端点（archival RPC）—— NEAR 最容易踩的坑
//! NEAR 的常规 RPC 节点（`rpc.mainnet.near.org`）**只保留最近若干 epoch
//! （大致几天）的数据**。查询一笔稍旧的交易会得到一个含糊的 `UNKNOWN_TRANSACTION`
//! 或直接超时，很多人因此误以为交易不存在。
//!
//! 查历史数据必须换成**归档节点**：`https://archival-rpc.mainnet.near.org`。
//! 本 SDK 不内置这个地址（它与网络名不是一对一关系），
//! 需要查历史的调用方请自行通过 `--rpc-url` 指定。

// `JsonRpcClient` 是 near 官方的 **async** JSON-RPC 客户端（底层是 reqwest 的异步版本）。
// 与 Solana 那侧的同步 `RpcClient` 不同，它可以直接在 async 上下文里 `.await`，
// 不需要 `spawn_blocking` 包装——这也是 NEAR adapter 里没有 blocking 辅助函数的原因。
use near_jsonrpc_client::JsonRpcClient;

/// 预置网络选择。
///
/// 语法说明：`#[derive(...)]` 里前五个是标准 trait，
/// `clap::ValueEnum` 则让本枚举可以直接用作命令行参数类型
/// （自动生成「字符串 <-> 变体」的解析、`--help` 的可选取值提示与 shell 补全）。
/// 这里写的是**完整路径** `clap::ValueEnum` 而非先 `use` 再写 `ValueEnum`，
/// 两者等价；只用一次时写完整路径更省一行。
///
/// `ValueEnum` 要求枚举是**无字段**的（unit variant），否则无法从字符串还原。
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NetworkArg {
    /// 主网。所有真实资产所在的链，账户名后缀为 `.near`。
    Mainnet,
    /// 测试网。账户名后缀为 `.testnet`，水龙头可直接创建账户。
    Testnet,
    /// 本机 `nearcore`（默认 `http://127.0.0.1:3030`）。
    Localnet,
}

// 固有实现块：给 `NetworkArg` 挂方法。
impl NetworkArg {
    /// 该网络的默认 RPC 端点。
    ///
    /// 语法说明：`self` 按值接收（本枚举 `Copy`，不会发生所有权转移）；
    /// `&'static str` 表示返回的是编译进二进制的字符串字面量，活得比任何调用者都久。
    pub fn rpc_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://rpc.mainnet.near.org",
            NetworkArg::Testnet => "https://rpc.testnet.near.org",
            NetworkArg::Localnet => "http://127.0.0.1:3030",
        }
    }

    /// 区块浏览器基础地址；localnet 没有公共浏览器，故为 `None`。
    ///
    /// 语法说明：`Option<&'static str>` 用来表达「可能没有」。
    /// Rust 没有 `null`，调用方必须显式处理 `None` 分支，
    /// 于是「忘了处理无浏览器这种情况」在编译期就会被拦住。
    pub fn explorer_base(self) -> Option<&'static str> {
        match self {
            // 主网与测试网用**两个不同域名**（不是靠查询参数区分），
            // 这与 Solana 那边「同域名 + `?cluster=`」的做法不同。
            NetworkArg::Mainnet => Some("https://explorer.near.org"),
            NetworkArg::Testnet => Some("https://explorer.testnet.near.org"),
            NetworkArg::Localnet => None,
        }
    }

    /// 网络短名，与 CLI 参数取值一致。
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Testnet => "testnet",
            NetworkArg::Localnet => "localnet",
        }
    }
}

use near_primitives::views::TxExecutionStatus;

/// 交易查询的等待阶段（对应 NEAR RPC 的 `wait_until` 参数）。
///
/// NEAR 的交易是**异步、跨分片执行**的：一笔交易发出后先产生 receipt，
/// 再由 receipt 在目标分片上执行，执行完还可能产生退款 receipt。
/// 因此「交易状态」不像 EVM 那样只有「成功/失败」两档，而是一整套执行阶段。
/// `wait_until` 决定节点在**返回响应之前**要等到哪个阶段：
/// 选得越靠后，返回越慢，但能拿到完整的手续费、日志与最终状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum WaitUntilArg {
    /// 不等待，立即返回当前状态
    None,
    /// 交易已入块（未最终确认）
    Included,
    /// 交易已完成执行（乐观，默认）
    ExecutedOptimistic,
    /// 交易已入最终确认区块
    IncludedFinal,
    /// 交易在最终区块中完成执行
    Executed,
    /// 所有收据（含退款收据）均已最终确认
    Final,
}

/// 把 CLI 侧的枚举转换成官方 SDK 的 `TxExecutionStatus`。
///
/// 语法说明：`impl From<A> for B` 是**标准库 trait 实现块**。
/// 实现 `From` 之后会自动获得反向的 `Into`（标准库有 blanket impl），
/// 于是调用方既能写 `TxExecutionStatus::from(arg)` 也能写 `arg.into()`。
///
/// 本枚举**有意**与 `TxExecutionStatus` 保持同构：它存在的唯一理由是给 CLI
/// 一个可解析的版本——官方类型来自外部 crate，无法直接派生 clap 的 trait（孤儿规则）。
impl From<WaitUntilArg> for TxExecutionStatus {
    // trait 方法签名必须与 trait 定义一致；`Self` 指代 `TxExecutionStatus`。
    fn from(value: WaitUntilArg) -> Self {
        match value {
            WaitUntilArg::None => TxExecutionStatus::None,
            WaitUntilArg::Included => TxExecutionStatus::Included,
            WaitUntilArg::ExecutedOptimistic => TxExecutionStatus::ExecutedOptimistic,
            WaitUntilArg::IncludedFinal => TxExecutionStatus::IncludedFinal,
            WaitUntilArg::Executed => TxExecutionStatus::Executed,
            WaitUntilArg::Final => TxExecutionStatus::Final,
        }
    }
}

/// 连接到指定 URL 的 JSON-RPC 客户端。
///
/// 注意：这里**只是**记录 URL，并不会立刻发起连接（HTTP 连接是惰性建立的），
/// 所以本函数不会失败、也不返回 `Result`。真正的网络错误要到第一次 `.call(..)` 时才暴露。
/// 也正因如此，适配器构造时传了一个无法访问的地址也不会报错——
/// 排查「连不上」的问题要看第一次查询的报错，而不是构造函数。
pub fn connect(rpc_url: &str) -> JsonRpcClient {
    JsonRpcClient::connect(rpc_url)
}
