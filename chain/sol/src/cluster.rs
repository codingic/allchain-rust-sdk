//! 集群端点、commitment 与 RPC 客户端构造。
//!
//! Solana 的「集群」（cluster）概念大致对应其它链的「网络」，但官方把它分成
//! mainnet-beta / devnet / testnet / localnet 四类，其中：
//! - devnet 与 testnet 都是测试网，但**用途不同**：testnet 主要供验证者做压力与升级演练，
//!   水龙头额度与数据保留策略都和 devnet 不一样，日常联调推荐 devnet；
//! - localnet 指本机 `solana-test-validator`，默认监听 127.0.0.1:8899。
//!
//! 另外一个与「集群」正交、但同等重要的概念是 **commitment**（确认级别），
//! 见本文件下方的 [`CommitmentArg`]：它决定「读到的数据有多新 / 多可信」。

// `clap` 是 Rust 生态最常用的命令行参数解析库。`ValueEnum` 是它的**派生宏**：
// 给枚举自动生成「字符串 <-> 变体」的双向映射，于是 CLI 里可以直接写
// `--cluster devnet`，clap 负责把它解析成 `ClusterArg::Devnet`，
// 并自动产出 `--help` 里可选的取值列表与 shell 补全。
use clap::ValueEnum;
// `CommitmentConfig` 描述 RPC 请求的确认级别（processed / confirmed / finalized）。
use solana_commitment_config::CommitmentConfig;
// `RpcClient` 是官方的 **同步阻塞** JSON-RPC 客户端：每个方法调用都会阻塞当前线程
// 直到拿到响应（内部用的是阻塞式 reqwest）。这一点决定了 adapter 里必须
// 用 `spawn_blocking` 把它搬到专用线程池，详见 `adapter::SolClient::blocking`。
use solana_rpc_client::rpc_client::RpcClient;

/// 预置集群选择。
///
/// 语法说明：`#[derive(...)]` 逐个来看：
/// - `Debug`       → 支持 `{:?}` 打印，clap 报错时需要打印解析到的值；
/// - `Clone`/`Copy` → 允许 `.clone()` / 赋值时自动按位复制。能 `Copy` 的前提是
///   所有字段都 `Copy`，而**无字段的枚举（C-like enum）天然满足**；
/// - `PartialEq`/`Eq` → 支持 `==` 比较，测试与分支判断都要用；
/// - `ValueEnum`   → clap 派生宏，作用见上面的 `use clap::ValueEnum` 说明。
///   它要求枚举是**无字段**的（unit variants），否则无法从字符串还原。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ClusterArg {
    /// 主网 beta（`api.mainnet-beta.solana.com`）。官方一直保留 beta 后缀，
    /// 但这就是真正的主网，真金白银都在这条链上。
    Mainnet,
    /// 开发测试网，水龙头可领空投，**日常联调默认用它**。
    Devnet,
    /// 验证者测试网，用于压测与协议升级演练，数据会周期性重置。
    Testnet,
    /// 本机 `solana-test-validator`（`http://127.0.0.1:8899`）。
    Localnet,
}

// 固有实现块：给 `ClusterArg` 挂方法。
impl ClusterArg {
    /// 该集群的默认公共 RPC 端点。
    ///
    /// 语法说明：`self`（不带 `&`）是**按值接收**；因为本枚举 `Copy`，
    /// 调用后原值依然可用，不存在所有权转移。`-> &'static str` 中的 `'static`
    /// 意思是「这段字符串活到程序结束」——这里是编译进二进制的字面量，自然满足。
    pub fn rpc_url(self) -> &'static str {
        match self {
            ClusterArg::Mainnet => "https://api.mainnet-beta.solana.com",
            ClusterArg::Devnet => "https://api.devnet.solana.com",
            ClusterArg::Testnet => "https://api.testnet.solana.com",
            ClusterArg::Localnet => "http://127.0.0.1:8899",
        }
    }

    /// 区块浏览器基础地址；localnet 没有公共浏览器，故为 `None`。
    ///
    /// 语法说明：`Option<&'static str>` 用来表达「可能没有」：
    /// Rust 没有 `null`，调用方必须显式处理 `None` 分支（比如 `if let Some(base) = ..`），
    /// 于是「忘记处理无浏览器的情况」在编译期就会被拦住。
    pub fn explorer_base(self) -> Option<&'static str> {
        match self {
            // devnet / testnet 与 mainnet 共用同一个 explorer 域名，
            // 靠 [`ClusterArg::explorer_cluster`] 返回的查询参数来区分集群。
            ClusterArg::Mainnet => Some("https://explorer.solana.com"),
            ClusterArg::Devnet => Some("https://explorer.solana.com"),
            ClusterArg::Testnet => Some("https://explorer.solana.com"),
            // 本机链没有公共浏览器。
            ClusterArg::Localnet => None,
        }
    }

    /// Explorer 的集群后缀参数（mainnet 无后缀）。
    pub fn explorer_cluster(self) -> &'static str {
        match self {
            // explorer 默认就是主网，无需额外参数。
            ClusterArg::Mainnet => "",
            ClusterArg::Devnet => "?cluster=devnet",
            ClusterArg::Testnet => "?cluster=testnet",
            // localnet 走 `custom` 模式，并把本机地址做 URL 编码后拼进 `customUrl`：
            // `%3A` = `:`，`%2F` = `/`。必须编码，否则 `:` 与 `/` 会被当作 URL 结构字符。
            ClusterArg::Localnet => "?cluster=custom&customUrl=http%3A%2F%2F127.0.0.1%3A8899",
        }
    }

    /// 集群短名，与 CLI 参数取值一致。
    pub fn as_str(self) -> &'static str {
        match self {
            ClusterArg::Mainnet => "mainnet",
            ClusterArg::Devnet => "devnet",
            ClusterArg::Testnet => "testnet",
            ClusterArg::Localnet => "localnet",
        }
    }
}

/// CLI 侧的 commitment 选择。
///
/// **commitment（确认级别）是 Solana 最容易踩坑的概念之一**，它决定节点以什么状态回答查询：
/// - `Processed`：只要被某个节点处理过就返回。**最快，但可能来自一条最终被丢弃的分叉**，
///   余额/交易结果都可能「回滚」，不适合任何涉及资金的判断；
/// - `Confirmed`：已被集群 **2/3 以上质押权重**投票确认（约 `optimistic confirmation` 级别）。
///   日常查询的默认档，速度与可靠性平衡最好，本 SDK 的适配器即固定用它；
/// - `Finalized`：已在其后追加了 31 个以上已确认区块，实际上不可能回滚。
///   最慢（主网上通常比 confirmed 晚十几秒），用于最终对账、入账确认。
///
/// 同样的查询在不同 commitment 下会得到**不同的余额**，这不是 bug。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CommitmentArg {
    /// 已被节点处理，可能回滚。
    Processed,
    /// 已被集群 2/3 质押权重确认（推荐默认）。
    Confirmed,
    /// 已最终确认，不可回滚。
    Finalized,
}

/// 把 CLI 侧的枚举转换成官方 SDK 的 `CommitmentConfig`。
///
/// 语法说明：`impl From<A> for B` 是**标准库 trait 实现块**（注意不是固有实现块
/// `impl B { .. }`）。实现 `From` 之后会自动获得 `Into`：`let c: CommitmentConfig = arg.into();`
/// 之所以实现 `From` 而不是 `Into`，是因为**孤儿规则**要求 trait 与类型至少有一个在本地，
/// 而 `CommitmentConfig` 是外部类型——实现 `From<本地类型> for 外部类型` 是允许的
/// （`From` 的本地性看的是**源类型**参数），反过来写 `impl Into<CommitmentConfig> for CommitmentArg`
/// 虽然也合法，但标准库的 blanket impl 会直接帮你把 `From` 转成 `Into`，所以约定俗成都写 `From`。
impl From<CommitmentArg> for CommitmentConfig {
    // trait 方法签名必须与 trait 定义一致：`fn from(value: 源类型) -> Self`。
    // 这里的 `Self` 指代被实现的类型，即 `CommitmentConfig`。
    fn from(value: CommitmentArg) -> Self {
        match value {
            // 右侧三个都是 `CommitmentConfig` 的关联函数（构造器），返回对应级别的实例。
            CommitmentArg::Processed => CommitmentConfig::processed(),
            CommitmentArg::Confirmed => CommitmentConfig::confirmed(),
            CommitmentArg::Finalized => CommitmentConfig::finalized(),
        }
    }
}

/// 构造 RPC 客户端（带超时提示：公共节点对 getBlock 等重接口有限流）。
///
/// `commitment` 会成为该客户端上**所有请求的默认确认级别**（单次请求仍可用
/// `RpcBlockConfig` 之类的 config 覆盖）。
///
/// 注意两点：
/// 1. 返回的 `RpcClient` 是**同步阻塞**客户端，不要直接在 async 上下文里调用；
/// 2. 公共端点（如 `api.mainnet-beta.solana.com`）对 `getBlock` / `getProgramAccounts`
///    这类重接口有严格限流，高频调用建议换用自建或第三方付费节点。
pub fn connect(rpc_url: &str, commitment: CommitmentConfig) -> RpcClient {
    // `rpc_url.to_string()`：`&str` → `String` 的显式转换。
    // 必须转成 `String` 是因为 `new_with_commitment` **按值接收** URL
    // （`RpcClient` 要把它存进自己的字段里长期持有，借用活不了那么久）。
    RpcClient::new_with_commitment(rpc_url.to_string(), commitment)
}
