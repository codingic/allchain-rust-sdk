//! 网络端点与 RPC Provider 构造。
//!
//! 这里刻意把「网络 → 端点」的映射集中在一处：CLI、统一门面、测试都从
//! 同一个 `NetworkArg` 取值，避免各处散落硬编码的 URL。

// `RootProvider` 是 alloy 里**最基础**的 Provider：只做 JSON-RPC 收发，
// 不含钱包、不含 gas/nonce 自动填充。查询类场景用它最合适——
// 需要签名时再由 `transactions.rs` 用 `ProviderBuilder` 叠一层钱包。
use alloy::providers::RootProvider;
// `Context` 是 anyhow 提供的扩展 trait，给错误挂上中文说明；
// `Result` 是 anyhow 的 `Result<T, anyhow::Error>` 别名，可容纳任意错误类型。
use anyhow::{Context, Result};

/// 预置网络选择。
///
/// 语法说明：这一串 derive 里只有 `clap::ValueEnum` 是新的——
/// 它让 clap 能直接把本枚举当 `--network` 的参数值解析（kebab-case 形式，
/// 即 `--network mainnet` / `sepolia` / `localnet`），省掉手工字符串解析。
/// 其余 `Debug` / `Clone` / `Copy` / `PartialEq` / `Eq` 的用途见 core 的 `chain.rs`。
///
/// 领域说明：ETH 的「网络」本质由 **chain id** 区分（主网 1、Sepolia 11155111），
/// 本地开发节点（anvil / hardhat）的 chain id 通常是 31337。这里不把 chain id
/// 写死进枚举，而是在 `status()` 里向节点实时查询——自建节点可以自定义 chain id。
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NetworkArg {
    /// 以太坊主网（chain id 1）。
    Mainnet,
    /// Sepolia 测试网（chain id 11155111），目前官方推荐的测试网。
    Sepolia,
    /// 本地开发节点（anvil / hardhat / geth --dev），默认 127.0.0.1:8545。
    Localnet,
}

impl NetworkArg {
    /// 该网络默认的 JSON-RPC 端点。
    ///
    /// 返回值 `&'static str` 是**静态生命周期**的字符串切片：这些 URL 是编译进
    /// 二进制的字面量，全程有效，所以不用分配 `String`。
    pub fn rpc_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://ethereum-rpc.publicnode.com",
            NetworkArg::Sepolia => "https://ethereum-sepolia-rpc.publicnode.com",
            NetworkArg::Localnet => "http://127.0.0.1:8545",
        }
    }

    /// 区块浏览器基址，用于拼接交易 / 地址链接。
    ///
    /// 返回 `Option<&'static str>`：本地网络没有公开浏览器，用 `None` 表达
    /// 「确实没有」而不是空字符串，调用方必须显式处理。
    pub fn explorer_base(self) -> Option<&'static str> {
        match self {
            NetworkArg::Mainnet => Some("https://etherscan.io"),
            NetworkArg::Sepolia => Some("https://sepolia.etherscan.io"),
            NetworkArg::Localnet => None,
        }
    }

    /// 网络短名，与 CLI 参数、JSON 输出中的 `network` 字段保持一致。
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Sepolia => "sepolia",
            NetworkArg::Localnet => "localnet",
        }
    }
}

/// 解析命令行/预置的端点字符串为 URL。
///
/// 用 `url::Url` 而不是裸 `String` 承接：Url 在**解析时**就校验了 scheme、
/// host 等结构，后面 alloy 拿到的必然是合法地址，不必再在每层重复校验。
///
/// 语法说明：`with_context(|| format!(..))` 与 `context("..")` 的区别在于
/// 前者传**闭包**，文案里要插值变量时才需要（惰性构造，成功路径零开销）；
/// 这里要回显用户输入的 `rpc_url`，所以用带闭包的版本。
pub fn parse_url(rpc_url: &str) -> Result<url::Url> {
    url::Url::parse(rpc_url).with_context(|| format!("非法 RPC 端点: {rpc_url}"))
}

/// 连接到指定 URL 的只读 HTTP Provider（无钱包、不填充交易字段）。
///
/// 领域说明：`RootProvider::new_http` 走的是 HTTP transport（不是 WS / IPC）。
/// 它**不订阅事件、不自动填 nonce/gas/chain id**——要那些能力得用
/// `ProviderBuilder` 叠加 filler 层，见 `transactions::wallet_provider`。
/// 查询接口全部只读，因此这里保持最小依赖。
///
/// 语法说明：`Ok(..)` 作为函数体最后一行：这里没有 `return`，因为
/// `?` 已把可能的错误提前返回，剩下的表达式直接包装成 `Ok` 即可。
pub fn connect(rpc_url: &str) -> Result<RootProvider> {
    Ok(RootProvider::new_http(parse_url(rpc_url)?))
}
