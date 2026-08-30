//! Sui 预置网络与 GraphQL 端点。
//!
//! 注意：Sui 公共 fullnode 的 JSON-RPC 已下线，统一走 GraphQL。
//!
//! 这条限制的实际影响不止「换个 URL」这么简单，它改变了取数的方式：
//! - JSON-RPC 时代有 `sui_getBalance` / `sui_getTransactionBlock` 等**扁平**方法；
//! - GraphQL 只有一个入口，所有条件都得拼进查询文本（query string）里，
//!   于是「参数校验」的责任落到了 SDK 自己身上——插值内容必须是安全的，
//!   否则可能构造出非预期的查询（见 `adapter::validate_address`）。

use allchain_core::SdkError;

/// 可选的 Sui 网络。
///
/// 语法说明：`#[derive(Debug, Clone, Copy, PartialEq, Eq)]` 中
/// `Copy` 让枚举可按位复制，于是方法能用 `self`（按值接收）而不会转移所有权。
/// 枚举无字段、只存判别值，天然满足 `Copy` 的前提。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkArg {
    /// 主网，链上资产为真实 SUI。
    Mainnet,
    /// 官方长期测试网，水龙头可领币。
    Testnet,
    /// 开发网，会不定期重置，适合 CI 与压力测试。
    Devnet,
    /// 本地 `sui start` 起的节点。
    Localnet,
}

impl NetworkArg {
    /// Sui 官方 GraphQL 端点。
    ///
    /// 注意四个端点的路径**都是** `/graphql`——Sui 把 GraphQL 与（已下线的）
    /// JSON-RPC 做过路径区分，现在只剩这一个。
    ///
    /// 语法说明：返回 `&'static str`，`'static` 生命周期表示这份字符串
    /// 在整个进程运行期都有效（这里是编译进二进制的字面量）。
    pub fn graphql_url(self) -> &'static str {
        // `match self` 强制穷尽所有变体：加网络忘了补分支就编译失败。
        match self {
            NetworkArg::Mainnet => "https://graphql.mainnet.sui.io/graphql",
            NetworkArg::Testnet => "https://graphql.testnet.sui.io/graphql",
            NetworkArg::Devnet => "https://graphql.devnet.sui.io/graphql",
            // GraphQL 默认端口 9000（与旧 JSON-RPC 的 9000 一致，但协议不同）。
            NetworkArg::Localnet => "http://127.0.0.1:9000/graphql",
        }
    }

    /// 网络短名，会原样出现在所有 View 的 `network` 字段里。
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Testnet => "testnet",
            NetworkArg::Devnet => "devnet",
            NetworkArg::Localnet => "localnet",
        }
    }
}

/// 解析网络名，缺省主网。
///
/// 语法说明：参数 `Option<&str>` 用「有没有值」表达「有没有指定」，
/// 比用空字符串 `""` 更明确，也杜绝了「传了空白当合法值」的歧义。
pub fn parse(raw: Option<&str>) -> Result<NetworkArg, SdkError> {
    // 三步链式处理把「没传 / 传空串」统一折叠成 `None`：
    // - `raw.map(str::trim)`    —— `str::trim` 作为函数值传入，签名 `fn(&str) -> &str` 正好匹配；
    // - `.filter(|s| !s.is_empty())` —— 把空串也变成 `None`。
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        // 或模式：`None`（未指定）与显式 `mainnet` 都落到主网，
        // 与 `core::ChainKind::default_network` 的「十链一律默认主网」约定一致。
        None | Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("testnet") => Ok(NetworkArg::Testnet),
        Some("devnet") => Ok(NetworkArg::Devnet),
        Some("localnet") => Ok(NetworkArg::Localnet),
        // `other` 绑定剩余输入，用于报错时回显用户原值。
        Some(other) => Err(SdkError::invalid_argument(format!(
            "SUI 不支持的网络: {other}（可选 mainnet / testnet / devnet / localnet）"
        ))),
    }
}
