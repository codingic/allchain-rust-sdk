//! TON 预置网络与 toncenter REST 端点。
//!
//! toncenter 是社区运营的公共 API（非 TON 官方），其 v2 接口是目前最通用的选择。
//! 使用它的两个现实约束：
//! - **免费档限流严格**（约 1 req/s），因此 `TonClient` 内置了串行节流；
//! - 带 API key 可提额，key 通过环境变量 `TONCENTER_API_KEY` 读取（见 `adapter::new`）。

use allchain_core::SdkError;

/// 可选的 TON 网络。
///
/// 语法说明：`#[derive(..., Copy, ...)]` 中的 `Copy` 让枚举可自动按位复制，
/// 于是方法能用 `self`（按值接收）而不会转移所有权。
/// 枚举无字段、只存判别值，天然满足 `Copy` 的前提。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkArg {
    /// 主网，链上资产为真实 TON。
    Mainnet,
    /// 测试网，水龙头可领测试币。
    Testnet,
    /// 本地节点（通常是 docker 起的 `toncenter/ton` 或自建 lite-server 代理）。
    Localnet,
}

impl NetworkArg {
    /// toncenter REST v2 的**基础地址**。
    ///
    /// 返回的是 base，不含具体方法路径：适配器在它后面拼
    /// `/getMasterchainInfo`、`/getAddressBalance` 等。
    ///
    /// 语法说明：返回 `&'static str`，`'static` 生命周期表示这份字符串
    /// 在整个进程运行期都有效（这里是编译进二进制的字面量）。
    pub fn api_url(self) -> &'static str {
        // `match self` 强制穷尽所有变体：加网络忘了补分支就编译失败。
        match self {
            NetworkArg::Mainnet => "https://toncenter.com/api/v2",
            NetworkArg::Testnet => "https://testnet.toncenter.com/api/v2",
            NetworkArg::Localnet => "http://127.0.0.1:8081/api/v2",
        }
    }

    /// 网络短名，会原样出现在所有 View 的 `network` 字段里。
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Testnet => "testnet",
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
    // - `raw.map(str::trim)`         —— `str::trim` 作为函数值传入，签名正好匹配；
    // - `.filter(|s| !s.is_empty())` —— 把空串也变成 `None`。
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        // 或模式：`None`（未指定）与显式 `mainnet` 都落到主网，
        // 与 `core::ChainKind::default_network` 的「十链一律默认主网」约定一致。
        None | Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("testnet") => Ok(NetworkArg::Testnet),
        // TON 没有独立的 devnet 概念，把 `devnet` 一并映射到本地节点。
        Some("localnet") | Some("devnet") => Ok(NetworkArg::Localnet),
        // `other` 绑定剩余输入，用于报错时回显用户原值。
        Some(other) => Err(SdkError::invalid_argument(format!(
            "TON 不支持的网络: {other}（可选 mainnet / testnet / localnet）"
        ))),
    }
}
