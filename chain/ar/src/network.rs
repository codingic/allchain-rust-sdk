//! Arweave 预置网络与网关端点。
//!
//! 与其余链不同，Arweave 官方**没有**「测试网网关」这一说：
//! 主网网关 `arweave.net` 由社区运营，本地开发则靠 `arlocal` 起一个模拟节点。
//! 所以本模块只有两个变体。

use allchain_core::SdkError;

/// 支持的网络。
///
/// 语法说明：`#[derive(..., Copy, ...)]` 让枚举按值传递而不转移所有权，
/// 于是 `net.as_str()` 之后再 `net.gateway_url()` 依然合法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkArg {
    Mainnet,
    /// arlocal 本地网（默认端口 1984）。
    Localnet,
}

impl NetworkArg {
    /// 网关 base URL。
    ///
    /// 领域说明：这里叫 `gateway_url` 而不是 `rpc_url`——Arweave 网关是
    /// 一层 REST 代理，语义上更接近「HTTP 网关」而非「JSON-RPC 节点」。
    pub fn gateway_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://arweave.net",
            NetworkArg::Localnet => "http://127.0.0.1:1984",
        }
    }

    /// 网络短名，与 CLI `--network` 参数取值一致。
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Localnet => "localnet",
        }
    }
}

/// 解析网络名，缺省主网。
pub fn parse(raw: Option<&str>) -> Result<NetworkArg, SdkError> {
    // `None | Some("mainnet")` 是**或模式**：一个分支匹配两种情形，
    // 于是「没传」与「显式传 mainnet」走同一条路。
    // 竖线 `|` 在 `match` 里是或模式，与闭包参数列表的 `|x|` 语义完全不同。
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None | Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("localnet") => Ok(NetworkArg::Localnet),
        Some(other) => Err(SdkError::invalid_argument(format!(
            "AR 不支持的网络: {other}（可选 mainnet / localnet）"
        ))),
    }
}
