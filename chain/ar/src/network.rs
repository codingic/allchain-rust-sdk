//! Arweave 预置网络与网关端点。

use allchain_core::SdkError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkArg {
    Mainnet,
    /// arlocal 本地网（默认端口 1984）。
    Localnet,
}

impl NetworkArg {
    pub fn gateway_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://arweave.net",
            NetworkArg::Localnet => "http://127.0.0.1:1984",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Localnet => "localnet",
        }
    }
}

/// 解析网络名，缺省主网。
pub fn parse(raw: Option<&str>) -> Result<NetworkArg, SdkError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None | Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("localnet") => Ok(NetworkArg::Localnet),
        Some(other) => Err(SdkError::invalid_argument(format!(
            "AR 不支持的网络: {other}（可选 mainnet / localnet）"
        ))),
    }
}
