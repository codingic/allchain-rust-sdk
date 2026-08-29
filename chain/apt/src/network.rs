//! Aptos 预置网络与 REST 端点。

use allchain_core::SdkError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
    Devnet,
    Localnet,
}

impl NetworkArg {
    pub fn rpc_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://api.mainnet.aptoslabs.com/v1",
            NetworkArg::Testnet => "https://api.testnet.aptoslabs.com/v1",
            NetworkArg::Devnet => "https://api.devnet.aptoslabs.com/v1",
            NetworkArg::Localnet => "http://127.0.0.1:8080/v1",
        }
    }

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
pub fn parse(raw: Option<&str>) -> Result<NetworkArg, SdkError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(NetworkArg::Mainnet),
        Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("testnet") => Ok(NetworkArg::Testnet),
        Some("devnet") => Ok(NetworkArg::Devnet),
        Some("localnet") => Ok(NetworkArg::Localnet),
        Some(other) => Err(SdkError::invalid_argument(format!(
            "APT 不支持的网络: {other}（可选 mainnet / testnet / devnet / localnet）"
        ))),
    }
}
