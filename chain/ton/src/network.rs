//! TON 预置网络与 toncenter REST 端点。

use allchain_core::SdkError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
    Localnet,
}

impl NetworkArg {
    pub fn api_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://toncenter.com/api/v2",
            NetworkArg::Testnet => "https://testnet.toncenter.com/api/v2",
            NetworkArg::Localnet => "http://127.0.0.1:8081/api/v2",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Testnet => "testnet",
            NetworkArg::Localnet => "localnet",
        }
    }
}

/// 解析网络名，缺省主网。
pub fn parse(raw: Option<&str>) -> Result<NetworkArg, SdkError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None | Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("testnet") => Ok(NetworkArg::Testnet),
        Some("localnet") | Some("devnet") => Ok(NetworkArg::Localnet),
        Some(other) => Err(SdkError::invalid_argument(format!(
            "TON 不支持的网络: {other}（可选 mainnet / testnet / localnet）"
        ))),
    }
}
