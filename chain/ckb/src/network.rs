//! CKB 预置网络与 JSON-RPC 端点。

use allchain_core::SdkError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
    Localnet,
}

impl NetworkArg {
    pub fn rpc_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://mainnet.ckb.dev/rpc",
            NetworkArg::Testnet => "https://testnet.ckb.dev/rpc",
            NetworkArg::Localnet => "http://127.0.0.1:8114",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Testnet => "testnet",
            NetworkArg::Localnet => "localnet",
        }
    }

    /// bech32 人可读前缀：主网 `ckb`，其余网络 `ckt`。
    pub fn hrp(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "ckb",
            NetworkArg::Testnet | NetworkArg::Localnet => "ckt",
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
            "CKB 不支持的网络: {other}（可选 mainnet / testnet / localnet）"
        ))),
    }
}
