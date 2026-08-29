//! Sui 预置网络与 GraphQL 端点。
//!
//! 注意：Sui 公共 fullnode 的 JSON-RPC 已下线，统一走 GraphQL。

use allchain_core::SdkError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
    Devnet,
    Localnet,
}

impl NetworkArg {
    pub fn graphql_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://graphql.mainnet.sui.io/graphql",
            NetworkArg::Testnet => "https://graphql.testnet.sui.io/graphql",
            NetworkArg::Devnet => "https://graphql.devnet.sui.io/graphql",
            NetworkArg::Localnet => "http://127.0.0.1:9000/graphql",
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
        None | Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("testnet") => Ok(NetworkArg::Testnet),
        Some("devnet") => Ok(NetworkArg::Devnet),
        Some("localnet") => Ok(NetworkArg::Localnet),
        Some(other) => Err(SdkError::invalid_argument(format!(
            "SUI 不支持的网络: {other}（可选 mainnet / testnet / devnet / localnet）"
        ))),
    }
}
