//! Filecoin 预置网络与 JSON-RPC 端点。

use allchain_core::SdkError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkArg {
    Mainnet,
    /// Calibration 校准测试网。
    Calibration,
    Localnet,
}

impl NetworkArg {
    pub fn rpc_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://api.node.glif.io/rpc/v1",
            NetworkArg::Calibration => "https://api.calibration.node.glif.io/rpc/v1",
            NetworkArg::Localnet => "http://127.0.0.1:1234/rpc/v1",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Calibration => "calibration",
            NetworkArg::Localnet => "localnet",
        }
    }

    /// 地址网络前缀：主网 `f`，其余 `t`。
    pub fn address_prefix(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "f",
            NetworkArg::Calibration | NetworkArg::Localnet => "t",
        }
    }
}

/// 解析网络名，缺省主网。
pub fn parse(raw: Option<&str>) -> Result<NetworkArg, SdkError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None | Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("testnet") | Some("calibration") => Ok(NetworkArg::Calibration),
        Some("localnet") | Some("devnet") => Ok(NetworkArg::Localnet),
        Some(other) => Err(SdkError::invalid_argument(format!(
            "FIL 不支持的网络: {other}（可选 mainnet / calibration / localnet）"
        ))),
    }
}
