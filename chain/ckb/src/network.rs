//! CKB 预置网络与 JSON-RPC 端点。
//!
//! 领域说明：CKB 的**主网与测试网的 code_hash 是相同的**（系统锁脚本的二进制一致），
//! 区分两者靠的是地址的 bech32 hrp（人可读前缀）：主网 `ckb`、其余 `ckt`。
//! 这一点与 BTC 的地址前缀、ETH 的 chain_id 是同一类设计。

use allchain_core::SdkError;

/// 支持的网络。
///
/// 语法说明：派生了 `Copy`，因此 `net.as_str()` 之后还能再 `net.rpc_url()`——
/// 否则第二次使用会触发「use of moved value」编译错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
    /// 本地 dev 节点（默认 8114 端口）。
    Localnet,
}

impl NetworkArg {
    /// JSON-RPC 端点。
    pub fn rpc_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://mainnet.ckb.dev/rpc",
            NetworkArg::Testnet => "https://testnet.ckb.dev/rpc",
            NetworkArg::Localnet => "http://127.0.0.1:8114",
        }
    }

    /// 网络短名，与 CLI `--network` 参数取值一致。
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Testnet => "testnet",
            NetworkArg::Localnet => "localnet",
        }
    }

    /// bech32 人可读前缀：主网 `ckb`，其余网络 `ckt`。
    ///
    /// 领域说明：CKB 地址编码（见 `address.rs`）用的是 bech32，
    /// 而网络区分就体现在 hrp 上，因此派生地址时必须带上这个信息。
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
        // `None | Some("mainnet")`：或模式，把「没传」与「显式传 mainnet」合并到一支。
        None | Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("testnet") => Ok(NetworkArg::Testnet),
        // CKB 没有独立的 devnet，本地开发就是 localnet，这里做个别名兼容。
        Some("localnet") | Some("devnet") => Ok(NetworkArg::Localnet),
        Some(other) => Err(SdkError::invalid_argument(format!(
            "CKB 不支持的网络: {other}（可选 mainnet / testnet / localnet）"
        ))),
    }
}
