//! sol 链对统一 `ChainClient` 契约的实现。
//!
//! Solana 的 RPC 客户端是**同步阻塞** API，这里统一包在 `spawn_blocking` 中，
//! 避免阻塞 async 运行时。

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use solana_commitment_config::CommitmentConfig;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_types::config::{RpcBlockConfig, RpcTransactionConfig};
use solana_signer::Signer;
use solana_transaction_status_client_types::{
    EncodedTransaction, UiMessage, UiTransactionEncoding, option_serializer::OptionSerializer,
};

use allchain_core::{
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, ErrorCode, SdkError, StatusView,
    TransferRequest, TransferView, TxStatus, TxView, hexutil,
};

use crate::cluster::{self, ClusterArg};

/// Solana 客户端。
pub struct SolClient {
    network: String,
    rpc_url: String,
    client: Arc<RpcClient>,
}

impl SolClient {
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let (network_name, url) = match custom {
            Some(url) => ("custom".to_string(), url),
            None => {
                let c = parse_network(network)?;
                (c.as_str().to_string(), c.rpc_url().to_string())
            }
        };

        let client = Arc::new(cluster::connect(&url, CommitmentConfig::confirmed()));
        Ok(Self {
            network: network_name,
            rpc_url: url,
            client,
        })
    }

    /// 把同步 RPC 调用搬到阻塞线程池，并把错误统一归类。
    async fn blocking<F, T>(&self, what: &'static str, f: F) -> Result<T, SdkError>
    where
        F: FnOnce(Arc<RpcClient>) -> Result<T, anyhow::Error> + Send + 'static,
        T: Send + 'static,
    {
        let client = Arc::clone(&self.client);
        tokio::task::spawn_blocking(move || f(client))
            .await
            .map_err(|e| SdkError::new(ErrorCode::Internal, format!("{what}任务异常: {e}")))?
            .map_err(|e| allchain_core::error::classify(&format!("{what}: {e:?}")))
    }
}

fn parse_network(raw: Option<&str>) -> Result<ClusterArg, SdkError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(ClusterArg::Mainnet),
        Some("mainnet") => Ok(ClusterArg::Mainnet),
        Some("devnet") => Ok(ClusterArg::Devnet),
        Some("testnet") => Ok(ClusterArg::Testnet),
        Some("localnet") => Ok(ClusterArg::Localnet),
        Some(other) => Err(SdkError::invalid_argument(format!(
            "SOL 不支持的网络: {other}（可选 mainnet / devnet / testnet / localnet）"
        ))),
    }
}

#[async_trait]
impl ChainClient for SolClient {
    fn kind(&self) -> ChainKind {
        ChainKind::Sol
    }

    fn network(&self) -> &str {
        &self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        let (version, slot, blockhash) = self
            .blocking("查询节点状态", |client| {
                let version = client.get_version()?;
                let slot = client.get_slot()?;
                let blockhash = client.get_latest_blockhash()?;
                Ok((version.solana_core, slot, blockhash.to_string()))
            })
            .await?;

        Ok(
            StatusView::new(ChainKind::Sol, &self.network, &self.rpc_url)
                .with_height(slot)
                .with_hash(blockhash)
                .with_version(version),
        )
    }

    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        let pubkey = address
            .trim()
            .parse::<Pubkey>()
            .map_err(|_| SdkError::invalid_argument(format!("非法 SOL 地址: {address}")))?;

        let lamports = self
            .blocking("查询余额", move |client| {
                Ok(client.get_balance(&pubkey)?)
            })
            .await?;

        Ok(BalanceView::new(
            ChainKind::Sol,
            &self.network,
            address,
            lamports as u128,
        ))
    }

    async fn block(&self, reference: Option<&str>) -> Result<BlockView, SdkError> {
        let slot = parse_slot(reference)?;
        // 必须显式声明 maxSupportedTransactionVersion，否则含 v0 交易的区块会被节点
        // 以 -32015 拒绝。
        let block = self
            .blocking("查询区块", move |client| {
                let config = RpcBlockConfig {
                    encoding: Some(UiTransactionEncoding::Json),
                    transaction_details: None,
                    rewards: Some(false),
                    commitment: None,
                    max_supported_transaction_version: Some(0),
                };
                Ok(client.get_block_with_config(slot, config)?)
            })
            .await?;

        let mut view = BlockView::new(ChainKind::Sol, &self.network, block.blockhash)
            .with_parent(block.previous_blockhash)
            .with_tx_count(block.transactions.as_deref().unwrap_or_default().len() as u64);
        if let Some(height) = block.block_height {
            view = view.with_height(height);
        }
        if let Some(time) = block.block_time {
            view = view.with_timestamp(time);
        }
        Ok(view.with_extra(json!({
            "slot": slot,
            "parent_slot": block.parent_slot,
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        let signature = hash
            .trim()
            .parse()
            .map_err(|_| SdkError::invalid_argument(format!("非法交易签名: {hash}")))?;

        let tx = self
            .blocking("查询交易", move |client| {
                let config = RpcTransactionConfig {
                    encoding: Some(UiTransactionEncoding::Json),
                    commitment: None,
                    max_supported_transaction_version: Some(0),
                };
                Ok(client.get_transaction_with_config(&signature, config)?)
            })
            .await?;

        let meta = tx.transaction.meta.as_ref();
        let status = match meta {
            None => TxStatus::Unknown,
            Some(m) if m.err.is_none() => TxStatus::Success,
            Some(_) => TxStatus::Failed,
        };

        let mut view =
            TxView::new(ChainKind::Sol, &self.network, hash, status).with_height(tx.slot);
        if let Some(time) = tx.block_time {
            view = view.with_timestamp(time);
        }
        if let Some(fee) = meta.map(|m| m.fee) {
            view = view.with_fee(fee as u128);
        }

        let mut extra = json!({ "slot": tx.slot });

        // 账户列表：首账户通常即 fee payer，可视作付款方。
        if let EncodedTransaction::Json(ui) = &tx.transaction.transaction {
            let keys: Vec<String> = match &ui.message {
                UiMessage::Parsed(m) => m
                    .account_keys
                    .iter()
                    .map(|a| a.pubkey.to_string())
                    .collect(),
                UiMessage::Raw(m) => m.account_keys.clone(),
            };
            if let Some(first) = keys.first() {
                view = view.with_from(first.clone());
            }
            extra["account_keys"] = json!(keys);
        }

        if let Some(m) = meta {
            extra["pre_balances"] = json!(m.pre_balances);
            extra["post_balances"] = json!(m.post_balances);
            if let OptionSerializer::Some(units) = m.compute_units_consumed {
                extra["compute_units"] = json!(units);
            }
            if let OptionSerializer::Some(logs) = &m.log_messages {
                extra["log_messages"] = json!(logs);
            }
        }

        Ok(view.with_extra(extra))
    }

    async fn transfer(&self, req: TransferRequest) -> Result<TransferView, SdkError> {
        let to: Pubkey = req
            .to
            .trim()
            .parse()
            .map_err(|_| SdkError::invalid_argument(format!("非法 SOL 地址: {}", req.to)))?;
        let lamports = crate::units::parse_sol(&req.amount)
            .map_err(|e| SdkError::invalid_argument(format!("非法金额: {e}")))?;
        let keypair = crate::tx::parse_keypair(&req.private_key)
            .map_err(|e| SdkError::invalid_argument(format!("非法私钥: {e}")))?;
        let from = keypair.pubkey().to_string();
        let dry_run = req.dry_run;

        let (signature, blockhash) = self
            .blocking("转账", move |client| {
                let built = crate::tx::build_signed_transfer(&client, &keypair, &to, lamports)?;
                if dry_run {
                    return Ok((built.signature, built.recent_blockhash));
                }
                let confirmed = client
                    .send_and_confirm_transaction(&built.tx)
                    .map_err(|e| {
                        anyhow::anyhow!("广播交易失败（账户可能不存在或余额不足）: {e}")
                    })?;
                Ok((confirmed, built.recent_blockhash))
            })
            .await?;

        Ok(TransferView::new(
            ChainKind::Sol,
            &self.network,
            Some(from),
            req.to,
            lamports as u128,
            Some(signature.to_string()),
            !req.dry_run,
        )
        .with_extra(json!({ "recent_blockhash": blockhash })))
    }

    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        let bytes = parse_pubkey_bytes(pubkey)?;
        let address = Pubkey::new_from_array(bytes);

        // Solana 的地址就是 ed25519 公钥的 base58 编码，二者是同一个字符串。
        Ok(AddressView::new(
            ChainKind::Sol,
            &self.network,
            address.to_string(),
            address.to_string(),
            "ed25519",
            bytes.len(),
        )
        .with_extra(json!({
            "pubkey_hex": hexutil::encode_hex_prefixed(&bytes),
            "derivation": "base58(ed25519_pubkey)",
        })))
    }
}

/// 解析 32 字节 ed25519 公钥。
///
/// 接受两种写法：base58（即 Solana 地址本身，最常用）或十六进制（需为
/// 64 个十六进制字符；建议显式加 `0x` 前缀以消除歧义）。
fn parse_pubkey_bytes(raw: &str) -> Result<[u8; 32], SdkError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(SdkError::invalid_argument("SOL 公钥不能为空"));
    }

    let looks_hex = trimmed.starts_with("0x")
        || trimmed.starts_with("0X")
        || (trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()));

    let bytes: Vec<u8> = if looks_hex {
        hexutil::decode_hex(trimmed)?
    } else {
        // base58：先校验字符集，长度不对时给出明确提示。
        bs58_decode(trimmed).map_err(|e| SdkError::invalid_argument(format!("{e}")))?
    };

    bytes.try_into().map_err(|got: Vec<u8>| {
        SdkError::invalid_argument(format!(
            "SOL 公钥需为 32 字节（base58 或 64 位十六进制），实际 {} 字节",
            got.len()
        ))
    })
}

/// 复用 `tx.rs` 中已有的最小 base58 解码实现，避免为此新增依赖。
fn bs58_decode(input: &str) -> Result<Vec<u8>, SdkError> {
    crate::tx::bs58_decode(input)
        .map_err(|e| SdkError::invalid_argument(format!("非法 base58 公钥: {e}")))
}

/// 解析区块引用：空 -> 当前 slot；否则必须是 slot 数字。
///
/// 注意 Solana 的区块按 **slot** 索引而非区块高度，两者在无跳块时才相等。
fn parse_slot(reference: Option<&str>) -> Result<u64, SdkError> {
    match reference.map(str::trim).filter(|s| !s.is_empty()) {
        None => Err(SdkError::invalid_argument(
            "SOL 查询区块必须显式指定 slot（公共节点通常只保留最近 1-2 天的区块）",
        )),
        Some(s) => s.parse().map_err(|_| {
            SdkError::invalid_argument(format!("非法 slot: {s}（Solana 按 slot 查询，需为整数）"))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 系统程序：32 字节全零，base58 表示为 32 个 1。
    const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

    #[test]
    fn base58_and_hex_produce_same_address() {
        let from_b58 = parse_pubkey_bytes(SYSTEM_PROGRAM).unwrap();
        let from_hex =
            parse_pubkey_bytes(&format!("0x{}", hexutil::encode_hex(&from_b58))).unwrap();
        assert_eq!(from_b58, from_hex);
        assert_eq!(Pubkey::new_from_array(from_b58).to_string(), SYSTEM_PROGRAM);
    }

    #[test]
    fn accepts_bare_64_char_hex() {
        let hex_key = hexutil::encode_hex(&[7u8; 32]);
        let parsed = parse_pubkey_bytes(&hex_key).unwrap();
        assert_eq!(parsed, [7u8; 32]);
    }

    #[test]
    fn rejects_wrong_length_and_bad_chars() {
        assert!(parse_pubkey_bytes("").is_err());
        // base58 中不含 0 / O / I / l
        assert!(parse_pubkey_bytes("0OIl").is_err());
        // 31 字节的 base58
        assert!(parse_pubkey_bytes(&"1".repeat(31)).is_err());
        assert!(parse_pubkey_bytes(&"ab".repeat(31)).is_err());
    }
}
