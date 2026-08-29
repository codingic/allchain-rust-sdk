//! near 链对统一 `ChainClient` 契约的实现。

use std::str::FromStr;

use async_trait::async_trait;
use near_crypto::{ED25519PublicKey, PublicKey, Secp256K1PublicKey};
use near_jsonrpc_client::{JsonRpcClient, methods};
use near_jsonrpc_primitives::types::transactions::TransactionInfo;
use near_primitives::action::{Action, TransferAction};
use near_primitives::types::{AccountId, Balance};
use near_primitives::views::{ActionView, FinalExecutionStatus, TxExecutionStatus};
use serde_json::json;

use allchain_core::{
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, SdkError, StatusView,
    TransferRequest, TransferView, TxStatus, TxView, hexutil,
};

use crate::network::{self, NetworkArg};
use crate::queries::{fetch_account, parse_block_reference};

/// NEAR 客户端。
pub struct NearClient {
    network: String,
    rpc_url: String,
    client: JsonRpcClient,
}

impl NearClient {
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let (network_name, url) = match custom {
            Some(url) => ("custom".to_string(), url),
            None => {
                let net = parse_network(network)?;
                (net.as_str().to_string(), net.rpc_url().to_string())
            }
        };

        let client = network::connect(&url);
        Ok(Self {
            network: network_name,
            rpc_url: url,
            client,
        })
    }

    fn fail(&self, context: &str, err: impl std::fmt::Display) -> SdkError {
        allchain_core::error::classify(&format!("{context}: {err}"))
    }
}

fn parse_network(raw: Option<&str>) -> Result<NetworkArg, SdkError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(NetworkArg::Mainnet),
        Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("testnet") => Ok(NetworkArg::Testnet),
        Some("localnet") => Ok(NetworkArg::Localnet),
        Some(other) => Err(SdkError::invalid_argument(format!(
            "NEAR 不支持的网络: {other}（可选 mainnet / testnet / localnet）"
        ))),
    }
}

#[async_trait]
impl ChainClient for NearClient {
    fn kind(&self) -> ChainKind {
        ChainKind::Near
    }

    fn network(&self) -> &str {
        &self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        let status = self
            .client
            .call(methods::status::RpcStatusRequest)
            .await
            .map_err(|e| self.fail("查询节点状态失败", e))?;

        Ok(
            StatusView::new(ChainKind::Near, &self.network, &self.rpc_url)
                .with_height(status.sync_info.latest_block_height)
                .with_hash(status.sync_info.latest_block_hash.to_string())
                .with_version(status.version.version)
                .with_extra(json!({
                    "chain_id": status.chain_id,
                    "protocol_version": status.protocol_version,
                    "syncing": status.sync_info.syncing,
                    "validator_count": status.validators.len(),
                })),
        )
    }

    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        let account_id = parse_account(address)?;
        let account = fetch_account(&self.client, &account_id)
            .await
            .map_err(|e| self.fail("查询账户失败", e))?;

        Ok(BalanceView::new(
            ChainKind::Near,
            &self.network,
            address,
            account.amount.as_yoctonear(),
        )
        .with_extra(json!({
            "locked": account.locked.as_yoctonear().to_string(),
            "storage_usage": account.storage_usage,
            "code_hash": account.code_hash.to_string(),
        })))
    }

    async fn block(&self, reference: Option<&str>) -> Result<BlockView, SdkError> {
        let block_reference = parse_block_reference(reference)
            .map_err(|e| SdkError::invalid_argument(e.to_string()))?;
        let block = self
            .client
            .call(methods::block::RpcBlockRequest { block_reference })
            .await
            .map_err(|e| self.fail("查询区块失败", e))?;

        Ok(BlockView::new(
            ChainKind::Near,
            &self.network,
            block.header.hash.to_string(),
        )
        .with_height(block.header.height)
        .with_parent(block.header.prev_hash.to_string())
        .with_timestamp(block.header.timestamp as i64)
        .with_extra(json!({
            "author": block.author.to_string(),
            "chunks": block.chunks.len(),
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        // NEAR 查询交易必须同时给出发送者账户，统一接口约定用 `@` 分隔。
        let (tx_hash_str, sender_str) = hash.split_once('@').ok_or_else(|| {
            SdkError::invalid_argument(
                "NEAR 查询交易需要发送者账户，格式为 <tx_hash>@<sender.near>；\
                 历史交易请改用归档端点（如 https://archival-rpc.mainnet.near.org）",
            )
        })?;
        let tx_hash = tx_hash_str
            .trim()
            .parse()
            .map_err(|_| SdkError::invalid_argument(format!("非法交易哈希: {tx_hash_str}")))?;
        let sender = parse_account(sender_str)?;

        let response = self
            .client
            .call(methods::tx::RpcTransactionStatusRequest {
                transaction_info: TransactionInfo::TransactionId {
                    tx_hash,
                    sender_account_id: sender,
                },
                wait_until: TxExecutionStatus::Final,
            })
            .await
            .map_err(|e| self.fail("查询交易失败", e))?;

        let outcome = response
            .final_execution_outcome
            .ok_or_else(|| {
                SdkError::not_found(
                    "节点未返回执行结果（交易可能不存在或尚未入块，历史交易请使用归档端点）",
                )
            })?
            .into_outcome();

        let status = match &outcome.status {
            near_primitives::views::FinalExecutionStatus::SuccessValue(_) => TxStatus::Success,
            near_primitives::views::FinalExecutionStatus::Failure(_) => TxStatus::Failed,
            near_primitives::views::FinalExecutionStatus::NotStarted
            | near_primitives::views::FinalExecutionStatus::Started => TxStatus::Pending,
        };

        // 手续费 = 交易本身 + 所有 receipt 燃烧的 token。
        let mut fee = outcome
            .transaction_outcome
            .outcome
            .tokens_burnt
            .as_yoctonear();
        for receipt in &outcome.receipts_outcome {
            fee = fee.saturating_add(receipt.outcome.tokens_burnt.as_yoctonear());
        }

        // 转账金额从 Transfer action 累加。
        let mut amount: u128 = 0;
        let mut has_transfer = false;
        for action in &outcome.transaction.actions {
            if let ActionView::Transfer { deposit } = action {
                amount = amount.saturating_add(deposit.as_yoctonear());
                has_transfer = true;
            }
        }

        let mut view = TxView::new(ChainKind::Near, &self.network, tx_hash_str, status)
            .with_from(outcome.transaction.signer_id.to_string())
            .with_to(outcome.transaction.receiver_id.to_string())
            .with_fee(fee);
        if has_transfer {
            view = view.with_amount(amount);
        }

        Ok(view.with_extra(json!({
            "gas_burnt": outcome.transaction_outcome.outcome.gas_burnt.as_gas(),
            "receipts": outcome.receipts_outcome.len(),
            "actions": outcome.transaction.actions.len(),
        })))
    }

    async fn transfer(&self, req: TransferRequest) -> Result<TransferView, SdkError> {
        let secret_key = crate::transactions::parse_secret_key(&req.private_key)
            .map_err(|e| SdkError::invalid_argument(format!("非法私钥: {e}")))?;
        let receiver = req
            .to
            .trim()
            .parse::<AccountId>()
            .map_err(|_| SdkError::invalid_argument(format!("非法 NEAR 账户名: {}", req.to)))?;

        // 付款账户：显式指定（命名账户），或从私钥派生隐式账户。
        let from = match &req.from {
            Some(from) => parse_account(from)?,
            None => {
                let public_key = secret_key.public_key();
                hexutil::encode_hex(public_key.key_data())
                    .parse::<AccountId>()
                    .map_err(|_| SdkError::invalid_argument("无法从私钥派生隐式账户".to_string()))?
            }
        };

        let amount = crate::units::parse_near(&req.amount)
            .map_err(|e| SdkError::invalid_argument(format!("非法金额: {e}")))?;

        let built = crate::transactions::build_signed(
            &self.client,
            &from,
            &secret_key,
            &receiver,
            vec![Action::Transfer(TransferAction {
                deposit: Balance::from_yoctonear(amount),
            })],
            None,
        )
        .await
        .map_err(|e| self.fail("构造签名转账失败", e))?;

        let success = if req.dry_run {
            None
        } else {
            let outcome = self
                .client
                .call(methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
                    signed_transaction: built.signed,
                })
                .await
                .map_err(|e| self.fail("广播交易失败", e))?;
            Some(matches!(
                outcome.status,
                FinalExecutionStatus::SuccessValue(_)
            ))
        };

        Ok(TransferView::new(
            ChainKind::Near,
            &self.network,
            Some(built.signer_id.to_string()),
            req.to,
            amount,
            Some(built.tx_hash.to_string()),
            !req.dry_run,
        )
        .with_extra(json!({
            "nonce": built.nonce,
            "block_hash": built.block_hash.to_string(),
            "success": success,
        })))
    }

    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        let key = parse_public_key(pubkey)?;
        let data = key.key_data();
        // NEAR 隐式账户 = 公钥原始字节的十六进制，不做任何哈希。
        let account = hexutil::encode_hex(data);

        Ok(AddressView::new(
            ChainKind::Near,
            &self.network,
            key.to_string(),
            account.clone(),
            "implicit",
            data.len(),
        )
        .with_extra(json!({
            "account_id": account,
            "key_type": key.key_type().to_string(),
            "derivation": "hex(public_key_bytes)",
        })))
    }
}

/// 解析 NEAR 公钥。
///
/// 接受三种写法：
/// - 规范形式 `ed25519:<base58>` / `secp256k1:<base58>`；
/// - 裸 base58（按字节长度判定：32 字节为 ed25519，64 字节为 secp256k1）；
/// - 十六进制（建议带 `0x` 前缀，长度同上）。
fn parse_public_key(raw: &str) -> Result<PublicKey, SdkError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(SdkError::invalid_argument("NEAR 公钥不能为空"));
    }

    if trimmed.contains(':') {
        return trimmed.parse::<PublicKey>().map_err(|e| {
            SdkError::invalid_argument(format!(
                "非法 NEAR 公钥: {raw}（期望 ed25519:<base58> 或 secp256k1:<base58>；{e}）"
            ))
        });
    }

    let is_hex = trimmed.starts_with("0x")
        || trimmed.starts_with("0X")
        || ((trimmed.len() == 64 || trimmed.len() == 128)
            && trimmed.chars().all(|c| c.is_ascii_hexdigit()));

    let bytes: Vec<u8> = if is_hex {
        hexutil::decode_hex(trimmed)?
    } else {
        bs58::decode(trimmed)
            .into_vec()
            .map_err(|e| SdkError::invalid_argument(format!("非法 base58 公钥: {e}")))?
    };

    from_bytes(&bytes)
}

fn from_bytes(bytes: &[u8]) -> Result<PublicKey, SdkError> {
    match bytes.len() {
        32 => Ok(PublicKey::ED25519(ED25519PublicKey(
            bytes
                .try_into()
                .map_err(|_| SdkError::invalid_argument("ed25519 公钥长度异常"))?,
        ))),
        64 => Secp256K1PublicKey::try_from(bytes)
            .map(PublicKey::SECP256K1)
            .map_err(|e| SdkError::invalid_argument(format!("构造 secp256k1 公钥失败: {e}"))),
        other => Err(SdkError::invalid_argument(format!(
            "NEAR 公钥需为 32 字节（ed25519）或 64 字节（secp256k1），实际 {other} 字节"
        ))),
    }
}

fn parse_account(raw: &str) -> Result<AccountId, SdkError> {
    AccountId::from_str(raw.trim())
        .map_err(|_| SdkError::invalid_argument(format!("非法 NEAR 账户名: {raw}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // sha256("allchain-near-test-vector") 的 32 字节，base58 编码后作为 ed25519 公钥。
    const ED25519_B58: &str = "Ea7rnrasYTNEJ74iGP3AGwvRLMiw1MpBBqLVRnyQDkih";
    const ED25519_HEX: &str = "c9a3da0428ef24d1dbc5f7fcc83d2c9de0edf20666b880cae7b96c4d5c1eef0e";
    const SECP_B58: &str =
        "6qGGJ2rJRXhivSFLNT5FUwPvjZaEBkkqbmuj8TMizuAenNf4n163CxG8y1Nkdt5wX1beMJys6jMVfzVAnDnBQpr";

    #[test]
    fn parses_canonical_form() {
        let key = parse_public_key(&format!("ed25519:{ED25519_B58}")).unwrap();
        assert_eq!(key.key_type().to_string(), "ed25519");
        assert_eq!(key.key_data().len(), 32);
        assert_eq!(key.to_string(), format!("ed25519:{ED25519_B58}"));
    }

    #[test]
    fn bare_base58_and_hex_agree() {
        let key = parse_public_key(ED25519_B58).unwrap();
        assert_eq!(hexutil::encode_hex(key.key_data()), ED25519_HEX);
        let from_hex = parse_public_key(ED25519_HEX).unwrap();
        let from_prefixed = parse_public_key(&format!("0x{ED25519_HEX}")).unwrap();
        assert_eq!(from_hex, key);
        assert_eq!(from_prefixed, key);
    }

    #[test]
    fn secp256k1_key_is_64_bytes() {
        let key = parse_public_key(SECP_B58).unwrap();
        assert_eq!(key.key_type().to_string(), "secp256k1");
        assert_eq!(key.key_data().len(), 64);
        assert_eq!(hexutil::encode_hex(key.key_data()).len(), 128);
    }

    #[test]
    fn implicit_account_is_hex_of_key_bytes() {
        let key = parse_public_key(ED25519_B58).unwrap();
        assert_eq!(hexutil::encode_hex(key.key_data()).len(), 64);
    }

    #[test]
    fn rejects_unknown_type_and_bad_length() {
        assert!(parse_public_key("ecdsa:abc").is_err());
        assert!(parse_public_key("").is_err());
        assert!(parse_public_key(&"ab".repeat(16)).is_err());
    }
}
