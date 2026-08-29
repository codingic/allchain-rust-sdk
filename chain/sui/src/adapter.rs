//! Sui 链对统一 `ChainClient` 契约的实现（官方 GraphQL）。

use async_trait::async_trait;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use serde_json::{Value, json};

use allchain_core::{
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, ErrorCode, SdkError, StatusView,
    TxStatus, TxView, hexutil,
};
use chain_rpcutil::{Http, loose_u64, loose_u128, rfc3339_to_unix};

use crate::network;

/// SUI 的 coin type 标识。
const SUI_COIN_TYPE: &str = "0x2::sui::SUI";

const CHECKPOINT_FIELDS: &str =
    "sequenceNumber digest previousCheckpointDigest timestamp networkTotalTransactions";

pub struct SuiClient {
    network: String,
    rpc_url: String,
    http: Http,
}

impl SuiClient {
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let (network_name, url) = match custom {
            Some(url) => ("custom".to_string(), url),
            None => {
                let net = network::parse(network)?;
                (net.as_str().to_string(), net.graphql_url().to_string())
            }
        };
        let http = Http::new(&url)?;
        Ok(Self {
            network: network_name,
            rpc_url: url,
            http,
        })
    }

    /// 查询指定序号 checkpoint；`None` 表示最新。
    async fn checkpoint(&self, seq: Option<u64>) -> Result<Value, SdkError> {
        let selector = match seq {
            Some(n) => format!("checkpoint(sequenceNumber: {n})"),
            None => "checkpoint".to_string(),
        };
        let query = format!("{{ {selector} {{ {CHECKPOINT_FIELDS} epoch {{ epochId }} }} }}");
        let data = self.http.graphql(&query).await?;
        data.get("checkpoint")
            .filter(|v| !v.is_null())
            .cloned()
            .ok_or_else(|| SdkError::not_found("checkpoint 不存在"))
    }
}

#[async_trait]
impl ChainClient for SuiClient {
    fn kind(&self) -> ChainKind {
        ChainKind::Sui
    }

    fn network(&self) -> &str {
        &self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        let query = format!(
            "{{ chainIdentifier epoch {{ epochId }} checkpoint {{ {CHECKPOINT_FIELDS} }} }}"
        );
        let data = self.http.graphql(&query).await?;
        let cp = data
            .get("checkpoint")
            .ok_or_else(|| SdkError::new(ErrorCode::RpcError, "缺少最新 checkpoint"))?;
        let mut view = StatusView::new(ChainKind::Sui, &self.network, &self.rpc_url);
        if let Some(seq) = cp.get("sequenceNumber").and_then(Value::as_u64) {
            view = view.with_height(seq);
        }
        if let Some(digest) = cp.get("digest").and_then(Value::as_str) {
            view = view.with_hash(digest);
        }
        if let Some(chain) = data.get("chainIdentifier").and_then(Value::as_str) {
            view = view.with_version(chain);
        }
        Ok(view.with_extra(json!({
            "epoch": data.pointer("/epoch/epochId").cloned().unwrap_or(Value::Null),
            "network_total_transactions": cp.get("networkTotalTransactions").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        validate_address(address)?;
        let query = format!(
            "{{ address(address: \"{}\") {{ balance(coinType: \"{SUI_COIN_TYPE}\") {{ totalBalance }} }} }}",
            address.trim()
        );
        let data = self.http.graphql(&query).await?;
        let raw = data
            .pointer("/address/balance/totalBalance")
            .and_then(|v| loose_u128(v).ok())
            .unwrap_or(0);
        Ok(
            BalanceView::new(ChainKind::Sui, &self.network, address, raw).with_extra(json!({
                "coin_type": SUI_COIN_TYPE,
            })),
        )
    }

    async fn block(&self, reference: Option<&str>) -> Result<BlockView, SdkError> {
        let cp = match reference.map(str::trim).filter(|s| !s.is_empty()) {
            None => self.checkpoint(None).await?,
            Some(r) => {
                let seq: u64 = r.parse().map_err(|_| {
                    SdkError::invalid_argument(format!("非法 checkpoint 序号: {r}"))
                })?;
                self.checkpoint(Some(seq)).await?
            }
        };

        let hash = cp
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "checkpoint 缺少 digest"))?
            .to_string();
        let seq = cp.get("sequenceNumber").and_then(Value::as_u64);
        let timestamp = cp
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(rfc3339_ok);

        // 交易数 = 截至本 checkpoint 的累计交易数 − 上一 checkpoint 的累计数。
        let total_here = cp
            .get("networkTotalTransactions")
            .and_then(|v| loose_u64(v).ok());
        let mut tx_count: Option<u64> = None;
        if let (Some(seq), Some(total)) = (seq, total_here) {
            if seq == 0 {
                tx_count = Some(total);
            } else if let Ok(prev) = self.checkpoint(Some(seq - 1)).await
                && let Some(prev_total) = prev
                    .get("networkTotalTransactions")
                    .and_then(|v| loose_u64(v).ok())
            {
                tx_count = Some(total.saturating_sub(prev_total));
            }
        }

        let mut view = BlockView::new(ChainKind::Sui, &self.network, hash);
        if let Some(s) = seq {
            view = view.with_height(s);
        }
        if let Some(ts) = timestamp {
            view = view.with_timestamp(ts);
        }
        if let Some(n) = tx_count {
            view = view.with_tx_count(n);
        }
        if let Some(parent) = cp.get("previousCheckpointDigest").and_then(Value::as_str) {
            view = view.with_parent(parent);
        }
        Ok(view.with_extra(json!({
            "epoch": cp.pointer("/epoch/epochId").cloned().unwrap_or(Value::Null),
            "network_total_transactions": cp.get("networkTotalTransactions").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        validate_digest(hash)?;
        let digest = hash.trim();
        let query = format!(
            r#"{{ transaction(digest: "{digest}") {{
                digest
                sender {{ address }}
                effects {{
                    status
                    timestamp
                    checkpoint {{ sequenceNumber }}
                    gasEffects {{ gasSummary {{
                        computationCost storageCost storageRebate nonRefundableStorageFee
                    }} }}
                    balanceChanges(first: 20) {{ nodes {{ coinType {{ repr }} amount }} }}
                }}
            }} }}"#
        );
        let data = self.http.graphql(&query).await?;
        let tx = data
            .get("transaction")
            .filter(|v| !v.is_null())
            .ok_or_else(|| SdkError::not_found(format!("SUI 交易不存在: {digest}")))?;
        let effects = tx
            .get("effects")
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "交易缺少 effects"))?;

        let status = match effects.get("status").and_then(Value::as_str) {
            Some("SUCCESS") => TxStatus::Success,
            Some("FAILURE") => TxStatus::Failed,
            _ => TxStatus::Unknown,
        };
        let mut view = TxView::new(ChainKind::Sui, &self.network, digest, status);
        if let Some(sender) = tx.pointer("/sender/address").and_then(Value::as_str) {
            view = view.with_from(sender);
        }
        if let Some(seq) = effects
            .pointer("/checkpoint/sequenceNumber")
            .and_then(Value::as_u64)
        {
            view = view.with_height(seq);
        }
        if let Some(ts) = effects
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(rfc3339_ok)
        {
            view = view.with_timestamp(ts);
        }
        // gas 总额 = computation + storage − rebate。
        let summary = effects.pointer("/gasEffects/gasSummary");
        if let Some(s) = summary {
            let comp = s
                .get("computationCost")
                .and_then(loose_str_u128)
                .unwrap_or(0);
            let storage = s.get("storageCost").and_then(loose_str_u128).unwrap_or(0);
            let rebate = s.get("storageRebate").and_then(loose_str_u128).unwrap_or(0);
            let fee = comp.saturating_add(storage).saturating_sub(rebate);
            if fee != 0 {
                view = view.with_fee(fee);
            }
        }
        Ok(view.with_extra(json!({
            "balance_changes": effects.pointer("/balanceChanges/nodes").cloned().unwrap_or(Value::Null),
            "gas_summary": summary.cloned().unwrap_or(Value::Null),
        })))
    }

    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        derive_address(pubkey, &self.network)
    }
}

/// Sui 地址 = blake2b-256(scheme_flag || 公钥字节)。
fn derive_address(pubkey: &str, network: &str) -> Result<AddressView, SdkError> {
    let (scheme, flag, expected_len, hex_part) = match pubkey.split_once(':') {
        Some((scheme, rest)) => {
            let (flag, len) = match scheme {
                "ed25519" => (0x00u8, 32),
                "secp256k1" => (0x01u8, 33),
                "secp256r1" => (0x02u8, 33),
                other => {
                    return Err(SdkError::invalid_argument(format!(
                        "未知 SUI 签名方案: {other}（ed25519 / secp256k1 / secp256r1）"
                    )));
                }
            };
            (scheme.to_string(), flag, len, rest)
        }
        // 裸公钥默认 ed25519（32 字节）。
        None => ("ed25519".to_string(), 0x00u8, 32, pubkey),
    };
    let key_bytes = hexutil::decode_hex(hex_part)?;
    if key_bytes.len() != expected_len {
        return Err(SdkError::invalid_argument(format!(
            "{scheme} 公钥应为 {expected_len} 字节，实际 {} 字节",
            key_bytes.len()
        )));
    }
    let mut hasher = Blake2bVar::new(32).expect("32 字节输出合法");
    hasher.update(&[flag]);
    hasher.update(&key_bytes);
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .expect("输出缓冲 32 字节");
    Ok(AddressView::new(
        ChainKind::Sui,
        network,
        hexutil::encode_hex_prefixed(&key_bytes),
        hexutil::encode_hex_prefixed(&digest),
        format!("{scheme}-blake2b"),
        key_bytes.len(),
    )
    .with_extra(json!({
        "scheme": scheme,
        "flag": format!("0x{flag:02x}"),
        "derivation": "blake2b256(flag || pubkey)",
    })))
}

fn validate_address(raw: &str) -> Result<(), SdkError> {
    let body = raw
        .trim()
        .strip_prefix("0x")
        .ok_or_else(|| SdkError::invalid_argument(format!("SUI 地址需以 0x 开头: {raw}")))?;
    if body.len() != 64 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SdkError::invalid_argument(format!("非法 SUI 地址: {raw}")));
    }
    Ok(())
}

fn validate_digest(raw: &str) -> Result<(), SdkError> {
    let t = raw.trim();
    // Sui digest 为 base58 的 32 字节，通常 43/44 字符。
    if !(32..=64).contains(&t.len())
        || t.chars()
            .any(|c| !c.is_ascii_alphanumeric() || matches!(c, '0' | 'O' | 'I' | 'l'))
    {
        return Err(SdkError::invalid_argument(format!(
            "非法 SUI 交易 digest: {raw}"
        )));
    }
    Ok(())
}

fn loose_str_u128(v: &Value) -> Option<u128> {
    v.as_str()
        .and_then(|s| s.parse::<u128>().ok())
        .or_else(|| loose_u128(v).ok())
}

fn rfc3339_ok(s: &str) -> Option<i64> {
    rfc3339_to_unix(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_addresses_and_digests() {
        assert!(validate_address(&format!("0x{}", "ab".repeat(32))).is_ok());
        assert!(validate_address("0x123").is_err());
        assert!(validate_digest("6LRkL8ez2KVq2m3QuwE46DKetS7xuxwwHndLwK1h6cuV").is_ok());
        assert!(validate_digest("has space").is_err());
        assert!(validate_digest("0OIl").is_err());
    }

    #[test]
    fn derives_ed25519_address_stably() {
        let pk = "01".repeat(32);
        let v1 = derive_address(&pk, "mainnet").unwrap();
        let v2 = derive_address(&format!("ed25519:{pk}"), "mainnet").unwrap();
        assert_eq!(v1.address, v2.address);
        assert_eq!(v1.address.len(), 66);
        assert_eq!(v1.address_type, "ed25519-blake2b");
    }

    #[test]
    fn rejects_unknown_scheme_and_bad_length() {
        assert!(derive_address("rsa:abcd", "mainnet").is_err());
        assert!(derive_address(&"ab".repeat(31), "mainnet").is_err());
        let secp = "02".repeat(33);
        assert!(derive_address(&format!("secp256k1:{secp}"), "mainnet").is_ok());
    }

    #[test]
    fn loose_helpers_accept_strings() {
        assert_eq!(loose_str_u128(&json!("1000000000")).unwrap(), 1_000_000_000);
    }
}
