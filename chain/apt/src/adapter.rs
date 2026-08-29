//! Aptos 链对统一 `ChainClient` 契约的实现（REST v1）。

use async_trait::async_trait;
use serde_json::{Value, json};
use sha3::{Digest, Sha3_256};

use allchain_core::{
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, ErrorCode, SdkError, StatusView,
    TxStatus, TxView, hexutil,
};
use chain_rpcutil::{Http, field_u64, loose_u64, loose_u128, micros_to_seconds, url_encode};

use crate::network;

/// Aptos 原生 gas 资产的 CoinStore 资源类型。
const APT_COINSTORE: &str = "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>";

pub struct AptClient {
    network: String,
    rpc_url: String,
    http: Http,
}

impl AptClient {
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let (network_name, url) = match custom {
            Some(url) => ("custom".to_string(), url),
            None => {
                let net = network::parse(network)?;
                (net.as_str().to_string(), net.rpc_url().to_string())
            }
        };
        let http = Http::new(&url)?;
        Ok(Self {
            network: network_name,
            rpc_url: url,
            http,
        })
    }

    /// 顶层账本信息（GET /）。
    async fn ledger_info(&self) -> Result<Value, SdkError> {
        self.http.get_value("").await
    }
}

#[async_trait]
impl ChainClient for AptClient {
    fn kind(&self) -> ChainKind {
        ChainKind::Apt
    }

    fn network(&self) -> &str {
        &self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        let info = self.ledger_info().await?;
        let height = field_u64(&info, "block_height").ok();
        let mut view = StatusView::new(ChainKind::Apt, &self.network, &self.rpc_url);
        if let Some(h) = height {
            view = view.with_height(h);
        }
        // Aptos 账本信息不含最新块哈希，latest_hash 保持 null。
        Ok(view.with_extra(json!({
            "chain_id": info.get("chain_id").cloned().unwrap_or(Value::Null),
            "epoch": info.get("epoch").cloned().unwrap_or(Value::Null),
            "ledger_version": info.get("ledger_version").cloned().unwrap_or(Value::Null),
            "oldest_block_height": info.get("oldest_block_height").cloned().unwrap_or(Value::Null),
            "git_hash": info.get("git_hash").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        validate_address(address)?;
        let path = format!(
            "/accounts/{}/resource/{}",
            address.trim(),
            url_encode(APT_COINSTORE)
        );
        let (raw, registered) = match self.http.get_value(&path).await {
            Ok(v) => {
                let coin = v.get("data").and_then(|d| d.get("coin")).ok_or_else(|| {
                    SdkError::new(ErrorCode::ParseError, format!("CoinStore 结构异常: {v}"))
                })?;
                (
                    loose_u128(coin.get("value").ok_or_else(|| {
                        SdkError::new(ErrorCode::ParseError, "CoinStore.coin 缺少 value 字段")
                    })?)?,
                    true,
                )
            }
            // 账户未注册 APT CoinStore（含账户不存在）等价于零余额。
            Err(e) if e.code == ErrorCode::NotFound => (0, false),
            Err(e) => return Err(e),
        };
        Ok(
            BalanceView::new(ChainKind::Apt, &self.network, address, raw).with_extra(json!({
                "coin_registered": registered,
                "coin_type": "0x1::aptos_coin::AptosCoin",
            })),
        )
    }

    async fn block(&self, reference: Option<&str>) -> Result<BlockView, SdkError> {
        let (path, height_hint) = match reference.map(str::trim).filter(|s| !s.is_empty()) {
            None => {
                let info = self.ledger_info().await?;
                let h = field_u64(&info, "block_height")?;
                (
                    format!("/blocks/by_height/{h}?with_transactions=true"),
                    Some(h),
                )
            }
            Some(r) if is_block_hash(r) => {
                (format!("/blocks/by_hash/{r}?with_transactions=true"), None)
            }
            Some(r) => {
                let h: u64 = r.parse().map_err(|_| {
                    SdkError::invalid_argument(format!(
                        "非法区块引用: {r}（需为高度数字或 0x 区块哈希）"
                    ))
                })?;
                (
                    format!("/blocks/by_height/{h}?with_transactions=true"),
                    Some(h),
                )
            }
        };

        let block = self.http.get_value(&path).await?;
        let hash = block
            .get("block_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SdkError::new(
                    ErrorCode::ParseError,
                    format!("区块缺少 block_hash: {block}"),
                )
            })?
            .to_string();
        let timestamp =
            micros_to_seconds(block.get("block_timestamp").ok_or_else(|| {
                SdkError::new(ErrorCode::ParseError, "区块缺少 block_timestamp")
            })?)?;
        let tx_count = match block.get("transactions").and_then(Value::as_array) {
            Some(txs) => txs.len() as u64,
            // with_transactions=true 时为 null，回退为版本跨度。
            None => match (
                block.get("first_version").and_then(loose_u64_opt),
                block.get("last_version").and_then(loose_u64_opt),
            ) {
                (Some(first), Some(last)) if last >= first => last - first + 1,
                _ => 0,
            },
        };
        let height = block
            .get("block_height")
            .and_then(loose_u64_opt)
            .or(height_hint);

        let mut view = BlockView::new(ChainKind::Apt, &self.network, hash)
            .with_timestamp(timestamp)
            .with_tx_count(tx_count);
        if let Some(h) = height {
            view = view.with_height(h);
        }
        Ok(view.with_extra(json!({
            "first_version": block.get("first_version").cloned().unwrap_or(Value::Null),
            "last_version": block.get("last_version").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        validate_tx_hash(hash)?;
        let tx = self
            .http
            .get_value(&format!("/transactions/by_hash/{}", hash.trim()))
            .await?;

        let success = tx.get("success").and_then(Value::as_bool).unwrap_or(false);
        let pending = tx.get("block_metadata_extension").is_none() && tx.get("version").is_none();
        let status = if pending {
            TxStatus::Pending
        } else if success {
            TxStatus::Success
        } else {
            TxStatus::Failed
        };

        let mut view = TxView::new(ChainKind::Apt, &self.network, hash.trim(), status);
        if let Some(sender) = tx.get("sender").and_then(Value::as_str) {
            view = view.with_from(sender);
        }
        if let Some(version) = tx.get("version").and_then(loose_u64_opt) {
            view = view.with_height(version);
        }
        if let Some(ts) = tx.get("timestamp")
            && let Ok(secs) = micros_to_seconds(ts)
        {
            view = view.with_timestamp(secs);
        }

        // 实际 gas = gas_used × gas_unit_price（octa）。
        let gas_used = tx.get("gas_used").and_then(loose_u128_opt).unwrap_or(0);
        let gas_price = tx
            .get("gas_unit_price")
            .and_then(loose_u128_opt)
            .unwrap_or(0);
        let fee = gas_used.saturating_mul(gas_price);
        if fee != 0 {
            view = view.with_fee(fee);
        }

        // 原生 APT 转账：entry function 0x1::coin::transfer 的参数为 [收款方, 金额]。
        let mut to: Option<String> = None;
        let mut amount: Option<u128> = None;
        if let Some(payload) = tx.get("payload") {
            let function = payload
                .get("function")
                .and_then(Value::as_str)
                .unwrap_or("");
            if function.ends_with("::coin::transfer")
                && let Some(args) = payload.get("arguments").and_then(Value::as_array)
            {
                to = args.first().and_then(Value::as_str).map(str::to_string);
                amount = args.get(1).and_then(loose_u128_opt);
            }
        }
        if let Some(t) = to {
            view = view.with_to(t);
        }
        if let Some(a) = amount {
            view = view.with_amount(a);
        }

        Ok(view.with_extra(json!({
            "tx_type": tx.get("type").cloned().unwrap_or(Value::Null),
            "vm_status": tx.get("vm_status").cloned().unwrap_or(Value::Null),
            "sequence_number": tx.get("sequence_number").cloned().unwrap_or(Value::Null),
            "gas_used": tx.get("gas_used").cloned().unwrap_or(Value::Null),
            "gas_unit_price": tx.get("gas_unit_price").cloned().unwrap_or(Value::Null),
            "version": tx.get("version").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        derive_address(pubkey, &self.network)
    }
}

/// 纯本地派生：Aptos 单签地址 = SHA3-256(pubkey || scheme_byte)。
fn derive_address(pubkey: &str, network: &str) -> Result<AddressView, SdkError> {
    let bytes = hexutil::decode_hex(pubkey)?;
    if bytes.len() != 32 {
        return Err(SdkError::invalid_argument(format!(
            "APT 单签公钥需为 32 字节 ed25519 公钥的十六进制，实际 {} 字节",
            bytes.len()
        )));
    }
    // ed25519 的 scheme byte = 0x00。
    let mut hasher = Sha3_256::new();
    hasher.update(&bytes);
    hasher.update([0x00]);
    let addr = hasher.finalize();
    let address_hex = hexutil::encode_hex_prefixed(&addr);

    Ok(AddressView::new(
        ChainKind::Apt,
        network,
        hexutil::encode_hex_prefixed(&bytes),
        address_hex,
        "ed25519",
        bytes.len(),
    )
    .with_extra(json!({
        "scheme": "ed25519",
        "scheme_byte": "0x00",
        "derivation": "sha3_256(pubkey || 0x00)",
    })))
}

// ---------------------------------------------------------------------------
// 输入校验
// ---------------------------------------------------------------------------

fn validate_address(raw: &str) -> Result<(), SdkError> {
    let t = raw.trim();
    let body = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if body.is_empty() || body.len() > 64 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SdkError::invalid_argument(format!(
            "非法 APT 地址: {raw}（期望 0x + 至多 64 位十六进制）"
        )));
    }
    Ok(())
}

fn validate_tx_hash(raw: &str) -> Result<(), SdkError> {
    let t = raw.trim();
    let body = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if body.len() != 64 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SdkError::invalid_argument(format!(
            "非法 APT 交易哈希: {raw}（期望 0x + 64 位十六进制）"
        )));
    }
    Ok(())
}

fn is_block_hash(raw: &str) -> bool {
    let body = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    body.len() == 64 && body.chars().all(|c| c.is_ascii_hexdigit())
}

fn loose_u64_opt(v: &Value) -> Option<u64> {
    loose_u64(v).ok()
}

fn loose_u128_opt(v: &Value) -> Option<u128> {
    loose_u128(v).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_known_aptos_address() {
        // 回归向量：ed25519 公钥全 0xEE，地址为 sha3_256(pk || 00)。
        let pk = "ee".repeat(32);
        let bytes = hexutil::decode_hex(&pk).unwrap();
        let mut hasher = Sha3_256::new();
        hasher.update(bytes);
        hasher.update([0x00]);
        let expect = format!("0x{}", hexutil::encode_hex(&hasher.finalize()));

        let view = derive_address(&pk, "mainnet").unwrap();
        assert_eq!(view.address, expect);
        assert_eq!(view.address_type, "ed25519");
        assert_eq!(view.pubkey_bytes, 32);
    }

    #[test]
    fn rejects_wrong_pubkey_length() {
        assert!(derive_address(&"ab".repeat(31), "mainnet").is_err());
        assert!(derive_address("", "mainnet").is_err());
    }

    #[test]
    fn validates_addresses_and_hashes() {
        assert!(validate_address("0x1").is_ok());
        assert!(validate_address(&format!("0x{}", "ab".repeat(32))).is_ok());
        assert!(validate_address("0xZZ").is_err());
        assert!(validate_address(&"ab".repeat(33)).is_err());
        assert!(validate_tx_hash(&format!("0x{}", "ab".repeat(32))).is_ok());
        assert!(validate_tx_hash("0x123").is_err());
        assert!(is_block_hash(&format!("0x{}", "ab".repeat(32))));
        assert!(!is_block_hash("12345"));
    }
}
