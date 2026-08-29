//! Arweave 链对统一 `ChainClient` 契约的实现（公共网关 REST）。

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use allchain_core::{
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, ErrorCode, SdkError, StatusView,
    TxStatus, TxView,
};
use chain_rpcutil::{Http, field_u64};

use crate::network;

pub struct ArClient {
    network: String,
    rpc_url: String,
    http: Http,
}

impl ArClient {
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let (network_name, url) = match custom {
            Some(url) => ("custom".to_string(), url),
            None => {
                let net = network::parse(network)?;
                (net.as_str().to_string(), net.gateway_url().to_string())
            }
        };
        let http = Http::new(&url)?;
        Ok(Self {
            network: network_name,
            rpc_url: url,
            http,
        })
    }
}

#[async_trait]
impl ChainClient for ArClient {
    fn kind(&self) -> ChainKind {
        ChainKind::Ar
    }

    fn network(&self) -> &str {
        &self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        let info = self.http.get_value("/info").await?;
        let mut view = StatusView::new(ChainKind::Ar, &self.network, &self.rpc_url);
        if let Ok(h) = field_u64(&info, "height") {
            view = view.with_height(h);
        }
        if let Some(current) = info.get("current").and_then(Value::as_str) {
            view = view.with_hash(current);
        }
        Ok(view.with_extra(json!({
            "network": info.get("network").cloned().unwrap_or(Value::Null),
            "version": info.get("version").cloned().unwrap_or(Value::Null),
            "release": info.get("release").cloned().unwrap_or(Value::Null),
            "peers": info.get("peers").cloned().unwrap_or(Value::Null),
            "blocks": info.get("blocks").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        validate_address(address)?;
        // 网关返回纯文本 winston 余额。
        let text = self
            .http
            .get_text(&format!("/wallet/{}/balance", address.trim()))
            .await?;
        let raw = text.trim().parse::<u128>().map_err(|_| {
            SdkError::new(ErrorCode::ParseError, format!("非法 winston 余额: {text}"))
        })?;
        Ok(BalanceView::new(ChainKind::Ar, &self.network, address, raw))
    }

    async fn block(&self, reference: Option<&str>) -> Result<BlockView, SdkError> {
        let path = match reference.map(str::trim).filter(|s| !s.is_empty()) {
            None => {
                let info = self.http.get_value("/info").await?;
                let h = field_u64(&info, "height")?;
                format!("/block/height/{h}")
            }
            Some(r) if r.chars().all(|c| c.is_ascii_digit()) => format!("/block/height/{r}"),
            Some(r) => {
                validate_txid(r)?;
                format!("/block/hash/{r}")
            }
        };
        let block = self.http.get_value(&path).await?;
        let hash = block
            .get("indep_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SdkError::new(
                    ErrorCode::ParseError,
                    format!("区块缺少 indep_hash: {block}"),
                )
            })?
            .to_string();
        let height = field_u64(&block, "height").ok();
        let timestamp = field_u64(&block, "timestamp").ok().map(|t| t as i64);
        let tx_count = block
            .get("txs")
            .and_then(Value::as_array)
            .map(|txs| txs.len() as u64);

        let mut view = BlockView::new(ChainKind::Ar, &self.network, hash);
        if let Some(h) = height {
            view = view.with_height(h);
        }
        if let Some(t) = timestamp {
            view = view.with_timestamp(t);
        }
        if let Some(n) = tx_count {
            view = view.with_tx_count(n);
        }
        if let Some(parent) = block.get("previous_block").and_then(Value::as_str) {
            view = view.with_parent(parent);
        }
        Ok(view.with_extra(json!({
            "nonce": block.get("nonce").cloned().unwrap_or(Value::Null),
            "reward_addr": block.get("reward_addr").cloned().unwrap_or(Value::Null),
            "weave_size": block.get("weave_size").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        validate_txid(hash)?;
        let id = hash.trim();
        let tx = self.http.get_value(&format!("/tx/{id}")).await?;
        // 确认状态：已上链时带 block_height；内存池中的交易无该字段。
        let status_text = self.http.get_text(&format!("/tx/{id}/status")).await.ok();
        let status_value: Option<Value> = status_text.and_then(|t| serde_json::from_str(&t).ok());
        let block_height = status_value
            .as_ref()
            .and_then(|s| s.get("block_height"))
            .and_then(Value::as_u64);
        let confirmations = status_value
            .as_ref()
            .and_then(|s| s.get("number_of_confirmations"))
            .cloned()
            .unwrap_or(Value::Null);

        let status = if block_height.is_some() {
            // Arweave 没有“失败上链”的概念，进入区块即成功。
            TxStatus::Success
        } else {
            TxStatus::Pending
        };

        let mut view = TxView::new(ChainKind::Ar, &self.network, id, status);
        if let Some(h) = block_height {
            view = view.with_height(h);
        }
        // owner 是 RSA 公钥模数（base64url），链上地址 = base64url(sha256(owner_bytes))。
        if let Some(owner) = tx.get("owner").and_then(Value::as_str)
            && let Ok(addr) = owner_to_address(owner)
        {
            view = view.with_from(addr);
        }
        if let Some(target) = tx.get("target").and_then(Value::as_str)
            && !target.is_empty()
        {
            view = view.with_to(target);
        }
        if let Some(q) = tx.get("quantity").and_then(Value::as_str)
            && let Ok(amount) = q.parse::<u128>()
        {
            view = view.with_amount(amount);
        }
        if let Some(r) = tx.get("reward").and_then(Value::as_str)
            && let Ok(fee) = r.parse::<u128>()
        {
            view = view.with_fee(fee);
        }
        Ok(view.with_extra(json!({
            "data_size": tx.get("data_size").cloned().unwrap_or(Value::Null),
            "format": tx.get("format").cloned().unwrap_or(Value::Null),
            "content_type": tx.get("content_type").cloned().unwrap_or(Value::Null),
            "tags_count": tx.get("tags").and_then(Value::as_array).map(|t| t.len()),
            "number_of_confirmations": confirmations,
        })))
    }

    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        derive_address(pubkey, &self.network)
    }
}

/// RSA 公钥模数（base64url）→ Arweave 地址（base64url(sha256(n))）。
fn derive_address(pubkey: &str, network: &str) -> Result<AddressView, SdkError> {
    let modulus = URL_SAFE_NO_PAD.decode(pubkey.trim()).map_err(|e| {
        SdkError::invalid_argument(format!("AR 公钥需为 base64url 的 RSA 模数 n: {e}"))
    })?;
    // Arweave 主网使用 4096 位 RSA（模数 512 字节）；不强制长度，只记录真实字节数。
    let digest = Sha256::digest(&modulus);
    let address = URL_SAFE_NO_PAD.encode(digest);
    validate_address(&address)?;
    Ok(AddressView::new(
        ChainKind::Ar,
        network,
        pubkey.trim(),
        address,
        "rsa-modulus-sha256",
        modulus.len(),
    )
    .with_extra(json!({
        "derivation": "base64url(sha256(rsa_modulus_bytes))",
    })))
}

fn owner_to_address(owner_b64url: &str) -> Result<String, SdkError> {
    let modulus = URL_SAFE_NO_PAD.decode(owner_b64url).map_err(|e| {
        SdkError::new(
            ErrorCode::ParseError,
            format!("owner 不是合法 base64url: {e}"),
        )
    })?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(modulus)))
}

/// 校验 Arweave 地址 / 交易 ID：base64url 无填充，地址固定 43 字符。
fn validate_address(raw: &str) -> Result<(), SdkError> {
    let t = raw.trim();
    if t.len() != 43
        || !t
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(SdkError::invalid_argument(format!(
            "非法 AR 地址: {raw}（期望 43 字符 base64url 字符串）"
        )));
    }
    URL_SAFE_NO_PAD
        .decode(t)
        .map_err(|e| SdkError::invalid_argument(format!("非法 AR 地址: {e}")))?;
    Ok(())
}

fn validate_txid(raw: &str) -> Result<(), SdkError> {
    let t = raw.trim();
    if t.len() != 43
        || !t
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(SdkError::invalid_argument(format!(
            "非法 AR 交易/区块 ID: {raw}（期望 43 字符 base64url 字符串）"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_arweave_ids() {
        assert!(
            validate_address("vmcOl107fL4JN0UDrQwCxA_zkp32MlAsWvsKZ3Wea8si7YZbnvNG-xku3QUenAPE")
                .is_err()
        ); // 64 字符，超长
        assert!(validate_txid("CwaasGHuRNeJqkPiVwnqfj3BHb0XJaO41JHUeNc4kow").is_ok()); // 43
        assert!(validate_txid("short").is_err());
        assert!(
            validate_txid("含有中文字符________________base64url_____________________").is_err()
        );
    }

    #[test]
    fn derives_address_from_owner() {
        // 全 0x03 的 512 字节模数，派生结果稳定。
        let n = URL_SAFE_NO_PAD.encode([3u8; 512]);
        let view = derive_address(&n, "mainnet").unwrap();
        assert_eq!(view.address.len(), 43);
        assert_eq!(view.pubkey_bytes, 512);
        // 与 owner_to_address 路径一致。
        assert_eq!(view.address, owner_to_address(&n).unwrap());
    }
}
