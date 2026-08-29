//! Filecoin 链对统一 `ChainClient` 契约的实现（Lotus JSON-RPC）。

use async_trait::async_trait;
use serde_json::{Value, json};

use allchain_core::{
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, ErrorCode, SdkError, StatusView,
    TxStatus, TxView, hexutil,
};
use chain_rpcutil::{Http, field_u64, loose_u128};

use crate::address;
use crate::network::{self, NetworkArg};

pub struct FilClient {
    network: String,
    rpc_url: String,
    is_mainnet: bool,
    http: Http,
}

impl FilClient {
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let (network_name, url, is_mainnet) = match custom {
            Some(url) => ("custom".to_string(), url, true),
            None => {
                let net = network::parse(network)?;
                (
                    net.as_str().to_string(),
                    net.rpc_url().to_string(),
                    net == NetworkArg::Mainnet,
                )
            }
        };
        let http = Http::new(&url)?;
        Ok(Self {
            network: network_name,
            rpc_url: url,
            is_mainnet,
            http,
        })
    }

    /// 把 CID 包成 Lotus 的 IPLD 引用形式 `{"/": cid}`。
    fn cid_ref(cid: &str) -> Value {
        json!({ "/": cid })
    }
}

#[async_trait]
impl ChainClient for FilClient {
    fn kind(&self) -> ChainKind {
        ChainKind::Fil
    }

    fn network(&self) -> &str {
        &self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        let head = self.http.jsonrpc("Filecoin.ChainHead", json!([])).await?;
        let version = self.http.jsonrpc("Filecoin.Version", json!([])).await.ok();
        let mut view = StatusView::new(ChainKind::Fil, &self.network, &self.rpc_url);
        if let Ok(h) = field_u64(&head, "Height") {
            view = view.with_height(h);
        }
        if let Some(cid) = head.pointer("/Cids/0/~1").and_then(Value::as_str) {
            view = view.with_hash(cid);
        }
        if let Some(v) = version
            .as_ref()
            .and_then(|v| v.get("Version"))
            .and_then(Value::as_str)
        {
            view = view.with_version(v);
        }
        Ok(view.with_extra(json!({
            "blocks_count": head.get("Blocks").and_then(Value::as_array).map(|b| b.len()),
            "miner": head.pointer("/Blocks/0/Miner").cloned().unwrap_or(Value::Null),
            "parent_base_fee": head.pointer("/Blocks/0/ParentBaseFee").cloned().unwrap_or(Value::Null),
            "timestamp": head.pointer("/Blocks/0/Timestamp").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        let (protocol, _, _) = address::inspect(address)?;
        let result = self
            .http
            .jsonrpc("Filecoin.WalletBalance", json!([address.trim()]))
            .await?;
        let raw = match result.as_str() {
            Some(s) => s.parse::<u128>().map_err(|_| {
                SdkError::new(ErrorCode::ParseError, format!("非法 attoFIL 余额: {s}"))
            })?,
            None => 0,
        };
        Ok(
            BalanceView::new(ChainKind::Fil, &self.network, address, raw).with_extra(json!({
                "protocol": protocol,
            })),
        )
    }

    async fn block(&self, reference: Option<&str>) -> Result<BlockView, SdkError> {
        let tipset = match reference.map(str::trim).filter(|s| !s.is_empty()) {
            None => self.http.jsonrpc("Filecoin.ChainHead", json!([])).await?,
            Some(r) if r.bytes().all(|b| b.is_ascii_digit()) => {
                let height: u64 = r
                    .parse()
                    .map_err(|_| SdkError::invalid_argument(format!("非法区块高度: {r}")))?;
                self.http
                    .jsonrpc(
                        "Filecoin.ChainGetTipSetByHeight",
                        json!([height, Value::Null]),
                    )
                    .await?
            }
            Some(cid) => {
                self.http
                    .jsonrpc("Filecoin.ChainGetTipSet", json!([[Self::cid_ref(cid)]]))
                    .await?
            }
        };
        if tipset.is_null() {
            return Err(SdkError::not_found("指定的 tipset 不存在"));
        }

        let hash = tipset
            .pointer("/Cids/0/~1")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "tipset 缺少 Cids"))?
            .to_string();
        let height = field_u64(&tipset, "Height").ok();
        let blocks = tipset.get("Blocks").and_then(Value::as_array);
        let timestamp = blocks
            .and_then(|b| b.first())
            .and_then(|b| b.get("Timestamp"))
            .and_then(Value::as_i64);
        let parent = blocks
            .and_then(|b| b.first())
            .and_then(|b| b.pointer("/Parents/0/~1"))
            .and_then(Value::as_str);
        let miner = blocks
            .and_then(|b| b.first())
            .and_then(|b| b.get("Miner"))
            .and_then(Value::as_str);

        // 消息数：统计 tipset 第一个块内的 BLS + secp 消息。
        let mut tx_count = 0u64;
        if let Some(cid) = tipset.pointer("/Cids/0/~1").and_then(Value::as_str)
            && let Ok(msgs) = self
                .http
                .jsonrpc(
                    "Filecoin.ChainGetBlockMessages",
                    json!([Self::cid_ref(cid)]),
                )
                .await
        {
            let bls = msgs
                .get("BlsMessages")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0);
            let secp = msgs
                .get("SecpkMessages")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0);
            tx_count = (bls + secp) as u64;
        }

        let mut view = BlockView::new(ChainKind::Fil, &self.network, hash).with_tx_count(tx_count);
        if let Some(h) = height {
            view = view.with_height(h);
        }
        if let Some(ts) = timestamp {
            view = view.with_timestamp(ts);
        }
        if let Some(p) = parent {
            view = view.with_parent(p);
        }
        Ok(view.with_extra(json!({
            "blocks_in_tipset": blocks.map(|b| b.len()),
            "miner": miner,
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        validate_cid(hash)?;
        let id = hash.trim();
        let message = self
            .http
            .jsonrpc("Filecoin.ChainGetMessage", json!([Self::cid_ref(id)]))
            .await?;
        if message.is_null() {
            return Err(SdkError::not_found(format!("FIL 消息不存在: {id}")));
        }
        // Glif 公共节点不提供 ChainGetReceipt，改用 StateSearchMsg 拿执行回执与上链高度；
        // 返回 null 表示消息尚未上链（mempool / 等待打包）。
        let search = self
            .http
            .jsonrpc(
                "Filecoin.StateSearchMsg",
                json!([Value::Null, Self::cid_ref(id), -1, false]),
            )
            .await
            .ok()
            .filter(|v| !v.is_null());
        let receipt = search.as_ref().and_then(|s| s.get("Receipt"));

        let status = match receipt
            .and_then(|r| r.get("ExitCode"))
            .and_then(Value::as_i64)
        {
            None => TxStatus::Pending,
            Some(0) => TxStatus::Success,
            Some(_) => TxStatus::Failed,
        };

        let mut view = TxView::new(ChainKind::Fil, &self.network, id, status);
        if let Some(h) = search
            .as_ref()
            .and_then(|s| s.get("Height"))
            .and_then(Value::as_u64)
        {
            view = view.with_height(h);
        }
        if let Some(from) = message.get("From").and_then(Value::as_str) {
            view = view.with_from(from);
        }
        if let Some(to) = message.get("To").and_then(Value::as_str) {
            view = view.with_to(to);
        }
        // Method=0 是原生 FIL 转账，Value 才有金额语义。
        let method = message.get("Method").and_then(Value::as_u64).unwrap_or(0);
        if method == 0
            && let Some(value) = message.get("Value").and_then(loose_str_u128)
        {
            view = view.with_amount(value);
        }
        // 手续费 = GasUsed × GasPremium（attoFIL）。
        let gas_used = receipt
            .and_then(|r| r.get("GasUsed"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as u128;
        let gas_premium = message
            .get("GasPremium")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        let fee = gas_used.saturating_mul(gas_premium);
        if fee != 0 {
            view = view.with_fee(fee);
        }

        Ok(view.with_extra(json!({
            "method": method,
            "nonce": message.get("Nonce").cloned().unwrap_or(Value::Null),
            "gas_limit": message.get("GasLimit").cloned().unwrap_or(Value::Null),
            "gas_fee_cap": message.get("GasFeeCap").cloned().unwrap_or(Value::Null),
            "gas_premium": message.get("GasPremium").cloned().unwrap_or(Value::Null),
            "gas_used": receipt.and_then(|r| r.get("GasUsed")).cloned().unwrap_or(Value::Null),
            "exit_code": receipt.and_then(|r| r.get("ExitCode")).cloned().unwrap_or(Value::Null),
        })))
    }

    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        let bytes = hexutil::decode_hex(pubkey)?;
        let address = address::f1_from_pubkey(pubkey, self.is_mainnet)?;
        Ok(AddressView::new(
            ChainKind::Fil,
            &self.network,
            hexutil::encode_hex_prefixed(&bytes),
            address,
            "f1-secp256k1",
            bytes.len(),
        )
        .with_extra(json!({
            "protocol": 1,
            "derivation": "blake2b160(uncompressed_pubkey) + blake2b checksum + base32",
        })))
    }
}

fn loose_str_u128(v: &Value) -> Option<u128> {
    v.as_str()
        .and_then(|s| s.parse::<u128>().ok())
        .or_else(|| loose_u128(v).ok())
}

fn validate_cid(raw: &str) -> Result<(), SdkError> {
    let t = raw.trim();
    // Filecoin CID v1 以 bafy/bafk 等开头，长度通常 50+。
    if t.len() < 40 || !t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(SdkError::invalid_argument(format!(
            "非法 FIL 消息 CID: {raw}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_cids() {
        assert!(
            validate_cid("bafy2bzacectcjfi3cux3kxb4c2vdgwzdd3ikdqdflhstslyqnthtbaub6ubge").is_ok()
        );
        assert!(validate_cid("short").is_err());
    }

    #[test]
    fn parses_str_u128() {
        assert_eq!(
            loose_str_u128(&json!("123456789012345678901")).unwrap(),
            123_456_789_012_345_678_901
        );
        assert_eq!(loose_str_u128(&json!(42)).unwrap(), 42);
    }
}
