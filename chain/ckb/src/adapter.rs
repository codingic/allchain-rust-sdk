//! Nervos CKB 链对统一 `ChainClient` 契约的实现（JSON-RPC）。

use async_trait::async_trait;
use serde_json::{Value, json};

use allchain_core::{
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, ErrorCode, SdkError, StatusView,
    TxStatus, TxView, hexutil,
};
use chain_rpcutil::{Http, loose_u64, loose_u128};

use crate::address::{self, LockScript};
use crate::network::{self, NetworkArg};

const PAGE_LIMIT: &str = "0x64"; // 每页 100 个 live cell

pub struct CkbClient {
    network: String,
    rpc_url: String,
    is_mainnet: bool,
    http: Http,
}

impl CkbClient {
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

    /// 分页汇总锁脚本下全部 live cell 的 capacity。
    async fn sum_capacity(&self, script: &LockScript) -> Result<u128, SdkError> {
        let search_key = json!({
            "script": {
                "code_hash": format!("0x{}", hexutil::encode_hex(&script.code_hash)),
                "hash_type": hash_type_str(script.hash_type),
                "args": format!("0x{}", hexutil::encode_hex(&script.args)),
            },
            "script_type": "lock",
            "script_search_mode": "exact",
        });
        let mut cursor: Value = Value::Null;
        let mut total = 0u128;
        let mut pages = 0u32;
        loop {
            let page = self
                .http
                .jsonrpc("get_cells", json!([search_key, "desc", PAGE_LIMIT, cursor]))
                .await?;
            let objects = page.get("objects").and_then(Value::as_array);
            if let Some(objs) = objects {
                for obj in objs {
                    if let Some(cap) = obj.pointer("/output/capacity") {
                        total = total.saturating_add(loose_u128(cap)?);
                    }
                }
            }
            let next = page
                .get("last_cursor")
                .and_then(Value::as_str)
                .unwrap_or("0x");
            // 空游标表示遍历结束。
            if next == "0x" || objects.is_none_or(|o| o.is_empty()) {
                break;
            }
            cursor = json!(next);
            pages += 1;
            if pages > 200 {
                return Err(SdkError::new(
                    ErrorCode::RpcError,
                    "get_cells 翻页超过 200 页，疑似异常，请缩小查询范围",
                ));
            }
        }
        Ok(total)
    }
}

#[async_trait]
impl ChainClient for CkbClient {
    fn kind(&self) -> ChainKind {
        ChainKind::Ckb
    }

    fn network(&self) -> &str {
        &self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        let header = self.http.jsonrpc("get_tip_header", json!([])).await?;
        let mut view = StatusView::new(ChainKind::Ckb, &self.network, &self.rpc_url);
        if let Some(n) = header.get("number").and_then(|v| loose_u64(v).ok()) {
            view = view.with_height(n);
        }
        if let Some(h) = header.get("hash").and_then(Value::as_str) {
            view = view.with_hash(h);
        }
        Ok(view.with_extra(json!({
            "epoch": header.get("epoch").cloned().unwrap_or(Value::Null),
            "parent_hash": header.get("parent_hash").cloned().unwrap_or(Value::Null),
            "dao": header.get("dao").cloned().unwrap_or(Value::Null),
            "timestamp_ms": header.get("timestamp").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        let (script, _) = address::decode_address(address)?;
        let raw = self.sum_capacity(&script).await?;
        Ok(
            BalanceView::new(ChainKind::Ckb, &self.network, address, raw).with_extra(json!({
                "lock_code_hash": format!("0x{}", hexutil::encode_hex(&script.code_hash)),
                "lock_hash_type": hash_type_str(script.hash_type),
            })),
        )
    }

    async fn block(&self, reference: Option<&str>) -> Result<BlockView, SdkError> {
        let block = match reference.map(str::trim).filter(|s| !s.is_empty()) {
            None => {
                let tip = self.http.jsonrpc("get_tip_header", json!([])).await?;
                let hash = tip
                    .get("hash")
                    .and_then(Value::as_str)
                    .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "tip header 缺少 hash"))?;
                self.http.jsonrpc("get_block", json!([hash])).await?
            }
            Some(r) if is_txid_hex(r) => self.http.jsonrpc("get_block", json!([r])).await?,
            Some(r) => {
                let number = normalize_number(r)?;
                let hash = self.http.jsonrpc("get_block_hash", json!([number])).await?;
                let hash = hash.as_str().ok_or_else(|| {
                    SdkError::new(ErrorCode::ParseError, "get_block_hash 未返回哈希")
                })?;
                self.http.jsonrpc("get_block", json!([hash])).await?
            }
        };
        let header = block.get("header").ok_or_else(|| {
            SdkError::new(ErrorCode::ParseError, format!("区块缺少 header: {block}"))
        })?;
        let hash = header
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "header 缺少 hash"))?
            .to_string();
        let mut view = BlockView::new(ChainKind::Ckb, &self.network, hash);
        if let Some(n) = header.get("number").and_then(|v| loose_u64(v).ok()) {
            view = view.with_height(n);
        }
        if let Some(ts_hex) = header.get("timestamp").and_then(Value::as_str)
            && let Ok(ms) = u64::from_str_radix(ts_hex.trim_start_matches("0x"), 16)
        {
            view = view.with_timestamp((ms / 1000) as i64);
        }
        if let Some(parent) = header.get("parent_hash").and_then(Value::as_str) {
            view = view.with_parent(parent);
        }
        let tx_count = block
            .get("transactions")
            .and_then(Value::as_array)
            .map(|txs| txs.len() as u64)
            .unwrap_or(0);
        let proposal_count = block
            .get("proposals")
            .and_then(Value::as_array)
            .map(|p| p.len() as u64)
            .unwrap_or(0);
        Ok(view.with_tx_count(tx_count).with_extra(json!({
            "proposal_count": proposal_count,
            "uncle_count": block.get("uncles").and_then(Value::as_array).map(|u| u.len()),
            "epoch": header.get("epoch").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        validate_txid(hash)?;
        let result = self
            .http
            .jsonrpc("get_transaction", json!([hash.trim()]))
            .await?;
        if result.is_null() {
            return Err(SdkError::not_found(format!("CKB 交易不存在: {hash}")));
        }
        let tx_status = result.get("tx_status").cloned().unwrap_or(Value::Null);
        let status_str = tx_status
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("");
        let status = match status_str {
            "committed" => TxStatus::Success,
            "proposed" => TxStatus::Pending,
            _ => TxStatus::Pending,
        };
        let transaction = result.get("transaction").ok_or_else(|| {
            SdkError::new(
                ErrorCode::ParseError,
                format!("交易缺少 transaction: {result}"),
            )
        })?;

        let mut view = TxView::new(ChainKind::Ckb, &self.network, hash.trim(), status);
        if let Some(n) = tx_status
            .get("block_number")
            .and_then(|v| loose_u64(v).ok())
        {
            view = view.with_height(n);
        }
        if let Some(fee_hex) = result.get("fee").and_then(Value::as_str)
            && let Ok(fee) = u128::from_str_radix(fee_hex.trim_start_matches("0x"), 16)
        {
            view = view.with_fee(fee);
        }

        // 输入只引用前序 outpoint，无法直接还原地址，记录到 extra。
        let mut from_outpoint = Value::Null;
        let mut is_cellbase = false;
        if let Some(inputs) = transaction.get("inputs").and_then(Value::as_array)
            && let Some(first) = inputs.first()
        {
            from_outpoint = first.get("previous_output").cloned().unwrap_or(Value::Null);
            is_cellbase = from_outpoint
                .get("index")
                .and_then(Value::as_str)
                .is_some_and(|i| i == "0xffffffff");
        }

        // 输出：to 取首个输出锁脚本重新编码出的地址；金额为全部输出 capacity 之和。
        let mut to_address: Option<String> = None;
        if let Some(outputs) = transaction.get("outputs").and_then(Value::as_array) {
            let mut total = 0u128;
            for out in outputs {
                if let Some(cap) = out.get("capacity").and_then(|v| loose_u128(v).ok()) {
                    total = total.saturating_add(cap);
                }
            }
            view = view.with_amount(total);
            if let Some(first_lock) = outputs.first().and_then(|o| o.get("lock"))
                && let Some(script) = parse_lock_json(first_lock)
            {
                to_address = Some(address::encode_address(&script, self.is_mainnet));
            }
        }
        if let Some(to) = to_address {
            view = view.with_to(to);
        }

        Ok(view.with_extra(json!({
            "status_detail": status_str,
            "block_hash": tx_status.get("block_hash").cloned().unwrap_or(Value::Null),
            "tx_index": tx_status.get("tx_index").cloned().unwrap_or(Value::Null),
            "cycles": result.get("cycles").cloned().unwrap_or(Value::Null),
            "from_outpoint": from_outpoint,
            "cellbase": is_cellbase,
        })))
    }

    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        let bytes = hexutil::decode_hex(pubkey)?;
        if bytes.len() != 33 {
            return Err(SdkError::invalid_argument(format!(
                "CKB 单签公钥需为 33 字节压缩 secp256k1 公钥，实际 {} 字节",
                bytes.len()
            )));
        }
        let blake160 = address::ckb_blake160(&bytes);
        let script = LockScript::sighash_blake160(blake160);
        let address = address::encode_address(&script, self.is_mainnet);
        let short = address::encode_short_sighash_address(&blake160, self.is_mainnet)?;
        Ok(AddressView::new(
            ChainKind::Ckb,
            &self.network,
            hexutil::encode_hex_prefixed(&bytes),
            address,
            "secp256k1-blake160-full",
            bytes.len(),
        )
        .with_extra(json!({
            "derivation": "blake160(compressed_pubkey) -> secp256k1_blake160_sighash_all lock",
            "address_format": "full",
            "alternatives": {
                "short_deprecated": short,
            },
            "lock_args": format!("0x{}", hexutil::encode_hex(&blake160)),
        })))
    }
}

fn hash_type_str(hash_type: u8) -> &'static str {
    match hash_type {
        0 => "data",
        1 => "type",
        2 => "data1",
        4 => "data2",
        _ => "type",
    }
}

fn parse_lock_json(value: &Value) -> Option<LockScript> {
    let code_hash_hex = value.get("code_hash")?.as_str()?;
    let code_hash_bytes = hexutil::decode_hex(code_hash_hex).ok()?;
    let code_hash: [u8; 32] = code_hash_bytes.try_into().ok()?;
    let ht = match value.get("hash_type")?.as_str()? {
        "data" => 0,
        "type" => 1,
        "data1" => 2,
        "data2" => 4,
        _ => 1,
    };
    let args = hexutil::decode_hex(value.get("args")?.as_str()?).ok()?;
    Some(LockScript {
        code_hash,
        hash_type: ht,
        args,
    })
}

fn validate_txid(raw: &str) -> Result<(), SdkError> {
    let body = raw
        .trim()
        .strip_prefix("0x")
        .ok_or_else(|| SdkError::invalid_argument(format!("CKB 哈希需带 0x 前缀: {raw}")))?;
    if body.len() != 64 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SdkError::invalid_argument(format!(
            "非法 CKB 交易哈希: {raw}"
        )));
    }
    Ok(())
}

fn is_txid_hex(raw: &str) -> bool {
    raw.strip_prefix("0x")
        .is_some_and(|b| b.len() == 64 && b.chars().all(|c| c.is_ascii_hexdigit()))
}

/// 区块号统一为 `0x` 十六进制字符串。
fn normalize_number(raw: &str) -> Result<String, SdkError> {
    if let Some(hex) = raw.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
            .map(|n| format!("0x{n:x}"))
            .map_err(|_| SdkError::invalid_argument(format!("非法区块号: {raw}")))
    } else {
        raw.parse::<u64>()
            .map(|n| format!("0x{n:x}"))
            .map_err(|_| SdkError::invalid_argument(format!("非法区块引用: {raw}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_block_numbers() {
        assert_eq!(normalize_number("100").unwrap(), "0x64");
        assert_eq!(normalize_number("0x64").unwrap(), "0x64");
        assert!(normalize_number("abc").is_err());
    }

    #[test]
    fn validates_txids() {
        assert!(validate_txid(&format!("0x{}", "ab".repeat(32))).is_ok());
        assert!(validate_txid(&"ab".repeat(32)).is_err());
        assert!(is_txid_hex(&format!("0x{}", "ab".repeat(32))));
    }
}
