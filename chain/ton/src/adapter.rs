//! TON 链对统一 `ChainClient` 契约的实现（toncenter REST v2）。

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio::time::{Instant, sleep};

use allchain_core::{
    BalanceView, BlockView, ChainClient, ChainKind, ErrorCode, SdkError, StatusView, TxStatus,
    TxView,
};
use chain_rpcutil::{Http, field_u64, loose_u128, url_encode};

use crate::network;

/// 主链（masterchain）固定 workchain / shard。
const MASTER_WORKCHAIN: i32 = -1;
const MASTER_SHARD: &str = "-9223372036854775808";

/// toncenter 免费档约 1 req/s，客户端内串行节流，避免 429。
const MIN_CALL_GAP_MS: u64 = 1100;

pub struct TonClient {
    network: String,
    rpc_url: String,
    /// 可选 API key（toncenter 免费档限速，key 通过 query 传递）。
    api_key: Option<String>,
    http: Http,
    last_call: Mutex<Option<Instant>>,
}

impl TonClient {
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let (network_name, url) = match custom {
            Some(url) => ("custom".to_string(), url),
            None => {
                let net = network::parse(network)?;
                (net.as_str().to_string(), net.api_url().to_string())
            }
        };
        // 允许通过环境变量传入 toncenter API key，缺省走免费档。
        let api_key = std::env::var("TONCENTER_API_KEY")
            .ok()
            .filter(|s| !s.is_empty());
        let http = Http::new(&url)?;
        Ok(Self {
            network: network_name,
            rpc_url: url,
            api_key,
            http,
            last_call: Mutex::new(None),
        })
    }

    /// 拼接带可选 api_key 的查询路径。
    fn with_key(&self, path: String) -> String {
        match &self.api_key {
            Some(key) => format!("{path}&api_key={key}"),
            None => path,
        }
    }

    /// 串行节流：保证相邻请求至少间隔 MIN_CALL_GAP_MS。
    async fn throttle(&self) {
        let mut last = self.last_call.lock().await;
        if let Some(prev) = *last {
            let elapsed = prev.elapsed();
            if elapsed < std::time::Duration::from_millis(MIN_CALL_GAP_MS) {
                sleep(std::time::Duration::from_millis(MIN_CALL_GAP_MS) - elapsed).await;
            }
        }
        *last = Some(Instant::now());
    }

    /// toncenter 统一信封：`{ok, result}`，ok=false 时映射错误。
    async fn call(&self, path: String) -> Result<Value, SdkError> {
        self.throttle().await;
        let value = self.http.get_value(&self.with_key(path)).await?;
        if value.get("ok").and_then(Value::as_bool) == Some(false) {
            let message = value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("toncenter 返回 ok=false")
                .to_string();
            let code = value.get("code").and_then(Value::as_i64);
            return Err(match code {
                Some(404) | Some(422) => SdkError::not_found(message),
                Some(429) => {
                    SdkError::new(ErrorCode::RpcError, format!("toncenter 限流: {message}"))
                }
                _ => SdkError::new(ErrorCode::RpcError, message),
            });
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| SdkError::new(ErrorCode::RpcError, "响应缺少 result 字段"))
    }
}

#[async_trait]
impl ChainClient for TonClient {
    fn kind(&self) -> ChainKind {
        ChainKind::Ton
    }

    fn network(&self) -> &str {
        &self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        let info = self.call("/getMasterchainInfo".to_string()).await?;
        let last = info
            .get("last")
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "缺少 last 块信息"))?;
        let mut view = StatusView::new(ChainKind::Ton, &self.network, &self.rpc_url);
        if let Ok(seq) = field_u64(last, "seqno") {
            view = view.with_height(seq);
        }
        if let Some(hash) = last.get("root_hash").and_then(Value::as_str) {
            view = view.with_hash(hash);
        }
        Ok(view.with_extra(json!({
            "workchain": last.get("workchain").cloned().unwrap_or(Value::Null),
            "shard": last.get("shard").cloned().unwrap_or(Value::Null),
            "file_hash": last.get("file_hash").cloned().unwrap_or(Value::Null),
            "state_root_hash": info.get("state_root_hash").cloned().unwrap_or(Value::Null),
            "init_file_hash": info.get("init_file_hash").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        validate_address(address)?;
        let path = format!("/getAddressBalance?address={}", url_encode(address.trim()));
        let result = self.call(path).await?;
        // result 是 nanoton 十进制字符串。
        let raw = match result {
            Value::String(s) => s.parse::<u128>().map_err(|_| {
                SdkError::new(ErrorCode::ParseError, format!("非法 nanoton 余额: {s}"))
            })?,
            other => loose_u128(&other)?,
        };
        Ok(BalanceView::new(
            ChainKind::Ton,
            &self.network,
            address,
            raw,
        ))
    }

    async fn block(&self, reference: Option<&str>) -> Result<BlockView, SdkError> {
        let seqno = match reference.map(str::trim).filter(|s| !s.is_empty()) {
            None => {
                let info = self.call("/getMasterchainInfo".to_string()).await?;
                field_u64(
                    info.get("last")
                        .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "缺少 last 块信息"))?,
                    "seqno",
                )?
            }
            Some(r) => r
                .parse::<u64>()
                .map_err(|_| SdkError::invalid_argument(format!("非法主链区块序号: {r}")))?,
        };
        let path = format!(
            "/getBlockHeader?workchain={MASTER_WORKCHAIN}&shard={MASTER_SHARD}&seqno={seqno}"
        );
        let header = self.call(path).await?;
        let id = header
            .get("id")
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "block header 缺少 id"))?;
        let hash = id
            .get("root_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "block id 缺少 root_hash"))?
            .to_string();

        let mut view = BlockView::new(ChainKind::Ton, &self.network, hash).with_height(seqno);
        if let Some(utime) = header.get("gen_utime").and_then(Value::as_i64) {
            view = view.with_timestamp(utime);
        }
        // 父块：prev_blocks[0] 本身即 blockIdExt，直接带 root_hash / seqno。
        let mut parent_seqno = Value::Null;
        if let Some(prev) = header
            .get("prev_blocks")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
        {
            parent_seqno = prev.get("seqno").cloned().unwrap_or(Value::Null);
            if let Some(rh) = prev.get("root_hash").and_then(Value::as_str) {
                view = view.with_parent(rh);
            }
        }

        // 交易数：尽力查询，失败不阻塞区块概览。
        let tx_path = format!(
            "/getBlockTransactions?workchain={MASTER_WORKCHAIN}&shard={MASTER_SHARD}&seqno={seqno}&count=1000"
        );
        if let Ok(txs) = self.call(tx_path).await
            && let Some(list) = txs.get("transactions").and_then(Value::as_array)
        {
            view = view.with_tx_count(list.len() as u64);
        }

        Ok(view.with_extra(json!({
            "workchain": id.get("workchain").cloned().unwrap_or(Value::Null),
            "shard": id.get("shard").cloned().unwrap_or(Value::Null),
            "file_hash": id.get("file_hash").cloned().unwrap_or(Value::Null),
            "is_key_block": header.get("is_key_block").cloned().unwrap_or(Value::Null),
            "global_id": header.get("global_id").cloned().unwrap_or(Value::Null),
            "parent_seqno": parent_seqno,
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        // TON 定位一笔交易需要 (hash, lt, account)，统一约定引用格式：
        // `<tx_hash_base64>:<lt>@<address>`。
        let (tx_hash, lt, address) = parse_tx_locator(hash)?;
        let path = format!(
            "/getTransactions?address={}&limit=1&lt={lt}&hash={}",
            url_encode(&address),
            url_encode(&tx_hash)
        );
        let result = self.call(path).await?;
        let item = result
            .as_array()
            .and_then(|a| a.first())
            .ok_or_else(|| SdkError::not_found(format!("未找到 TON 交易: {hash}")))?;

        // 交易可被节点返回即代表已执行（失败交易会被链丢弃）。
        let mut view = TxView::new(ChainKind::Ton, &self.network, &tx_hash, TxStatus::Success);
        if let Some(utime) = item.get("utime").and_then(Value::as_i64) {
            view = view.with_timestamp(utime);
        }
        if let Some(in_msg) = item.get("in_msg") {
            if let Some(source) = in_msg.get("source").and_then(Value::as_str)
                && !source.is_empty()
            {
                view = view.with_from(source);
            }
            if let Some(dest) = in_msg.get("destination").and_then(Value::as_str) {
                view = view.with_to(dest);
            }
            if let Some(value) = in_msg.get("value").and_then(Value::as_str)
                && let Ok(amount) = value.parse::<u128>()
            {
                view = view.with_amount(amount);
            }
        }
        let fee = item
            .get("fee")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u128>().ok());
        if let Some(fee) = fee {
            view = view.with_fee(fee);
        }
        let out_count = item
            .get("out_msgs")
            .and_then(Value::as_array)
            .map(|m| m.len());
        Ok(view.with_extra(json!({
            "lt": item.pointer("/transaction_id/lt").cloned().unwrap_or(json!(lt)),
            "account": address,
            "storage_fee": item.get("storage_fee").cloned().unwrap_or(Value::Null),
            "other_fee": item.get("other_fee").cloned().unwrap_or(Value::Null),
            "out_message_count": out_count,
        })))
    }

    // 不实现 address_from_pubkey：TON 地址是钱包合约 StateInit 的哈希，
    // 依赖具体钱包合约版本（V3/V4R2/W5…），无法仅由公钥唯一确定，使用 trait 默认 UNSUPPORTED。
}

/// 解析交易定位符 `<hash>:<lt>@<address>`。
fn parse_tx_locator(raw: &str) -> Result<(String, String, String), SdkError> {
    let (left, address) = raw.trim().split_once('@').ok_or_else(|| {
        SdkError::invalid_argument(
            "TON 交易引用格式应为 <tx_hash>:<lt>@<address>（地址用于定位账户交易列表）",
        )
    })?;
    let (tx_hash, lt) = left
        .split_once(':')
        .ok_or_else(|| SdkError::invalid_argument("TON 交易引用缺少 :<lt> 部分"))?;
    if tx_hash.is_empty() || lt.is_empty() || address.is_empty() {
        return Err(SdkError::invalid_argument("TON 交易引用存在空字段"));
    }
    validate_address(address)?;
    Ok((tx_hash.to_string(), lt.to_string(), address.to_string()))
}

/// 宽松校验 TON 地址：raw 形式 `wc:64hex` 或用户友好形式（base64url，约 48 字符）。
fn validate_address(raw: &str) -> Result<(), SdkError> {
    let t = raw.trim();
    if let Some((wc, hex_part)) = t.split_once(':') {
        let workchain: i32 = wc
            .parse()
            .map_err(|_| SdkError::invalid_argument(format!("非法 workchain: {wc}")))?;
        if !(-128..=127).contains(&workchain) {
            return Err(SdkError::invalid_argument(format!(
                "workchain 越界: {workchain}"
            )));
        }
        if hex_part.len() != 64 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SdkError::invalid_argument(format!(
                "raw 地址账户哈希需为 64 位十六进制: {t}"
            )));
        }
        return Ok(());
    }
    // 用户友好地址：base64/base64url，44~48 字符。
    let ok_len = (44..=48).contains(&t.len());
    let ok_charset = t
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'+' | b'/' | b'='));
    if !ok_len || !ok_charset {
        return Err(SdkError::invalid_argument(format!(
            "非法 TON 地址: {t}（应为 wc:hex 或 EQ/UQ 开头的用户友好地址）"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tx_locator() {
        let (h, lt, addr) = parse_tx_locator(
            "01KYvC3KxWaVwycwdrlAGB8fSiyY183v9DNRATm5Rww=:63489315000007@EQAvDfWFG0oYX19jwNDNBBL1rKNT9XfaGP9HyTb5nb2Eml6y",
        )
        .unwrap();
        assert_eq!(h, "01KYvC3KxWaVwycwdrlAGB8fSiyY183v9DNRATm5Rww=");
        assert_eq!(lt, "63489315000007");
        assert!(addr.starts_with("EQ"));
        assert!(parse_tx_locator("onlyhash").is_err());
        assert!(parse_tx_locator("h:1@no-at").is_err());
    }

    #[test]
    fn validates_raw_and_friendly_addresses() {
        assert!(
            validate_address("-1:3333333333333333333333333333333333333333333333333333333333333333")
                .is_ok()
        );
        assert!(validate_address("EQAvDfWFG0oYX19jwNDNBBL1rKNT9XfaGP9HyTb5nb2Eml6y").is_ok());
        assert!(validate_address("0:short").is_err());
        assert!(validate_address("bad address").is_err());
        assert!(
            validate_address(
                "999:3333333333333333333333333333333333333333333333333333333333333333"
            )
            .is_err()
        );
    }
}
