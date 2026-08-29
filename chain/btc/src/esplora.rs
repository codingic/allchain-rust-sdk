//! Esplora（mempool.space / blockstream）REST 客户端：地址、UTXO、交易、区块、费率与广播。

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const USER_AGENT: &str = concat!("btc-rpc-cli/", env!("CARGO_PKG_VERSION"));
const TIMEOUT: Duration = Duration::from_secs(25);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct Esplora {
    base: String,
    http: reqwest::Client,
}

impl Esplora {
    pub fn new(base: &str) -> Result<Self> {
        let base = base.trim_end_matches('/').to_string();
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .context("构造 HTTP 客户端失败")?;
        Ok(Self { base, http })
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    async fn get_text(&self, path: &str) -> Result<String> {
        let url = format!("{}{}", self.base, path);
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("请求 {url} 失败"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .with_context(|| format!("读取 {url} 响应失败"))?;
        if !status.is_success() {
            bail!("{url} 返回 {status}: {}", body.trim());
        }
        Ok(body.trim().to_string())
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base, path);
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("请求 {url} 失败"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .with_context(|| format!("读取 {url} 响应失败"))?;
        if !status.is_success() {
            bail!("{url} 返回 {status}: {}", body.trim());
        }
        serde_json::from_str(&body).with_context(|| format!("解析 {url} 响应失败"))
    }

    /// 链尖高度。
    pub async fn tip_height(&self) -> Result<u64> {
        let text = self.get_text("/blocks/tip/height").await?;
        text.parse()
            .with_context(|| format!("链尖高度不是数字: {text}"))
    }

    /// 链尖区块哈希。
    pub async fn tip_hash(&self) -> Result<String> {
        self.get_text("/blocks/tip/hash").await
    }

    /// 指定高度对应的区块哈希。
    pub async fn block_hash_at(&self, height: u64) -> Result<String> {
        self.get_text(&format!("/block-height/{height}")).await
    }

    pub async fn block(&self, hash: &str) -> Result<Block> {
        self.get_json(&format!("/block/{hash}")).await
    }

    pub async fn tx(&self, txid: &str) -> Result<Tx> {
        self.get_json(&format!("/tx/{txid}")).await
    }

    pub async fn tx_hex(&self, txid: &str) -> Result<String> {
        self.get_text(&format!("/tx/{txid}/hex")).await
    }

    pub async fn address(&self, address: &str) -> Result<AddressStats> {
        self.get_json(&format!("/address/{address}")).await
    }

    pub async fn utxos(&self, address: &str) -> Result<Vec<Utxo>> {
        self.get_json(&format!("/address/{address}/utxo")).await
    }

    /// 费率估计：优先 Esplora 的 `/fee-estimates`（确认目标 -> sat/vB），
    /// 失败时回退到 mempool.space 的 `/v1/fees/recommended`。
    pub async fn fee_estimates(&self) -> Result<Vec<(u16, f64)>> {
        if let Ok(map) = self
            .get_json::<HashMap<String, f64>>("/fee-estimates")
            .await
        {
            let mut parsed: Vec<(u16, f64)> = map
                .iter()
                .filter_map(|(target, rate)| target.parse::<u16>().ok().map(|t| (t, *rate)))
                .collect();
            if !parsed.is_empty() {
                parsed.sort_unstable_by_key(|(target, _)| *target);
                return Ok(parsed);
            }
        }

        let recommended: RecommendedFees = self.get_json("/v1/fees/recommended").await?;
        let mut parsed = vec![
            (1u16, recommended.fastest_fee),
            (3, recommended.half_hour_fee),
            (6, recommended.hour_fee),
            (12, recommended.economy_fee),
            (144, recommended.minimum_fee),
        ];
        parsed.sort_unstable_by_key(|(target, _)| *target);
        Ok(parsed)
    }

    /// 广播原始交易（text/plain 提交 hex），返回 txid。
    pub async fn broadcast(&self, raw_hex: &str) -> Result<String> {
        let url = format!("{}/tx", self.base);
        let response = self
            .http
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(raw_hex.to_string())
            .send()
            .await
            .with_context(|| format!("请求 {url} 失败"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .with_context(|| format!("读取 {url} 响应失败"))?;
        if !status.is_success() {
            bail!("广播失败（HTTP {status}）: {}", body.trim());
        }
        Ok(body.trim().to_string())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Stats {
    #[serde(default)]
    pub funded_txo_count: u64,
    #[serde(default)]
    pub funded_txo_sum: u64,
    #[serde(default)]
    pub spent_txo_count: u64,
    #[serde(default)]
    pub spent_txo_sum: u64,
    #[serde(default)]
    pub tx_count: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddressStats {
    pub address: String,
    pub chain_stats: Stats,
    pub mempool_stats: Stats,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UtxoStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u64>,
    #[serde(default)]
    pub block_time: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: UtxoStatus,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TxStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u64>,
    #[serde(default)]
    pub block_hash: Option<String>,
    #[serde(default)]
    pub block_time: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Prevout {
    #[serde(default)]
    pub scriptpubkey_address: Option<String>,
    #[serde(default)]
    pub scriptpubkey_type: Option<String>,
    pub value: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Vin {
    pub txid: String,
    pub vout: u32,
    #[serde(default)]
    pub is_coinbase: Option<bool>,
    #[serde(default)]
    pub prevout: Option<Prevout>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Vout {
    #[serde(default)]
    pub scriptpubkey_address: Option<String>,
    #[serde(default)]
    pub scriptpubkey_type: Option<String>,
    pub value: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tx {
    pub txid: String,
    pub version: i32,
    pub locktime: u32,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub weight: Option<u64>,
    #[serde(default)]
    pub fee: Option<u64>,
    #[serde(default)]
    pub vin: Vec<Vin>,
    #[serde(default)]
    pub vout: Vec<Vout>,
    pub status: TxStatus,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Block {
    pub id: String,
    pub height: u64,
    pub timestamp: u64,
    pub tx_count: u64,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub weight: Option<u64>,
    #[serde(default)]
    pub merkle_root: Option<String>,
    #[serde(default)]
    pub previousblockhash: Option<String>,
    #[serde(default)]
    pub median_time: Option<u64>,
    #[serde(default)]
    pub nonce: Option<u64>,
    #[serde(default)]
    pub bits: Option<u64>,
    #[serde(default)]
    pub difficulty: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedFees {
    pub fastest_fee: f64,
    pub half_hour_fee: f64,
    pub hour_fee: f64,
    pub economy_fee: f64,
    pub minimum_fee: f64,
}
