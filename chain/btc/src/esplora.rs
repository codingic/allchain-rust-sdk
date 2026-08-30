//! Esplora（mempool.space / blockstream）REST 客户端：地址、UTXO、交易、区块、费率与广播。
//!
//! 为什么需要它：**bitcoind 全节点不索引地址**。
//! 想回答「某地址有多少余额 / 有哪些 UTXO」必须靠外部索引器。
//! Esplora 是 mempool.space 与 blockstream.info 共同实现的一套 REST 接口，
//! 事实上的行业标准，本文件是它的最小客户端。

// `HashMap`：这里只用来承接 `/fee-estimates` 返回的「确认目标 → 费率」映射。
use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
// 只导入 `Deserialize`：**这些结构体只用于读入上游响应，从不写出**，
// 少派生一个 trait 就少一份生成代码，也避免误把响应体当请求体发出去。
use serde::Deserialize;

/// 自定义 User-Agent，便于对方服务端识别流量来源。
///
/// 语法说明：`concat!` 在**编译期**拼接字符串字面量，`env!("CARGO_PKG_VERSION")`
/// 则把 Cargo.toml 里的版本号在编译期读进来。两者都是编译期行为，零运行期开销。
const USER_AGENT: &str = concat!("btc-rpc-cli/", env!("CARGO_PKG_VERSION"));
/// 单次请求的**整体**超时。费率接口偶发较慢，给得宽一些。
const TIMEOUT: Duration = Duration::from_secs(25);
/// 建连超时：连不上快速失败，不必等满整体超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Esplora 客户端。
///
/// 语法说明：`#[derive(Clone)]` 只派生了 `Clone`——`reqwest::Client` 内部用
/// `Arc` 持有连接池，`clone()` 只是**共享同一个连接池**而非新建连接，
/// 这是 reqwest 官方推荐的做法。
#[derive(Clone)]
pub struct Esplora {
    /// 索引器基址（形如 `https://mempool.space/api`），末尾不带 `/`。
    base: String,
    /// 复用的 HTTP 客户端。
    http: reqwest::Client,
}

impl Esplora {
    /// 构造客户端。`base` 末尾的斜杠会被去掉，便于后面直接拼接路径。
    pub fn new(base: &str) -> Result<Self> {
        // `trim_end_matches('/')` 去掉**所有**尾部斜杠（`trim_end_matches` 是重复匹配，
        // 与只去一个的 `strip_suffix` 不同），再转成自有 String。
        let base = base.trim_end_matches('/').to_string();
        // reqwest 的 builder 模式：链式配置后 `build()`。
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .context("构造 HTTP 客户端失败")?;
        Ok(Self { base, http })
    }

    /// 索引器基址。
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// GET 一个返回**纯文本**的接口（如链尖高度、原始交易 hex）。
    ///
    /// 注意这里先取状态码、再读 body、最后判成功：
    /// 顺序不能反——出错时响应体里往往带着可读的失败原因，
    /// 先读出来才能把它放进错误信息。
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
            // 把上游的状态码与响应体原样回显，排查索引器问题时极有用。
            bail!("{url} 返回 {status}: {}", body.trim());
        }
        // `.trim()` 去掉可能的换行；Esplora 的纯文本接口常带尾随换行。
        Ok(body.trim().to_string())
    }

    /// GET 一个返回 **JSON** 的接口。
    ///
    /// 语法说明：`<T: serde::de::DeserializeOwned>` 是泛型约束。
    /// 用 `DeserializeOwned` 而不是 `Deserialize<'de>`，是因为结果来自
    /// 运行期构造的 `String`——它活不过本函数，所以 T **不能借用**输入数据，
    /// 必须是「自持有」的可反序列化类型。
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

    /// 链尖高度。Esplora 的 `/blocks/tip/height` 直接返回十进制数字文本。
    pub async fn tip_height(&self) -> Result<u64> {
        let text = self.get_text("/blocks/tip/height").await?;
        text.parse()
            .with_context(|| format!("链尖高度不是数字: {text}"))
    }

    /// 链尖区块哈希。
    pub async fn tip_hash(&self) -> Result<String> {
        self.get_text("/blocks/tip/hash").await
    }

    /// 指定高度对应的区块哈希（需要索引器支持高度反查）。
    pub async fn block_hash_at(&self, height: u64) -> Result<String> {
        self.get_text(&format!("/block-height/{height}")).await
    }

    /// 区块详情。
    pub async fn block(&self, hash: &str) -> Result<Block> {
        self.get_json(&format!("/block/{hash}")).await
    }

    /// 交易详情。
    pub async fn tx(&self, txid: &str) -> Result<Tx> {
        self.get_json(&format!("/tx/{txid}")).await
    }

    /// 原始交易 hex（序列化后的完整交易字节）。
    pub async fn tx_hex(&self, txid: &str) -> Result<String> {
        self.get_text(&format!("/tx/{txid}/hex")).await
    }

    /// 地址统计（已确认 + 内存池两组收发汇总）。
    pub async fn address(&self, address: &str) -> Result<AddressStats> {
        self.get_json(&format!("/address/{address}")).await
    }

    /// 地址的未花费输出列表。**选币的输入来源**。
    pub async fn utxos(&self, address: &str) -> Result<Vec<Utxo>> {
        self.get_json(&format!("/address/{address}/utxo")).await
    }

    /// 费率估计：优先 Esplora 的 `/fee-estimates`（确认目标 -> sat/vB），
    /// 失败时回退到 mempool.space 的 `/v1/fees/recommended`。
    ///
    /// 两级回退的原因：`/fee-estimates` 不是所有 Esplora 实现都提供（属扩展接口），
    /// 而 `/v1/fees/recommended` 是 mempool.space 的私有接口，也不是人人都有。
    /// 两条都试过再放弃，能覆盖绝大多数公共索引器。
    pub async fn fee_estimates(&self) -> Result<Vec<(u16, f64)>> {
        if let Ok(map) = self
            .get_json::<HashMap<String, f64>>("/fee-estimates")
            .await
        {
            let mut parsed: Vec<(u16, f64)> = map
                .iter()
                // `filter_map` = `filter` + `map`：闭包返回 `Option`，
                // 为 `None` 的项被直接丢掉。这里用它跳过解析失败的键。
                .filter_map(|(target, rate)| target.parse::<u16>().ok().map(|t| (t, *rate)))
                .collect();
            if !parsed.is_empty() {
                // `sort_unstable_by_key` 比 `sort_by_key` 快（不保证相等元素的相对顺序），
                // 这里元素无顺序语义，用它即可。
                parsed.sort_unstable_by_key(|(target, _)| *target);
                return Ok(parsed);
            }
        }

        // 回退：mempool.space 只给「最快 / 半小时 / 一小时 / 经济 / 最低」五档，
        // 这里手动把每档映射成一个代表性的确认目标区块数。
        let recommended: RecommendedFees = self.get_json("/v1/fees/recommended").await?;
        // `vec![..]` 宏构造 Vec；首项标了 `1u16` 以固定元素类型，
        // 后续项靠类型推断自动对齐。
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
    ///
    /// 领域说明：Esplora 的 `POST /tx` 要求 **body 就是 hex 字符串**，
    /// Content-Type 为 `text/plain`——不是 JSON。这与 `sendrawtransaction`
    /// 的 JSON-RPC 封装形式不同，是最容易写错的地方。
    pub async fn broadcast(&self, raw_hex: &str) -> Result<String> {
        let url = format!("{}/tx", self.base);
        let response = self
            .http
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            // `.body(..)` 需要**自有**数据，故 `to_string()` 复制一份。
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
            // 常见失败原因：`bad-txns-inputs-missingorspent`（UTXO 已被花）、
            // `txn-already-in-mempool`、`min relay fee not met`。原样透出便于定位。
            bail!("广播失败（HTTP {status}）: {}", body.trim());
        }
        // 成功时响应体就是 txid。
        Ok(body.trim().to_string())
    }
}

/// 一组统计（已确认 / 内存池各一份）。
///
/// 语法说明：`#[serde(default)]` 表示「该字段缺失时用 `Default` 值填补」。
/// Esplora 各实现返回的字段并不完全一致，这个属性让反序列化对缺失字段**宽容**。
#[derive(Debug, Clone, Deserialize)]
pub struct Stats {
    /// 曾给该地址产生过输出的 UTXO 数量。
    #[serde(default)]
    pub funded_txo_count: u64,
    /// 这些 UTXO 的金额总和（satoshi）。
    #[serde(default)]
    pub funded_txo_sum: u64,
    /// 已被花掉的 UTXO 数量。
    #[serde(default)]
    pub spent_txo_count: u64,
    /// 已花掉的金额总和（satoshi）。
    #[serde(default)]
    pub spent_txo_sum: u64,
    /// 涉及该地址的交易数。
    #[serde(default)]
    pub tx_count: u64,
}

/// `/address/{address}` 的响应：已确认与内存池两组统计。
///
/// 领域说明：**余额并没有单独的字段**，而要由
/// `funded_txo_sum - spent_txo_sum` 算出——这是 UTXO 账本的自然结果。
#[derive(Debug, Clone, Deserialize)]
pub struct AddressStats {
    pub address: String,
    pub chain_stats: Stats,
    pub mempool_stats: Stats,
}

/// UTXO 的确认状态。
#[derive(Debug, Clone, Deserialize)]
pub struct UtxoStatus {
    /// 是否已入块。false 表示还在内存池（可能是你刚收到的、或待确认的找零）。
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u64>,
    #[serde(default)]
    pub block_time: Option<u64>,
}

/// 一个未花费输出。
///
/// 领域说明：`txid` + `vout`（输出序号）合起来才是 UTXO 的**唯一标识**，
/// 花费时必须两个都对上——这就是 `OutPoint` 的含义。
#[derive(Debug, Clone, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    /// 金额（satoshi）。
    pub value: u64,
    pub status: UtxoStatus,
}

/// 交易的确认状态。
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

/// 输入所引用的**上一笔输出**（prevout）。
///
/// 领域说明：比特币交易的输入只写「引用哪个 UTXO」，**不写金额**；
/// 金额要回溯上一笔交易才知道。Esplora 贴心地把 prevout 一并展开，
/// 省掉我们自己去追。
#[derive(Debug, Clone, Deserialize)]
pub struct Prevout {
    #[serde(default)]
    pub scriptpubkey_address: Option<String>,
    #[serde(default)]
    pub scriptpubkey_type: Option<String>,
    pub value: u64,
}

/// 交易输入。**coinbase 输入没有 txid / prevout**（它是凭空新造的币）。
#[derive(Debug, Clone, Deserialize)]
pub struct Vin {
    pub txid: String,
    pub vout: u32,
    #[serde(default)]
    pub is_coinbase: Option<bool>,
    #[serde(default)]
    pub prevout: Option<Prevout>,
}

/// 交易输出。注意**没有 index 字段**——顺序即索引，由调用方用 `enumerate()` 补上。
#[derive(Debug, Clone, Deserialize)]
pub struct Vout {
    #[serde(default)]
    pub scriptpubkey_address: Option<String>,
    #[serde(default)]
    pub scriptpubkey_type: Option<String>,
    /// 金额（satoshi）。
    pub value: u64,
}

/// 交易详情。
#[derive(Debug, Clone, Deserialize)]
pub struct Tx {
    pub txid: String,
    /// 交易版本号；v2 表示支持相对时间锁（BIP68）。
    pub version: i32,
    /// 时间锁：为 0 表示立即可入块。
    pub locktime: u32,
    #[serde(default)]
    pub size: Option<u64>,
    /// 权重（WU）。vsize 可由 `weight / 4` 上取整得到。
    #[serde(default)]
    pub weight: Option<u64>,
    /// 手续费（satoshi），由索引器根据输入输出差额算出。
    #[serde(default)]
    pub fee: Option<u64>,
    #[serde(default)]
    pub vin: Vec<Vin>,
    #[serde(default)]
    pub vout: Vec<Vout>,
    pub status: TxStatus,
}

/// 区块详情。
#[derive(Debug, Clone, Deserialize)]
pub struct Block {
    /// 区块哈希（注意字段名是 `id` 而非 `hash`，与 Esplora 接口一致）。
    pub id: String,
    pub height: u64,
    /// 出块时间（Unix 秒）。
    pub timestamp: u64,
    pub tx_count: u64,
    /// 序列化字节数。
    #[serde(default)]
    pub size: Option<u64>,
    /// 权重（WU）。
    #[serde(default)]
    pub weight: Option<u64>,
    #[serde(default)]
    pub merkle_root: Option<String>,
    /// 父区块哈希；创世块没有。
    #[serde(default)]
    pub previousblockhash: Option<String>,
    #[serde(default)]
    pub median_time: Option<u64>,
    #[serde(default)]
    pub nonce: Option<u64>,
    /// 难度目标位的紧凑表示。
    #[serde(default)]
    pub bits: Option<u64>,
    #[serde(default)]
    pub difficulty: Option<f64>,
}

/// mempool.space 的推荐费率（`GET /v1/fees/recommended`）。
///
/// 语法说明：`#[serde(rename_all = "camelCase")]` 把 Rust 的 snake_case 字段名
/// 自动映射成 JSON 里的 camelCase（如 `fastestFee`），
/// 这样就不必给每个字段手写 `#[serde(rename = "..")]`。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedFees {
    /// 最快档（约下一个块）。
    pub fastest_fee: f64,
    /// 约 30 分钟（3 个块）。
    pub half_hour_fee: f64,
    /// 约 1 小时（6 个块）。
    pub hour_fee: f64,
    /// 经济档（约 12 个块）。
    pub economy_fee: f64,
    /// 最低可转发档（约 144 个块，一天）。
    pub minimum_fee: f64,
}
