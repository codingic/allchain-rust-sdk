//! 跨链统一数据模型。
//!
//! 设计取舍：
//! - 顶层字段是四链公共子集，**字段名在所有链上保持稳定**，链间无对应值的字段为 `null`，
//!   这样调用方可以按固定 schema 解析，不必按链分支。
//! - 链专有字段一律塞进 `extra`，并通过 `#[serde(flatten)]` 平铺到同一层级，
//!   既不破坏公共 schema，也不丢失各链特有信息。
//! - 金额同时提供 `*_raw`（最小单位整数字符串）与 `*_ui`（人类可读十进制），
//!   用字符串而非 f64 承载大整数，避免 JSON 精度丢失。

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::ChainKind;

/// 空 extra：序列化时 flatten 后不产生任何额外键。
pub fn no_extra() -> Value {
    Value::Object(Map::new())
}

/// 由若干键值对构造 extra。
#[macro_export]
macro_rules! extra {
    { $($k:expr => $v:expr),* $(,)? } => {{
        let mut map = ::serde_json::Map::new();
        $( map.insert($k.to_string(), ::serde_json::json!($v)); )*
        ::serde_json::Value::Object(map)
    }};
}

/// 节点与链状态。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusView {
    pub chain: ChainKind,
    pub network: String,
    pub rpc_url: String,
    pub latest_height: Option<u64>,
    pub latest_hash: Option<String>,
    pub node_version: Option<String>,
    #[serde(flatten)]
    pub extra: Value,
}

impl StatusView {
    pub fn new(chain: ChainKind, network: impl Into<String>, rpc_url: impl Into<String>) -> Self {
        Self {
            chain,
            network: network.into(),
            rpc_url: rpc_url.into(),
            latest_height: None,
            latest_hash: None,
            node_version: None,
            extra: no_extra(),
        }
    }

    pub fn with_height(mut self, height: u64) -> Self {
        self.latest_height = Some(height);
        self
    }

    pub fn with_hash(mut self, hash: impl Into<String>) -> Self {
        self.latest_hash = Some(hash.into());
        self
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.node_version = Some(version.into());
        self
    }

    pub fn with_extra(mut self, extra: Value) -> Self {
        self.extra = extra;
        self
    }
}

/// 账户/地址余额。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceView {
    pub chain: ChainKind,
    pub network: String,
    pub address: String,
    /// 最小单位整数（wei / satoshi / lamport / yoctoNEAR），字符串形式防精度丢失。
    pub balance_raw: String,
    /// 人类可读金额，按 `decimals` 换算。
    pub balance_ui: String,
    pub symbol: String,
    pub decimals: u8,
    #[serde(flatten)]
    pub extra: Value,
}

impl BalanceView {
    pub fn new(
        chain: ChainKind,
        network: impl Into<String>,
        address: impl Into<String>,
        raw: u128,
    ) -> Self {
        Self {
            chain,
            network: network.into(),
            address: address.into(),
            balance_raw: raw.to_string(),
            balance_ui: crate::chain::format_units(raw, chain.decimals()),
            symbol: chain.symbol().to_string(),
            decimals: chain.decimals(),
            extra: no_extra(),
        }
    }

    pub fn with_extra(mut self, extra: Value) -> Self {
        self.extra = extra;
        self
    }
}

/// 区块概览。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockView {
    pub chain: ChainKind,
    pub network: String,
    pub height: Option<u64>,
    pub hash: String,
    pub parent_hash: Option<String>,
    /// Unix 秒级时间戳。
    pub timestamp: Option<i64>,
    pub tx_count: Option<u64>,
    #[serde(flatten)]
    pub extra: Value,
}

impl BlockView {
    pub fn new(chain: ChainKind, network: impl Into<String>, hash: impl Into<String>) -> Self {
        Self {
            chain,
            network: network.into(),
            height: None,
            hash: hash.into(),
            parent_hash: None,
            timestamp: None,
            tx_count: None,
            extra: no_extra(),
        }
    }

    pub fn with_height(mut self, height: u64) -> Self {
        self.height = Some(height);
        self
    }

    pub fn with_parent(mut self, parent: impl Into<String>) -> Self {
        self.parent_hash = Some(parent.into());
        self
    }

    pub fn with_timestamp(mut self, ts: i64) -> Self {
        self.timestamp = Some(ts);
        self
    }

    pub fn with_tx_count(mut self, count: u64) -> Self {
        self.tx_count = Some(count);
        self
    }

    pub fn with_extra(mut self, extra: Value) -> Self {
        self.extra = extra;
        self
    }
}

/// 由公钥派生的地址。
///
/// 这是一次**纯本地计算**，不访问网络；但 `network` 仍然有意义——
/// BTC 的地址编码（bech32 hrp、base58 版本字节）随网络而变。
///
/// `pubkey` 是规范化后的输入，`address` 是该链上的主地址；同一公钥在 BTC 上
/// 还能派生出其它脚本类型的地址，统一放在 `extra` 里。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressView {
    pub chain: ChainKind,
    pub network: String,
    /// 规范化后的输入公钥（各链自己的表示法）。
    pub pubkey: String,
    /// 主地址：ETH 为 EIP-55 校验和地址，BTC 为 P2WPKH，SOL 为 base58，
    /// NEAR 为隐式账户（十六进制）。
    pub address: String,
    /// 主地址类型：`eoa` / `p2wpkh` / `ed25519` / `implicit`。
    pub address_type: String,
    /// 公钥字节长度，便于调用方核对输入是否被正确解析。
    pub pubkey_bytes: usize,
    #[serde(flatten)]
    pub extra: Value,
}

impl AddressView {
    pub fn new(
        chain: ChainKind,
        network: impl Into<String>,
        pubkey: impl Into<String>,
        address: impl Into<String>,
        address_type: impl Into<String>,
        pubkey_bytes: usize,
    ) -> Self {
        Self {
            chain,
            network: network.into(),
            pubkey: pubkey.into(),
            address: address.into(),
            address_type: address_type.into(),
            pubkey_bytes,
            extra: no_extra(),
        }
    }

    /// 合并一组链专有字段；已存在的同名键会被覆盖。
    pub fn with_extra(mut self, extra: Value) -> Self {
        merge_extra(&mut self.extra, extra);
        self
    }

    /// 该公钥在其它脚本类型 / 表示形式下的地址，BTC 等多地址链才有。
    ///
    /// 与 [`Self::with_extra`] 一样是合并语义，两者调用顺序不影响结果。
    pub fn with_alternatives(mut self, alternatives: Value) -> Self {
        merge_extra(&mut self.extra, json!({ "alternatives": alternatives }));
        self
    }
}

/// 把 `patch` 中的键并入 `base`；两者都必须是 JSON 对象，否则以 `patch` 为准。
fn merge_extra(base: &mut Value, patch: Value) {
    match (base.as_object_mut(), patch.as_object()) {
        (Some(base), Some(patch)) => {
            for (key, value) in patch {
                base.insert(key.clone(), value.clone());
            }
        }
        _ => *base = patch,
    }
}

/// 交易执行结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxStatus {
    Success,
    Failed,
    Pending,
    Unknown,
}

/// 交易详情。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxView {
    pub chain: ChainKind,
    pub network: String,
    pub hash: String,
    pub status: TxStatus,
    pub from: Option<String>,
    pub to: Option<String>,
    /// 转账金额（最小单位整数字符串）；多输入输出或合约调用时可能为 null。
    pub amount_raw: Option<String>,
    pub amount_ui: Option<String>,
    /// 手续费（最小单位整数字符串）。
    pub fee_raw: Option<String>,
    pub height: Option<u64>,
    pub timestamp: Option<i64>,
    pub confirmations: Option<u64>,
    #[serde(flatten)]
    pub extra: Value,
}

impl TxView {
    pub fn new(
        chain: ChainKind,
        network: impl Into<String>,
        hash: impl Into<String>,
        status: TxStatus,
    ) -> Self {
        Self {
            chain,
            network: network.into(),
            hash: hash.into(),
            status,
            from: None,
            to: None,
            amount_raw: None,
            amount_ui: None,
            fee_raw: None,
            height: None,
            timestamp: None,
            confirmations: None,
            extra: no_extra(),
        }
    }

    /// 同时设置原始金额与可读金额。
    pub fn with_amount(mut self, raw: u128) -> Self {
        self.amount_raw = Some(raw.to_string());
        self.amount_ui = Some(crate::chain::format_units(raw, self.chain.decimals()));
        self
    }

    pub fn with_fee(mut self, raw: u128) -> Self {
        self.fee_raw = Some(raw.to_string());
        self
    }

    pub fn with_from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    pub fn with_to(mut self, to: impl Into<String>) -> Self {
        self.to = Some(to.into());
        self
    }

    pub fn with_height(mut self, height: u64) -> Self {
        self.height = Some(height);
        self
    }

    pub fn with_timestamp(mut self, ts: i64) -> Self {
        self.timestamp = Some(ts);
        self
    }

    pub fn with_confirmations(mut self, confirmations: u64) -> Self {
        self.confirmations = Some(confirmations);
        self
    }

    pub fn with_extra(mut self, extra: Value) -> Self {
        self.extra = extra;
        self
    }
}

/// 统一转账请求（跨链）。
///
/// 各链执行时自行解析地址与金额，因此这里只保留顶层公共语义：
/// - `amount` 是人类可读的原生单位金额（如 `0.01`）；
/// - `private_key` 的格式随链而异（ETH 十六进制 / BTC WIF / SOL JSON 数组或 base58 /
///   NEAR `ed25519:...`），由各链适配器解析；
/// - `dry_run` 为 `true` 时只本地构造并签名，不广播；
/// - `from` 仅 NEAR 需要（命名账户），其余链自动从私钥派生并忽略该字段。
#[derive(Debug, Clone)]
pub struct TransferRequest {
    pub to: String,
    pub amount: String,
    pub private_key: String,
    pub dry_run: bool,
    pub from: Option<String>,
}

impl TransferRequest {
    pub fn new(
        to: impl Into<String>,
        amount: impl Into<String>,
        private_key: impl Into<String>,
    ) -> Self {
        Self {
            to: to.into(),
            amount: amount.into(),
            private_key: private_key.into(),
            dry_run: false,
            from: None,
        }
    }
}

/// 转账执行结果。
///
/// `broadcast` 为 `false` 表示 dry-run：交易已在本地构造并签名（`tx_hash` 为
/// 这笔已签名交易应有的哈希），但未广播。链专有信息（signed_raw / fee / fee_rate /
/// nonce / confirmations 等）统一放进 `extra`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferView {
    pub chain: ChainKind,
    pub network: String,
    /// 付款地址/账户；NEAR 取名为 `signer account`。
    pub from: Option<String>,
    pub to: String,
    /// 最小单位整数字符串（wei / satoshi / lamport / yoctoNEAR）。
    pub amount_raw: String,
    /// 人类可读金额，按 `decimals` 换算。
    pub amount_ui: String,
    pub symbol: String,
    /// 交易哈希 / txid / signature；dry-run 下为本地签名产生的预期哈希。
    pub tx_hash: Option<String>,
    /// 是否已广播到链上。
    pub broadcast: bool,
    #[serde(flatten)]
    pub extra: Value,
}

impl TransferView {
    pub fn new(
        chain: ChainKind,
        network: impl Into<String>,
        from: Option<String>,
        to: impl Into<String>,
        amount_raw: u128,
        tx_hash: Option<String>,
        broadcast: bool,
    ) -> Self {
        Self {
            chain,
            network: network.into(),
            from,
            to: to.into(),
            amount_raw: amount_raw.to_string(),
            amount_ui: crate::chain::format_units(amount_raw, chain.decimals()),
            symbol: chain.symbol().to_string(),
            tx_hash,
            broadcast,
            extra: no_extra(),
        }
    }

    pub fn with_extra(mut self, extra: Value) -> Self {
        self.extra = extra;
        self
    }
}

/// 便捷构造：把若干字段放进 extra。
pub fn extra_of(pairs: &[(&str, Value)]) -> Value {
    let mut map = Map::new();
    for (k, v) in pairs {
        map.insert((*k).to_string(), v.clone());
    }
    Value::Object(map)
}

/// 生成空 JSON 对象，供适配器初始化 extra。
pub fn empty_extra() -> Value {
    json!({})
}
