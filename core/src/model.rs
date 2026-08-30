//! 跨链统一数据模型。
//!
//! 设计取舍：
//! - 顶层字段是四链公共子集，**字段名在所有链上保持稳定**，链间无对应值的字段为 `null`，
//!   这样调用方可以按固定 schema 解析，不必按链分支。
//! - 链专有字段一律塞进 `extra`，并通过 `#[serde(flatten)]` 平铺到同一层级，
//!   既不破坏公共 schema，也不丢失各链特有信息。
//! - 金额同时提供 `*_raw`（最小单位整数字符串）与 `*_ui`（人类可读十进制），
//!   用字符串而非 f64 承载大整数，避免 JSON 精度丢失。
//!
//! 补充：所有 View 结构都刻意**不**实现 `Default`，而是提供 `new(..)` + 一串
//! `with_xxx` 构造器。这样「哪些字段是必填的」由 `new` 的参数列表固定下来，
//! 可选字段则通过链式方法补齐，避免了 `Default` 那种「漏填字段也能编译过」的隐患。

// `Serialize` / `Deserialize` 派生：模型既要输出给调用方，也要能从 HTTP 响应还原。
use serde::{Deserialize, Serialize};
// `Map` 是 serde_json 的对象类型（底层是 `BTreeMap`/`IndexMap`，取决于 feature）；
// `Value` 是任意 JSON 值；`json!` 是用字面量语法构造 `Value` 的宏。
use serde_json::{Map, Value, json};

use crate::ChainKind;

/// 空 extra：序列化时 flatten 后不产生任何额外键。
///
/// 为什么需要它：`#[serde(flatten)]` 的字段必须是个 **map 型**的值。
/// 如果塞 `Value::Null`，序列化会直接报错；塞空对象则是安全的空集。
/// 所以所有 `new(..)` 都用它做 `extra` 的初值。
pub fn no_extra() -> Value {
    // `Map::new()` 造一个空对象，再用 `Value::Object(..)` 包成 JSON 值。
    Value::Object(Map::new())
}

/// 由若干键值对构造 extra。
///
/// 用法：`extra!{ "confirmations" => 6, "fee_rate" => 12 }`。
///
/// 语法说明：这是 `macro_rules!`（声明式宏），在**编译期**做文本替换，
/// 与 `format!` 那种「调用库函数」的宏不是一回事。逐段拆开：
/// - `{ ... }` 是宏的匹配臂，用大括号而非小括号只是风格（三种括号都能配 macros_rules）；
/// - `$k` / `$v` 是**元变量**，捕获调用处的一段语法；
/// - `:expr` 是片段类型（fragment specifier），表示「这里必须是表达式」；
/// - `$( ... ),*` 表示「重复零次或多次，中间用逗号分隔」；
/// - `$(,)?` 表示「末尾允许一个可选逗号」，于是 `extra!{a=>1,}` 也能编译；
/// - 展开体最外层的 `{{ }}` 是转义：外层一对属于宏语法，内层 `{}` 才是生成出来的块表达式。
#[macro_export]
// `#[macro_export]` 把宏提升到 **crate 根**：即使它定义在 `model` 模块里，
// 外部也能通过 `allchain_core::extra!` 使用。这是 Rust 2018 里宏与类型
// 在可见性规则上的一个重要区别——宏不走普通的 `pub` 路径系统。
macro_rules! extra {
    { $($k:expr => $v:expr),* $(,)? } => {{
        // `let mut map` 只存在于宏展开后的作用域里，不会污染调用方的变量名。
        let mut map = ::serde_json::Map::new();
        // `$( ... )*` 把这段插入语句按捕获到的组数**原样重复展开**。
        // `::serde_json` 开头的 `::` 表示「从外部 crate 根开始找」，
        // 保证即使用调用方本地也有个叫 `serde_json` 的模块也不会找错。
        $( map.insert($k.to_string(), ::serde_json::json!($v)); )*
        ::serde_json::Value::Object(map)
    }};
}

/// 节点与链状态。
///
/// 语法说明：`#[derive(Deserialize)]` 让调用方可以把 SDK 输出的结构原样反序列化回来
/// （HTTP 客户端、测试快照都依赖这一点）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusView {
    /// 所属链。每个 View 都自带 `chain` / `network`，是为了让单条响应**自解释**：
    /// 调用方拿到一段 JSON 就能判断它属于哪条链哪个网络，不必依赖外层上下文
    /// （批量查询、日志归档、消息队列转发都依赖这一点）。
    pub chain: ChainKind,
    /// 网络名，与 [`crate::traits::ChainClient::network`] 的返回值一致。
    pub network: String,
    /// 实际连的 RPC 地址，回显给调用方便于确认「打的是不是预期节点」。
    pub rpc_url: String,
    /// 最新高度。取不到（如节点只提供 tip 哈希）时为 `None`，序列化成 `null`。
    pub latest_height: Option<u64>,
    /// 最新区块哈希。用 `Option` 而不是空字符串表达「上游没给」。
    pub latest_hash: Option<String>,
    /// 节点版本号。各链格式差异极大，统一按字符串原样透出，不做解析。
    pub node_version: Option<String>,
    /// `#[serde(flatten)]`：把这个字段的内容**平铺到父对象的同一层级**，
    /// 而不是生成嵌套的 `"extra": { ... }`。
    /// 于是链专有字段与公共字段并列出现，公共 schema 不被嵌套破坏。
    ///
    /// 有两个坑值得注意：
    /// 1. 被 flatten 的类型必须是 map（`Value::Object`），否则序列化报错；
    /// 2. flatten 与 `deny_unknown_fields` 互斥，且**反序列化**时 flatten 会先把
    ///    未知键全部收进这里，因此无法再检测「上游多给了字段」。
    #[serde(flatten)]
    pub extra: Value,
}

/// 固有实现块：构造器 + builder 方法。
impl StatusView {
    /// 只要求最必要的三个参数，其余字段留给 `with_xxx` 补齐。
    ///
    /// 参数 `impl Into<String>` 让调用方既能传 `&str` 也能传 `String`；
    /// `chain` 直接收 `ChainKind`（它是 `Copy` 的，按值传不产生所有权问题）。
    pub fn new(chain: ChainKind, network: impl Into<String>, rpc_url: impl Into<String>) -> Self {
        Self {
            // 字段初始化简写：变量名与字段名相同，`chain` 等价于 `chain: chain`。
            chain,
            network: network.into(),
            rpc_url: rpc_url.into(),
            latest_height: None,
            latest_hash: None,
            node_version: None,
            // 初值必须是空对象而非 Null，理由见 [`no_extra`]。
            extra: no_extra(),
        }
    }

    /// builder 方法：`mut self` 按值接收 → 改字段 → `self` 交回，支持链式调用
    /// `StatusView::new(..).with_height(1).with_hash("0x..")`。
    pub fn with_height(mut self, height: u64) -> Self {
        // 字段是 `Option<u64>`，所以要用 `Some(..)` 装箱。
        self.latest_height = Some(height);
        // 无分号 = 返回自身。
        self
    }

    /// 设置最新区块哈希。
    ///
    /// `impl Into<String>` + `mut self -> Self` 是本文件所有 `with_xxx` 的统一形态：
    /// 接收任意字符串形态（`&str` / `String` / `Cow<str>`），按值改完再交回所有权，
    /// 于是能写成 `StatusView::new(..).with_height(1).with_hash("0x..")` 一条链。
    pub fn with_hash(mut self, hash: impl Into<String>) -> Self {
        self.latest_hash = Some(hash.into());
        self
    }

    /// 设置节点版本号。
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.node_version = Some(version.into());
        self
    }

    /// 直接**替换**整个 extra（不是合并）。
    /// 需要增量追加的场合请用 [`AddressView::with_extra`] 那种合并语义。
    pub fn with_extra(mut self, extra: Value) -> Self {
        self.extra = extra;
        self
    }
}

/// 账户/地址余额。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceView {
    /// 所属链（自解释字段，理由见 [`StatusView::chain`]）。
    pub chain: ChainKind,
    /// 网络名。
    pub network: String,
    /// 被查询的地址/账户，原样回显：批量查询时调用方能据此把结果对回具体请求。
    pub address: String,
    /// 最小单位整数（wei / satoshi / lamport / yoctoNEAR），字符串形式防精度丢失。
    ///
    /// 为什么是 `String` 而不是 `u128`：JSON 的数字在很多语言里会被解析成 f64，
    /// 只有 53 位有效位，NEAR 的 24 位小数（yoctoNEAR）必然丢精度。
    /// 用字符串承载，把「怎么解析大整数」的决定权交回调用方。
    pub balance_raw: String,
    /// 人类可读金额，按 `decimals` 换算。
    pub balance_ui: String,
    /// 资产符号（ETH / BTC / SOL / NEAR …），与 `decimals` 一样由构造器按链推导，
    /// 避免适配器手填出错。
    pub symbol: String,
    /// 精度随链而异，回显出来调用方就不必自己维护一张「链 → decimals」表。
    pub decimals: u8,
    #[serde(flatten)]
    pub extra: Value,
}

/// 构造器 + builder 方法，模式与 [`StatusView`] 完全一致：
/// 必填字段由 `new(..)` 的参数列表固定，可选字段通过返回 `Self` 的 `with_xxx` 补齐。
impl BalanceView {
    /// `raw` 是**最小单位整数**，可读金额由构造函数统一换算，
    /// 这样各链适配器不会各自写出不一致的格式化逻辑。
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
            // `to_string()` 是 `Display` trait 提供的默认方法，把整数转成十进制 `String`。
            // 与 `String::from(..)` 的区别：`String::from` 只接受 `&str` / `char` 等，
            // 整数没有 `From<u128> for String` 实现，所以这里只能用 `to_string()`。
            balance_raw: raw.to_string(),
            // 复用 core 里那套「整数运算 + 字符串拼接」的换算，全程不碰 f64。
            balance_ui: crate::chain::format_units(raw, chain.decimals()),
            // `chain.symbol()` 返回 `&'static str`，这里需要 `String`，故再 `to_string()` 一次。
            symbol: chain.symbol().to_string(),
            decimals: chain.decimals(),
            extra: no_extra(),
        }
    }

    /// 整体**替换** extra（不是合并）。
    ///
    /// 传进来的值必须是 JSON 对象（`Value::Object`），否则 `#[serde(flatten)]`
    /// 序列化时会直接报错；拿不准时用 [`no_extra`] / [`empty_extra`] 兜底。
    pub fn with_extra(mut self, extra: Value) -> Self {
        self.extra = extra;
        self
    }
}

/// 区块概览。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockView {
    /// 所属链（自解释字段）。
    pub chain: ChainKind,
    /// 网络名。
    pub network: String,
    /// 按高度查询时才有值；按哈希查询且上游不回高度时为 `None`。
    pub height: Option<u64>,
    /// 区块哈希：本结构中唯一必填的业务字段，区块可以没有高度，但不可能没有哈希。
    pub hash: String,
    /// 父区块哈希；创世块、或上游不提供时为 `None`。
    pub parent_hash: Option<String>,
    /// Unix 秒级时间戳。
    ///
    /// 用 `i64` 而非 `u64`：历史上存在 1970 年之前的区块/创世时间，
    /// 且不少上游（如 Bitcoin）直接用有符号整数表示，用 `i64` 可无损承接。
    pub timestamp: Option<i64>,
    /// 区块内交易数。部分链需要额外请求才能统计，拿不到时为 `None`。
    pub tx_count: Option<u64>,
    #[serde(flatten)]
    pub extra: Value,
}

/// 构造器 + builder 方法：`new(..)` 只收必填的链 / 网络 / 哈希，其余按能力逐步补齐。
impl BlockView {
    /// `hash` 是必填：区块可以没有高度（按哈希查询时上游可能不回），
    /// 但不可能没有哈希。
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

    /// 设置区块高度。字段是 `Option<u64>`，因此用 `Some(..)` 装箱。
    pub fn with_height(mut self, height: u64) -> Self {
        self.height = Some(height);
        self
    }

    /// 设置父区块哈希。
    pub fn with_parent(mut self, parent: impl Into<String>) -> Self {
        self.parent_hash = Some(parent.into());
        self
    }

    /// 设置出块时间（Unix 秒）。有符号 `i64` 能承接 1970 年之前的创世时间。
    pub fn with_timestamp(mut self, ts: i64) -> Self {
        self.timestamp = Some(ts);
        self
    }

    /// 设置区块内交易数。
    pub fn with_tx_count(mut self, count: u64) -> Self {
        self.tx_count = Some(count);
        self
    }

    /// 整体替换 extra，语义同 [`BalanceView::with_extra`]。
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
    /// 所属链（自解释字段）。
    pub chain: ChainKind,
    /// 网络名。即使是纯本地计算也要带网络：BTC 的 bech32 hrp 与 base58
    /// 版本字节都随网络而变，脱离网络谈地址是没有意义的。
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

/// 构造器 + builder 方法。本结构没有真正的「必填/可选」之分——
/// `new(..)` 一次收全所有字段，builder 只用来追加 `extra` 里的链专有信息。
impl AddressView {
    /// 全字段构造器：这里没有可选项，所有信息都由适配器一次给全。
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
    ///
    /// 注意这里是**合并**语义（走 `merge_extra`），与 `StatusView::with_extra`
    /// 的「整体替换」语义不同：BTC 适配器常常要分几步塞入不同脚本类型的地址。
    pub fn with_extra(mut self, extra: Value) -> Self {
        // `&mut self.extra` 取可变借用，函数内部就地修改，之后再返回 `self`。
        merge_extra(&mut self.extra, extra);
        self
    }

    /// 该公钥在其它脚本类型 / 表示形式下的地址，BTC 等多地址链才有。
    ///
    /// 与 [`Self::with_extra`] 一样是合并语义，两者调用顺序不影响结果。
    pub fn with_alternatives(mut self, alternatives: Value) -> Self {
        // `json!({ "alternatives": alternatives })` 先包一层固定键，
        // 再合并进去，于是输出里会出现顶层的 `"alternatives": {...}`。
        // `json!` 宏在编译期展开成构造 `Value` 的代码，键必须是字符串字面量。
        merge_extra(&mut self.extra, json!({ "alternatives": alternatives }));
        self
    }
}

/// 把 `patch` 中的键并入 `base`；两者都必须是 JSON 对象，否则以 `patch` 为准。
///
/// 语法说明：`&mut Value` 是可变借用——调用方在调用期间不能同时持有 `base` 的其它引用，
/// 这是 Rust 「一个可变借用 或 多个不可变借用」规则的要求，换来的是无数据竞争的保证。
fn merge_extra(base: &mut Value, patch: Value) {
    // 在一个 `match` 里对**元组**做模式匹配：
    // `as_object_mut()` 返回 `Option<&mut Map>`，`as_object()` 返回 `Option<&Map>`，
    // 于是 `(Some(base), Some(patch))` 同时确认两边都是对象，并取出内部引用。
    //
    // 注意分支里 `base` / `patch` **遮蔽**（shadowing）了外层的同名变量：
    // 这里拿到的是 `&mut Map` / `&Map`，类型与外层不同，这正是遮蔽的便利之处。
    match (base.as_object_mut(), patch.as_object()) {
        (Some(base), Some(patch)) => {
            // `for (key, value) in patch`：`&Map` 可迭代出 `(&String, &Value)` 键值对。
            for (key, value) in patch {
                // `key.clone()` / `value.clone()`：拿到的都是引用，
                // 要放进 `base` 必须获得所有权，因此显式克隆一份。
                base.insert(key.clone(), value.clone());
            }
        }
        // 兜底：任一侧不是对象（比如 `patch` 是 Null / 数组），
        // 无法逐键合并，直接整体替换。`*base` 是**解引用**，把值写回调用方的那块内存。
        _ => *base = patch,
    }
}

/// 交易执行结果。
///
/// 只区分到「成功 / 失败 / 待确认 / 未知」四档，不承载各链的终局性细节
/// （如 NEAR 的 finality、BTC 的确认数）——那些属于链专有信息，放 `extra`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
// 序列化成 `"success"` / `"failed"` 等小写单词，与 CLI 参数风格保持一致。
#[serde(rename_all = "lowercase")]
pub enum TxStatus {
    /// 已上链且执行成功。
    Success,
    /// 已上链但执行失败（如 EVM 交易回执里的 `status = 0`）。
    /// 注意与「查不到」区分开——后者是 [`TxStatus::Unknown`]。
    Failed,
    /// 已在内存池 / 尚未上链。
    Pending,
    /// 查不到、或上游没给出明确结论时的兜底值。
    Unknown,
}

/// 交易详情。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxView {
    /// 所属链（自解释字段）。
    pub chain: ChainKind,
    /// 网络名。
    pub network: String,
    /// 交易哈希 / txid / signature，本结构的主键。
    pub hash: String,
    /// 执行结果。刻意只分四档，不承载各链的终局性细节，那些放 `extra`。
    pub status: TxStatus,
    /// 合约调用、多输入输出的交易可能没有单一发送方，故为 `Option`。
    pub from: Option<String>,
    /// 收款方；合约创建、或上游不提供时为 `None`。
    pub to: Option<String>,
    /// 转账金额（最小单位整数字符串）；多输入输出或合约调用时可能为 null。
    pub amount_raw: Option<String>,
    /// 人类可读金额，由 [`TxView::with_amount`] 按链精度一并推导，不单独填。
    pub amount_ui: Option<String>,
    /// 手续费（最小单位整数字符串）。
    pub fee_raw: Option<String>,
    /// 所在区块高度；还在内存池里的交易为 `None`。
    pub height: Option<u64>,
    /// 出块时间（Unix 秒）。
    pub timestamp: Option<i64>,
    /// 确认数。BTC / ETH 有明确语义，DAG 类链可能恒为 `None`。
    pub confirmations: Option<u64>,
    #[serde(flatten)]
    pub extra: Value,
}

/// 构造器 + builder 方法。字段最多的一个 View，因此 builder 也最多：
/// `new(..)` 只收四项必填，其余十余项全部走 `with_xxx`，适配器按需选用。
impl TxView {
    /// 必填四项：链、网络、哈希、状态。
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
    ///
    /// 只收最小单位整数 `raw`，可读金额由本方法按当前链的精度换算，
    /// 保证两个字段**永远自洽**——不会出现手滑填了一个对不上的 `amount_ui`。
    pub fn with_amount(mut self, raw: u128) -> Self {
        self.amount_raw = Some(raw.to_string());
        // 注意这里从 `self.chain` 取精度：此时 `self` 已被移动进本方法，
        // 但读取字段不受影响（读发生在写之后、返回之前）。
        self.amount_ui = Some(crate::chain::format_units(raw, self.chain.decimals()));
        self
    }

    /// 只设 `fee_raw`，不设 `fee_ui`：手续费的展示需求远弱于金额，
    /// 需要时调用方可自行用 `format_units` 换算。
    pub fn with_fee(mut self, raw: u128) -> Self {
        self.fee_raw = Some(raw.to_string());
        self
    }

    /// 设置发送方。
    pub fn with_from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    /// 设置接收方。
    pub fn with_to(mut self, to: impl Into<String>) -> Self {
        self.to = Some(to.into());
        self
    }

    /// 设置所在区块高度。
    pub fn with_height(mut self, height: u64) -> Self {
        self.height = Some(height);
        self
    }

    /// 设置出块时间（Unix 秒）。
    pub fn with_timestamp(mut self, ts: i64) -> Self {
        self.timestamp = Some(ts);
        self
    }

    /// 设置确认数。DAG 类链没有这个概念，直接不调用即可。
    pub fn with_confirmations(mut self, confirmations: u64) -> Self {
        self.confirmations = Some(confirmations);
        self
    }

    /// 整体替换 extra，语义同 [`BalanceView::with_extra`]。
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
///
/// 语法说明：这里**只派生了 `Debug, Clone`，刻意没有 `Serialize` / `Deserialize`**。
/// 结构体里含私钥，一旦派生 `Serialize`，就可能在打日志、打印错误、序列化 HTTP
/// 请求体时把私钥泄漏出去。不给它这个能力，编译器会替我们守住这条底线。
#[derive(Debug, Clone)]
pub struct TransferRequest {
    /// 收款地址（各链原生格式，由适配器解析）。
    pub to: String,
    /// 人类可读的原生单位金额，如 `"0.01"`；用字符串而非 f64，避免
    /// 十进制小数在二进制浮点里变成 0.00999999… 这类误差。
    pub amount: String,
    /// 私钥。格式随链而异（ETH 十六进制 / BTC WIF / SOL base58 或 JSON 数组 /
    /// NEAR `ed25519:...`），只参与本地签名，绝不外发。
    pub private_key: String,
    /// `true` 时只本地构造并签名，不广播；默认由构造器设为 `false`（真发）。
    pub dry_run: bool,
    /// 付款账户，仅 NEAR 这类「命名账户」链需要；其余链从私钥派生并忽略本字段。
    pub from: Option<String>,
}

/// 只有一个构造器：请求字段全部必填（除 `from`），故没有 builder。
impl TransferRequest {
    /// 构造器默认 `dry_run = false`、`from = None`，
    /// 需要试跑的调用方自行改字段——写操作默认「真发」，避免误以为安全结果真上链。
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
    /// 所属链（自解释字段）。
    pub chain: ChainKind,
    /// 网络名。
    pub network: String,
    /// 付款地址/账户；NEAR 取名为 `signer account`。
    pub from: Option<String>,
    /// 收款地址。转账请求本身已校验过，因此这里必填（不像 [`TxView::to`] 是可选的）。
    pub to: String,
    /// 最小单位整数字符串（wei / satoshi / lamport / yoctoNEAR）。
    pub amount_raw: String,
    /// 人类可读金额，按 `decimals` 换算。
    pub amount_ui: String,
    /// 资产符号，由构造器按链推导。
    pub symbol: String,
    /// 交易哈希 / txid / signature；dry-run 下为本地签名产生的预期哈希。
    pub tx_hash: Option<String>,
    /// 是否已广播到链上。
    pub broadcast: bool,
    #[serde(flatten)]
    pub extra: Value,
}

/// 构造器 + builder 方法：`new(..)` 收全部业务字段，`with_extra` 追加链专有信息
/// （signed_raw / fee / fee_rate / nonce / confirmations 等）。
impl TransferView {
    /// 与 [`BalanceView::new`] 同样的思路：只收最小单位整数，
    /// `amount_ui` 与 `symbol` 由构造函数统一派生，避免两处字段不一致。
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
            // `from` 本身就是 `Option<String>`，直接移进来，不必再包 `Some(..)`。
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

    /// 整体替换 extra，语义同 [`BalanceView::with_extra`]。
    pub fn with_extra(mut self, extra: Value) -> Self {
        self.extra = extra;
        self
    }
}

/// 便捷构造：把若干字段放进 extra。
///
/// 参数 `&[(&str, Value)]` 是**元组切片**：每一项是「键 + 值」的二元组。
/// 与上面的 `extra!` 宏相比，这个版本是**运行期**构造，键可以是变量，
/// 代价是调用方得先把值都构造成 `Value`。
pub fn extra_of(pairs: &[(&str, Value)]) -> Value {
    let mut map = Map::new();
    // `for (k, v) in pairs`：迭代 `&[(&str, Value)]` 得到 `&(&str, Value)`，
    // 解构后 `k: &&str`、`v: &Value`。
    for (k, v) in pairs {
        // `(*k).to_string()`：先解引用拿到 `&str`，再 `to_string()` 转成 `String`。
        // `v.clone()`：只借到了 `&Value`，要放进 map 必须取得所有权，因此克隆。
        map.insert((*k).to_string(), v.clone());
    }
    Value::Object(map)
}

/// 生成空 JSON 对象，供适配器初始化 extra。
///
/// 与 [`no_extra`] 功能相同，只是用 `json!({})` 宏写出来更直观；
/// 两者都应返回 `Value::Object(空表)` 而非 `Value::Null`（flatten 需要 map）。
pub fn empty_extra() -> Value {
    json!({})
}
