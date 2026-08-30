//! Aptos 链对统一 `ChainClient` 契约的实现（REST v1）。
//!
//! Aptos 领域背景（对照代码理解）：
//! - Move 虚拟机公链，账户地址是 **32 字节**十六进制（`0x` + 64 位 hex）；
//!   但框架保留地址（`0x1`、`0xa550c18`…）比 32 字节短，因此校验放宽为「至多 64 位」。
//! - 最小单位 `octa`，精度 8（1 APT = 10^8 octa）。
//! - 原生币不是账户字段，而是一个 **Move 资源**：
//!   `0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>`。账户未注册该资源
//!   （含账户根本不存在）时等价于零余额——这是余额查询里最关键的分支。
//! - 高度有两套坐标系：`block_height`（区块）与 `version`（交易版本，全局单调）。
//!   一个区块对应一段连续版本区间 `[first_version, last_version]`。
//!
//! 上游的坑：
//! - REST v1 的 `GET /` 只给 `block_height`，**不给最新区块哈希**，
//!   所以 `StatusView.latest_hash` 恒为 null；
//! - 区块时间戳是**微秒**字符串，需除以 10^6；
//! - `GET /blocks/by_height/{h}` 必须带 `with_transactions=true` 才回交易数组，
//!   即便如此 `transactions` 仍可能是 null，故有版本跨度的兜底算法。

// `#[async_trait]` 属性宏：trait 里不能直接写 `async fn`（返回值是匿名 Future，
// 会让 trait 失去对象安全），该宏在编译期把每个 `async fn` 改写成
// 返回 `Pin<Box<dyn Future + Send + 'async_trait>>` 的普通 `fn`。
use async_trait::async_trait;
// `serde_json::Value` 是「任意 JSON 值」；`json!` 宏用字面量语法直接构造 `Value`，
// 用于往统一 View 的 `extra` 字段里塞链专有信息（经 `#[serde(flatten)]` 平铺到顶层）。
use serde_json::{Value, json};
// sha3 crate：`Digest` 是 trait，必须引入作用域才能调用 `new/update/finalize`；
// `Sha3_256` 是 SHA3-256（Keccak 家族的 NIST 标准版，**不是** 以太坊用的 keccak256）。
use sha3::{Digest, Sha3_256};

use allchain_core::{
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, ErrorCode, SdkError, StatusView,
    TxStatus, TxView, hexutil,
};
// 各链共用的 HTTP + 值提取工具。命名说明：
// - `field_u64`：字段缺失时报 ParseError，用于「必须有」的字段；
// - `loose_u64` / `loose_u128`：宽松解析，数字 / 十进制字符串 / `0x` 十六进制都能吃；
// - `micros_to_seconds`：微秒时间戳转 Unix 秒；
// - `url_encode`：手动百分号编码，因为 Move 的 struct tag 含 `:` `<` `>`，
//   直接拼进 URL 路径会被服务端拒绝。
use chain_rpcutil::{Http, field_u64, loose_u64, loose_u128, micros_to_seconds, url_encode};

use crate::network;

/// Aptos 原生 gas 资产的 CoinStore 资源类型。
///
/// 领域说明：这是 Move 的**泛型结构体标签**（struct tag），格式是
/// `地址::模块::结构名<类型参数>`。Aptos 的原生币在链上就是一个普通资源，
/// 因此查余额 = 读账户下这个资源的 `coin.value` 字段，而不是读账户对象本身。
const APT_COINSTORE: &str = "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>";

/// Aptos 客户端：绑定一个 REST 端点 + 一个 reqwest 连接池。
///
/// 语法说明：三个字段都是拥有所有权的 `String` 而非 `&str`。
/// 若用 `&str` 字段，结构体必须带生命周期参数变成 `AptClient<'a>`，
/// 并把这个生命周期传染给所有持有它的地方（包括 `Box<dyn ChainClient>`，
/// 那要求写成 `Box<dyn ChainClient + 'a>`）。多一次堆分配换掉整套复杂度，很划算。
pub struct AptClient {
    /// 网络名；使用自定义端点时固定为 `"custom"`。
    ///
    /// 为什么自定义端点要改网络名：调用方看到 `rpc_url` 就知道连的是哪个节点，
    /// 但看到 `network` 应该知道「这是不是我预期的那条链的网络」。
    /// 用 `custom` 而不是猜，避免把自建节点误当主网。
    network: String,
    /// 实际 REST base URL，回显给调用方确认「打的是不是预期节点」。
    rpc_url: String,
    /// 共享 HTTP 客户端（内部 `Arc`，克隆廉价）；所有 IO 都经由它。
    http: Http,
}

impl AptClient {
    /// 构造客户端：`rpc_url` 优先，否则按 `network` 取预置端点（缺省主网）。
    ///
    /// 语法说明：`Option<&str>` 参数让调用方可以「不传」。返回的 `Result<Self, SdkError>`
    /// 允许构造阶段就失败（端点非法、网络名不支持）。
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        // 与 `network::parse` 里同款链式调用：trim → 过滤空串 → 转成 `String`。
        // `.map(str::to_string)` 把 `Option<&str>` 变成 `Option<String>`，
        // 拿到所有权后就不必担心它来自调用方的临时借用。
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        // `match` 的两个分支返回**同一个类型**的元组 `(String, String)`，这是硬性要求：
        // Rust 的 `match` 是表达式，全部分支的值类型必须一致。
        let (network_name, url) = match custom {
            // 分支内 `url` 遮蔽（shadowing）了外层的 `custom`，类型从 `Option<String>`
            // 变成移动出来的 `String`。遮蔽让我们不必另起 `custom_url` 这种名字。
            Some(url) => ("custom".to_string(), url),
            None => {
                // `?` 是错误传播运算符：若 `network::parse` 返回 `Err`，
                // 立即从本函数 `return Err(..)`；否则取出 `Ok` 里的值继续往下。
                // 它等价于 `match ... { Err(e) => return Err(e.into()), Ok(v) => v }`。
                let net = network::parse(network)?;
                // `net.as_str()` 返回 `&'static str`，这里要 `String`，故再 `to_string()`。
                (net.as_str().to_string(), net.rpc_url().to_string())
            }
        };
        let http = Http::new(&url)?;
        // `Self { .. }` 是结构体的字面量构造；`Self` 等价于 `AptClient`。
        // 字段初始化简写：`network` 等价于 `network: network`。
        Ok(Self {
            network: network_name,
            rpc_url: url,
            http,
        })
    }

    /// 顶层账本信息（GET /）。
    ///
    /// Aptos 的根节点自带 chain_id / epoch / ledger_version / block_height，
    /// 是 `status()` 与「取最新区块高度」共用的入口，因此单独抽出来复用。
    async fn ledger_info(&self) -> Result<Value, SdkError> {
        // 空路径 = base URL 本身（`Http::new` 已去掉末尾的 `/`）。
        self.http.get_value("").await
    }
}

// `impl Trait for Type` 是 **trait 实现块**：一旦实现，本类型就能被当作
// `Box<dyn ChainClient>` 使用，上层 acli 因此可以在运行期按链名分发，
// 完全不认识 `AptClient` 这个具体类型。
#[async_trait]
impl ChainClient for AptClient {
    /// 所属链。同步方法——值在编译期就确定，无需 IO。
    fn kind(&self) -> ChainKind {
        ChainKind::Apt
    }

    /// 网络名。返回 `&str` 借用的是 `self` 内部的 `String`，
    /// 生命周期被自动绑定为「不比 `self` 活得更久」。
    fn network(&self) -> &str {
        &self.network
    }

    /// 实际 REST base URL。
    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        let info = self.ledger_info().await?;
        // `.ok()` 把 `Result<u64, SdkError>` 转成 `Option<u64>`，丢弃错误详情。
        // 这里刻意降级：账本信息里缺 block_height 不该让整个 status 失败。
        let height = field_u64(&info, "block_height").ok();
        // `&self.network`：`&String` 会**自动解引用强制转换**（deref coercion）成 `&str`，
        // 正好匹配 `impl Into<String>` 参数的要求。
        let mut view = StatusView::new(ChainKind::Apt, &self.network, &self.rpc_url);
        // `if let Some(h) = height` 是「只在有值时执行」的惯用写法，
        // 模式绑定把 `Option<u64>` 里的 `u64` 解出来。
        if let Some(h) = height {
            view = view.with_height(h);
        }
        // Aptos 账本信息不含最新块哈希，latest_hash 保持 null。
        //
        // 下面这一串 `info.get(k).cloned().unwrap_or(Value::Null)` 是固定套路，值得拆开看：
        // - `Value::get(&str)` 返回 `Option<&Value>`（借用的，拿不到所有权）；
        // - `.cloned()` 等价于 `.map(Clone::clone)`，把 `Option<&Value>` 变成 `Option<Value>`；
        // - `.unwrap_or(Value::Null)` 把「字段缺失」变成显式的 JSON null，
        //   于是输出的 schema 稳定（键一定存在，值可能是 null），调用方不必判断键是否存在。
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
        // 资源路径里的 struct tag 必须百分号编码，否则 `::` 和 `<>` 会破坏 URL 解析。
        let path = format!(
            "/accounts/{}/resource/{}",
            address.trim(),
            url_encode(APT_COINSTORE)
        );
        // 元组解构：把一次请求的结果同时映射成「余额」和「是否注册过该资源」两个信息。
        let (raw, registered) = match self.http.get_value(&path).await {
            Ok(v) => {
                // 两层 `and_then` 沿 JSON 路径下钻：`data` → `coin`。
                // `and_then(闭包)` 只在 `Some` 时调用闭包，且闭包必须返回 `Option`（可扁平化）；
                // 与之相对的 `map` 会产生 `Option<Option<_>>` 这种嵌套。
                //
                // `ok_or_else(|| ..)` 把 `Option` 转成 `Result`，闭包**惰性**求值：
                // 只有真的为 `None` 时才付代价去 `format!` 错误信息。
                // 对比 `ok_or(err)`：那会无条件先构造好 `err`，哪怕用不上。
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
            //
            // 语法说明：`Err(e) if e.code == ErrorCode::NotFound` 是 **match guard**（匹配守卫）：
            // 先匹配上 `Err(e)` 这个模式，再用 `if` 追加一个运行期条件。
            // 有了它，`Err` 分支就能按错误码分流——这正是「统一错误码」设计的收益：
            // 适配器无需解析上游错误文本。
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


    /// 查询交易。
    /// 链头高度：最新区块高度（裸 `u64`）。
    async fn last_block_height(&self) -> Result<u64, SdkError> {
        let info = self.ledger_info().await?;
        field_u64(&info, "block_height")
    }

    /// 按高度查询区块。
    async fn block_by_height(&self, height: u64) -> Result<BlockView, SdkError> {
        let block = self
            .http
            .get_value(&format!("/blocks/by_height/{height}?with_transactions=true"))
            .await?;
        let hash = block
            .get("block_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, format!("区块缺少 block_hash: {block}")))?
            .to_string();
        let timestamp = micros_to_seconds(block.get("block_timestamp").ok_or_else(|| {
            SdkError::new(ErrorCode::ParseError, "区块缺少 block_timestamp")
        })?)?;
        let tx_count = match block.get("transactions").and_then(Value::as_array) {
            Some(txs) => txs.len() as u64,
            None => match (
                block.get("first_version").and_then(loose_u64_opt),
                block.get("last_version").and_then(loose_u64_opt),
            ) {
                (Some(first), Some(last)) if last >= first => last - first + 1,
                _ => 0,
            },
        };
        let height_v = block.get("block_height").and_then(loose_u64_opt);
        let mut view = BlockView::new(ChainKind::Apt, &self.network, hash)
            .with_timestamp(timestamp)
            .with_tx_count(tx_count);
        if let Some(h) = height_v { view = view.with_height(h); }
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

        // Aptos 的 `success` 只在交易已执行后才有意义；未上链时该字段缺失，
        // 故 `unwrap_or(false)` 兜底，再配合下面的 pending 判断决定最终状态。
        let success = tx.get("success").and_then(Value::as_bool).unwrap_or(false);
        // 判 pending 的经验规则：已上链的交易一定带 `version`（全局交易版本号），
        // 或带 `block_metadata_extension`；两者都缺说明还在内存池里。
        let pending = tx.get("block_metadata_extension").is_none() && tx.get("version").is_none();
        // `if / else if / else` 在 Rust 里是**表达式**，整体有值，可直接赋给变量。
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
        // 注意：填进 `height` 的是 **version** 而不是区块高度。
        // Aptos 的 `version` 是全局单调递增的交易序号，`block_height` 是区块序号，
        // 二者不同；统一 View 里 `height` 语义是「定位该交易的位置」，
        // 用 version 更精确（一个区块内有多笔交易）。
        if let Some(version) = tx.get("version").and_then(loose_u64_opt) {
            view = view.with_height(version);
        }
        // **let 链**（let chains）：`if let Some(ts) = .. && let Ok(secs) = ..`
        // 是较新的稳定语法，把两层嵌套 `if let` 压平，避免「箭头型」代码。
        // `&&` 在这里是 let 链的接续符，要求前一个模式匹配成功才会继续。
        if let Some(ts) = tx.get("timestamp")
            && let Ok(secs) = micros_to_seconds(ts)
        {
            // 内层 `let Ok(..)` 失败时（微秒时间戳解析不了）只是跳过设时间戳，
            // 不影响整笔交易的查询——这是刻意的降级策略。
            view = view.with_timestamp(secs);
        }

        // 实际 gas = gas_used × gas_unit_price（octa）。
        let gas_used = tx.get("gas_used").and_then(loose_u128_opt).unwrap_or(0);
        let gas_price = tx
            .get("gas_unit_price")
            .and_then(loose_u128_opt)
            .unwrap_or(0);
        // `saturating_mul` 是**饱和乘法**：溢出时停在 `u128::MAX` 而不是 panic。
        // 调试构建下普通 `*` 溢出会 panic，发布构建下会静默回绕，两者都不可接受，
        // 因此凡涉及上游传来的数字做算术，一律用 `saturating_*` / `checked_*`。
        let fee = gas_used.saturating_mul(gas_price);
        // 手续费为 0 时不设字段，让 JSON 输出为 null 而非 "0"——
        // 「没算出来」与「算出来是 0」在无 gas 交易上难以区分，这里选择不误导。
        if fee != 0 {
            view = view.with_fee(fee);
        }

        // 原生 APT 转账：entry function 0x1::coin::transfer 的参数为 [收款方, 金额]。
        //
        // 为什么只能这样猜：Aptos 交易是 Move 函数调用，没有 EVM 那种
        // 固定的 `to` / `value` 字段。只有识别出「调用的是 coin::transfer」
        // 才能把参数数组解释成 [收款地址, 金额]——这是**启发式**，
        // 对其它 entry function（如 aptos_account::transfer）不会命中。
        let mut to: Option<String> = None;
        let mut amount: Option<u128> = None;
        if let Some(payload) = tx.get("payload") {
            let function = payload
                .get("function")
                .and_then(Value::as_str)
                // 缺函数名的 payload（如 script payload）按空串处理，
                // 于是下面的 `ends_with` 必然不命中，安全退化。
                .unwrap_or("");
            // `ends_with` 而非 `==`：Move 函数带模块前缀，
            // 例如 `0x1::coin::transfer` 与 `0x1::aptos_account::transfer` 都以它结尾。
            if function.ends_with("::coin::transfer")
                && let Some(args) = payload.get("arguments").and_then(Value::as_array)
            {
                // `args.first()` 返回 `Option<&Value>`，取第一个参数作为收款方。
                to = args.first().and_then(Value::as_str).map(str::to_string);
                // `args.get(1)` 而非 `args[1]`：索引越界会 panic，
                // 而 `get` 返回 `Option`，对上游畸形数据天然安全。
                amount = args.get(1).and_then(loose_u128_opt);
            }
        }
        if let Some(t) = to {
            view = view.with_to(t);
        }
        if let Some(a) = amount {
            // `with_amount` 内部按 Aptos 的 8 位精度一并算出 `amount_ui`，
            // 保证 raw 与 ui 两个字段永远自洽。
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

    /// 由公钥派生地址：**纯本地计算**，不访问网络。
    ///
    /// 只支持单签 ed25519 账户。Aptos 的多签账户地址是另一套派生规则
    /// （涉及公钥列表与阈值），当前未实现。
    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        // 委托给自由函数：`&self.network` 传进去是为了让返回的 `AddressView`
        // 也带上网络标记，保持与其它链一致的自解释性。
        derive_address(pubkey, &self.network)
    }
}

/// 纯本地派生：Aptos 单签地址 = SHA3-256(pubkey || scheme_byte)。
///
/// 领域说明：Aptos 把「认证密钥」（authentication key）与「地址」在单签场景下
/// 统一为 `sha3_256(32 字节公钥 || 1 字节 scheme)`：
/// - ed25519 单签的 scheme byte 是 `0x00`；
/// - 多签是 `0x01`，且输入是 `sha3_256(各公钥 || 阈值 || 公钥个数)` 的结果；
/// - 摘要取**全部 32 字节**，与 ETH 只取后 20 字节的做法不同。
///
/// 语法说明：这是**自由函数**（不在任何 impl 块里），因此是本模块私有、不对外暴露。
fn derive_address(pubkey: &str, network: &str) -> Result<AddressView, SdkError> {
    // `hexutil::decode_hex` 允许 `0x` / `0X` 前缀、大小写不敏感；
    // `?` 在失败时直接返回 `INVALID_ARGUMENT`，错误信息由 core 统一给出。
    let bytes = hexutil::decode_hex(pubkey)?;
    if bytes.len() != 32 {
        // 提前 `return Err(..)`：公钥长度不对就没有继续算的意义。
        return Err(SdkError::invalid_argument(format!(
            "APT 单签公钥需为 32 字节 ed25519 公钥的十六进制，实际 {} 字节",
            bytes.len()
        )));
    }
    // ed25519 的 scheme byte = 0x00。
    //
    // `Digest` trait 的三段式用法（sha3 / sha2 / blake2 都是这套）：
    // 1. `Sha3_256::new()` 造一个 hasher；
    // 2. `update(数据)` 可以调多次，内部增量累积；
    // 3. `finalize()` 产出摘要。
    // 这里**故意分两次 update** 而不是先拼好一个 33 字节数组再喂进去，
    // 省掉一次 `Vec` 分配，也让「公钥 + scheme」的两段语义一目了然。
    let mut hasher = Sha3_256::new();
    // `&bytes`：`Vec<u8>` 借成 `&[u8]` 切片（deref coercion）。
    hasher.update(&bytes);
    // `[0x00]` 是长度为 1 的数组字面量，类型 `[u8; 1]`。
    hasher.update([0x00]);
    // `finalize()` 返回 `GenericArray<u8, U32>`，可按切片使用。
    let addr = hasher.finalize();
    let address_hex = hexutil::encode_hex_prefixed(&addr);

    Ok(AddressView::new(
        ChainKind::Apt,
        network,
        // `pubkey` 字段回填**规范化后**的公钥（小写、带 0x），
        // 而不是调用方原样传入的字符串——这样输出可比较、可复现。
        hexutil::encode_hex_prefixed(&bytes),
        address_hex,
        "ed25519",
        bytes.len(),
    )
    // `extra` 里记下派生规则，调用方无需读源码就能核对地址是怎么算出来的。
    .with_extra(json!({
        "scheme": "ed25519",
        "scheme_byte": "0x00",
        "derivation": "sha3_256(pubkey || 0x00)",
    })))
}

// ---------------------------------------------------------------------------
// 输入校验
//
// 校验放在**发请求之前**：地址格式不对就让上游返回 404，会与
// 「账户确实不存在」混淆（本适配器正是把 404 当零余额处理），
// 本地先挡一道才能给出准确的 INVALID_ARGUMENT。
// ---------------------------------------------------------------------------

/// 校验 Aptos 地址：`0x` 前缀（可省）+ 至多 64 位十六进制。
fn validate_address(raw: &str) -> Result<(), SdkError> {
    let t = raw.trim();
    // 允许带或不带 `0x` / `0X` 前缀，剥掉后再校验主体。
    let body = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    // 为什么是 `> 64` 而不是 `!= 64`：Aptos 的框架保留地址（如 `0x1`、`0xa550c18`）
    // 比 32 字节短，是合法地址。因此上限卡死 32 字节，下限只要求非空。
    //
    // `.chars().all(闭包)` 是迭代器短路求值：遇到第一个不满足的字符立即返回 false。
    // `is_ascii_hexdigit` 只认 0-9a-fA-F，不接受全角字符。
    if body.is_empty() || body.len() > 64 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SdkError::invalid_argument(format!(
            "非法 APT 地址: {raw}（期望 0x + 至多 64 位十六进制）"
        )));
    }
    // 返回 `Ok(())`：`()` 是**单元类型**，相当于其它语言的 void，
    // 这里表示「校验通过，没有产出值」。
    Ok(())
}

/// 校验交易哈希：`0x` 前缀（可省）+ **恰好** 64 位十六进制。
///
/// 与地址不同，哈希长度是固定的，因此这里用 `!= 64` 严格卡死。
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

/// 判断 `raw` 是否形如区块哈希（64 位十六进制）。
///
/// 语法说明：返回 `bool` 而非 `Result`——这里只是「看起来像不像」的试探，
/// 不是校验，判断为 false 还有后续的高度解析路径可以走。
fn is_block_hash(raw: &str) -> bool {
    let body = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    body.len() == 64 && body.chars().all(|c| c.is_ascii_hexdigit())
}

/// `loose_u64` 的 `Option` 适配版，供 `and_then` 链式调用。
///
/// 为什么需要它：`loose_u64` 返回 `Result<u64, SdkError>`，而 `and_then` 要求
/// 闭包返回 `Option`。这里 `.ok()` 丢弃错误详情——用于「有就取，没有就算了」的字段。
/// 必填字段请直接用 `field_u64`，它会保留错误信息。
fn loose_u64_opt(v: &Value) -> Option<u64> {
    loose_u64(v).ok()
}

/// `loose_u128` 的 `Option` 适配版，理由同上。
fn loose_u128_opt(v: &Value) -> Option<u128> {
    loose_u128(v).ok()
}

/// 单元测试模块：`#[cfg(test)]` 保证它只在 `cargo test` 时编译，正式构建里完全不存在。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_known_aptos_address() {
        // 回归向量：ed25519 公钥全 0xEE，地址为 sha3_256(pk || 00)。
        //
        // `format!("{}", ..)` 里的 `{hasher.finalize()}` 未能直接打印（GenericArray 无 Display），
        // 所以先用 `hexutil::encode_hex` 转字符串。
        // 注意测试里**独立重算一遍**期望值而不是写死常量：
        // 这样它验证的是「derive_address 是否走对了 sha3_256(pk||0x00) 这条路」，
        // 而不是「sha3 库有没有变」。
        let pk = "ee".repeat(32);
        let bytes = hexutil::decode_hex(&pk).unwrap();
        let mut hasher = Sha3_256::new();
        hasher.update(bytes);
        hasher.update([0x00]);
        // 手写 `0x{}` 前缀，等价于 `encode_hex_prefixed`。
        let expect = format!("0x{}", hexutil::encode_hex(&hasher.finalize()));

        let view = derive_address(&pk, "mainnet").unwrap();
        assert_eq!(view.address, expect);
        assert_eq!(view.address_type, "ed25519");
        assert_eq!(view.pubkey_bytes, 32);
    }

    #[test]
    fn rejects_wrong_pubkey_length() {
        // 31 字节（62 位 hex）与空串都应被拒。
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
