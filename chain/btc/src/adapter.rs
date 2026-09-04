//! btc 链对统一 `ChainClient` 契约的实现。
//!
//! 直接复用 `backend::Chain` 已有的双数据源（Esplora 索引器 / 自建 bitcoind）能力，
//! 把其 View 结构映射为 core 的统一模型。
//!
//! 本文件的职责边界很清晰：**不做任何链上算法**，只做三件事——
//!   1. 把字符串参数（网络名、地址、金额、公钥）校验并翻译成 rust-bitcoin 的强类型；
//!   2. 调用 `backend::Chain` 拿到数据；
//!   3. 把结果塞进 core 的 `*_View`，并把 BTC 特有的字段放进 `extra`。
//!
//! 之所以要「翻译」而不是直接暴露 `backend` 的结构：core 的 View 是**跨链统一**的，
//! 上层（acli 的 CLI / HTTP / MCP）只认这一套模型，
//! 于是换链不需要改上层代码，这就是整个 SDK 的核心解耦点。
//!
//! ⚠️ 关于 `extra`：BTC 有很多无法塞进统一模型的字段
//! （vsize / weight / UTXO 明细 / 找零 / 手续费率……）。
//! core 的模型为此预留了 `serde_json::Value` 类型的 `extra` 字段，
//! 配合 `#[serde(flatten)]` 在序列化时把 extra 摊平到顶层，
//! 既保住了跨链统一，又不丢链特有信息。

// `#[async_trait]` 是**属性宏**：它会把 `impl` 块里的 `async fn`
// 改写成返回 `Pin<Box<dyn Future + Send + 'async_trait>>` 的普通 fn。
// 之所以必须如此：trait 里目前还不能原生写 `async fn`（会缺少 `Send` 等约束的表达能力），
// 装箱成 trait object 后才能放进 `dyn ChainClient` 里做动态分发。
use async_trait::async_trait;
// `NetworkUnchecked` 是 rust-bitcoin 用**类型状态**表达「地址还没校验网络」的技巧：
// `Address<NetworkUnchecked>` 必须经 `require_network()` 才能变成 `Address<NetworkChecked>`，
// 让「拿主网地址去测试网转账」在编译期就不可能发生。
use bitcoin::address::NetworkUnchecked;
// `Secp256k1` 是椭圆曲线运算上下文，派生 Taproot 地址时做点乘与调整。
use bitcoin::key::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, Network, PublicKey};
use serde_json::json;

use allchain_core::{
    AddressView, BalanceView, BlockView, BuildTransferRequest, BuildTransferView, ChainClient,
    ChainKind, SdkError, StatusView, SubmitRequest, SubmitView, TxStatus, TxView, hexutil,
};

use crate::backend::Chain;
use crate::network::NetworkArg;

/// BTC 客户端。地址/UTXO 类查询必须有索引器，默认走 Esplora。
///
/// 领域说明：BTC 与 ETH 最大的架构差异在于——**bitcoind 本身不索引地址**。
/// 它只维护 UTXO 集合，无法回答「某个地址有多少币」。
/// 因此「查余额」「查 UTXO」这类操作必须依赖外部索引器（Esplora / Electrs）。
///
/// 语法说明：三个字段都用 `String` 而非 `&str`。
/// 若写成 `&'a str`，结构体就得多一个生命周期参数 `BtcClient<'a>`，
/// 这个参数会顺着 `ChainClient` 的实现传染到所有使用处。
/// 多一次堆分配换取"无生命周期"，在这种长期存活的客户端对象上是划算的。
pub struct BtcClient {
    /// 网络名字符串（`mainnet` / `testnet` / ...），供统一的 View 输出。
    network: String,
    /// 实际生效的数据源端点，回显给用户便于排查。
    rpc_url: String,
    /// 真正干活的后端：封装了 Esplora 索引器与可选的自建 bitcoind。
    chain: Chain,
}

impl BtcClient {
    /// `rpc_url` 对 BTC 而言是 **Esplora 索引器地址**（不是 JSON-RPC 端点）；
    /// 提供时覆盖当前网络的默认索引器。
    ///
    /// ⚠️ 这是本 SDK 最容易踩的坑：`--rpc-url` 在 ETH 上是 JSON-RPC，
    /// 在 BTC 上却是 REST 索引器（形如 `https://blockstream.info/api`）。
    /// 想连自建 bitcoind 要另外配 `node_url` / cookie，见 `backend::Chain::new`。
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        let net = parse_network(network)?;
        // 三级归一化的**迭代器链**：
        //   1. `map(str::trim)`      去掉首尾空白（用户从命令行粘贴常带空格）；
        //   2. `filter(|s| !s.is_empty())`  把纯空白串视为"未提供"；
        //   3. `map(str::to_string)` 转成自有 `String`。
        // 注意 `str::trim` 直接传**函数指针**——它接受 `&str` 且返回 `&str`，
        // 签名正好匹配，所以不必写 `|s| s.trim()`。
        let esplora = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            // 只有前面三步都通过但结果是 `None` 时才用默认值，
            // 且 `unwrap_or_else` 是**惰性**的：显式给了地址就不会去算默认地址。
            .unwrap_or_else(|| net.esplora_url().to_string());

        // `Chain::new` 返回的是 `anyhow::Result`，这里要转成契约层的 `SdkError`。
        // `map_err` 只做类型转换，不改变控制流；`?` 负责提前返回。
        // 第三个参数 `None` 表示「不配置自建 bitcoind」。
        let chain = Chain::new(net, &esplora, None).map_err(|e| fail("初始化链数据源失败", e))?;
        // 回显的端点取自 `chain.endpoint()` 而不是入参：
        // 因为 `Chain` 内部可能做了归一化（比如去掉结尾斜杠）。
        let rpc_url = chain.endpoint();
        Ok(Self {
            // `net.to_string()`：借助 `Display` 而不是 `Debug`（`{:?}`），
            // 得到的是 `mainnet` 这种人类可读的名字。
            network: net.to_string(),
            rpc_url,
            chain,
        })
    }

    /// 便捷方法：把上下文前缀拼进错误消息再分类。
    ///
    /// 语法说明：这是**关联函数（方法）**，第一个参数是 `&self`；
    /// 它只是转发给同名的自由函数 `fail`，好处是调用处可写 `self.fail(...)`
    /// 而不必关心 `fail` 在模块何处定义。
    ///
    /// 约束必须与自由函数**完全一致**（同样是 `Into<anyhow::Error>`），
    /// 否则转发时会在这一层就把错误降级成 Display，根因照样丢掉。
    fn fail(&self, context: &str, err: impl Into<anyhow::Error>) -> SdkError {
        fail(context, err)
    }
}

/// 把网络名解析成 `NetworkArg`，`None` / 空串一律视为主网。
///
/// 语法说明：`raw.map(str::trim).filter(|s| !s.is_empty())` 把
/// `Option<&str>` 里的空串与空白串统一折叠成 `None`，
/// 这样 `match` 里就不必为「空串」单独写一条分支。
fn parse_network(raw: Option<&str>) -> Result<NetworkArg, SdkError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(NetworkArg::Mainnet),
        // 字面量模式 `Some("mainnet")` 直接匹配字符串切片的内容，
        // 这是 Rust `match` 相比其它语言更强大的地方。
        Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("testnet") => Ok(NetworkArg::Testnet),
        Some("testnet4") => Ok(NetworkArg::Testnet4),
        Some("signet") => Ok(NetworkArg::Signet),
        Some("regtest") => Ok(NetworkArg::Regtest),
        // `other` 绑定把剩余情况的值捕获下来，用于拼错误消息——
        // 只报"不支持"而不回显用户输入会让排查困难很多。
        Some(other) => Err(SdkError::invalid_argument(format!(
            "BTC 不支持的网络: {other}（可选 mainnet / testnet / testnet4 / signet / regtest）"
        ))),
    }
}

/// 解析地址并**校验它属于指定网络**。
///
/// 抽出来是因为转账相关的三个入口（`transfer` / `build_transfer`）
/// 都必须做同一件事：先按 `NetworkUnchecked` 解析字符，再升级成
/// `NetworkChecked`。漏掉第二步就会出现「把主网地址发到测试网」，
/// 而这类错误在广播前**不会有任何提示**。
fn parse_checked_address(
    raw: &str,
    network: Network,
) -> Result<Address<bitcoin::address::NetworkChecked>, SdkError> {
    raw.trim()
        // turbofish 语法 `parse::<Address<NetworkUnchecked>>()`：
        // 在方法名上直接指定泛型参数，让编译器知道要解析成什么类型。
        .parse::<Address<NetworkUnchecked>>()
        // 这里丢弃解析器的原始英文错误，改用统一的中文提示，
        // 避免把库内部信息直接抛给用户。
        .map_err(|_| SdkError::invalid_argument(format!("非法 BTC 地址: {raw}")))?
        // **关键一步**：把「未校验网络的地址」升级成「已校验网络的地址」。
        // 若用户拿主网地址来测试网转账，这里就会报错，
        // 而不是等到广播时才被节点拒绝（那时钱可能已经打错网络了）。
        .require_network(network)
        .map_err(|e| SdkError::invalid_argument(format!("地址网络不匹配: {e}")))
}

/// 把任意错误附加上中文上下文，再交给 `classify` 归类成 `SdkError`。
///
/// 领域说明：`classify` 会扫描错误文本里的关键词
/// （如 `timeout` / `connection refused` / `404`）
/// 映射成 `ErrorCode::Network` / `Rpc` / `NotFound` 等，
/// 所以**上下文文案必须保留原始错误**，否则分类会失准。
///
/// ⚠️ 为什么参数必须是 `Into<anyhow::Error>` 而不是 `impl Display`：
/// `anyhow::Error` 的普通 `Display` **只打印最外层上下文**，
/// 真正的根因（网络不通、超时、HTTP 状态码）藏在 `source()` 链里，
/// 用 `impl Display` 接住就会**静默丢掉整条链**，表现为
/// 「只看到『查询 UTXO 失败』、看不出是网络还是参数问题」。
/// 转成 `anyhow::Error` 后用 `{err:#}` 才能把整条链拼进文本。
///
/// 语法说明：
/// - `impl Into<anyhow::Error>` 是**参数位置的 impl Trait**：泛型 + 静态分发。
///   它同时接受两种实参——`anyhow::Error` 本身（走标准库的反射实现
///   `impl<T> From<T> for T`），以及任何 `std::error::Error + Send + Sync + 'static`
///   的具体错误类型（走 `anyhow` 的 `impl<E: Error + Send + Sync + 'static> From<E> for Error`）。
/// - `{err:#}` 里的 `#` 是**备用（alternate）格式化标志**。anyhow 为 `Display`
///   实现了两种形态：`{}` 只给最外层，`{:#}` 把整条链用 `": "` 串成一行。
///   这正是 `classify` 需要的输入形态。
fn fail(context: &str, err: impl Into<anyhow::Error>) -> SdkError {
    let err = err.into();
    allchain_core::error::classify(&format!("{context}: {err:#}"))
}

// 属性宏必须先于 `impl` 块，它会在**编译前**重写整个块。
// 注意 `ChainClient` 要求实现者 `Send + Sync`——异步任务可能被调度到别的线程，
// 而 `BtcClient` 的三个字段都是 `String` / `Chain`（内部是 `Arc`），天然满足。
#[async_trait]
impl ChainClient for BtcClient {
    /// 返回链标识。这是 `ChainKind` 枚举的**单元变体**，没有附加数据。
    fn kind(&self) -> ChainKind {
        ChainKind::Btc
    }

    /// 返回网络名。
    ///
    /// 语法说明：返回类型是 `&str` 而不是 `String`，
    /// 参数 `&self` 的生命周期会被**生命周期省略规则**自动借给返回值，
    /// 所以不必写 `fn network<'a>(&'a self) -> &'a str`。
    fn network(&self) -> &str {
        &self.network
    }

    /// 返回实际生效的数据源端点。
    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// 查询链状态：高度、最佳区块哈希，以及 BTC 特有的难度 / 内存池 / 中位时间。
    async fn status(&self) -> Result<StatusView, SdkError> {
        // `map_err` 把 `anyhow::Error` 转成 `SdkError`。
        // 这里用 `self.fail(...)` 而不是裸传错误，是为了带上中文上下文供 `classify` 分类。
        let v = self
            .chain
            .status()
            .await
            .map_err(|e| self.fail("查询链状态失败", e))?;
        // 链式构造器（builder）模式：每个 `with_xxx` 接收 `self` 并返回 `Self`，
        // 因此可以一路点下去。相比"先 new 再逐个赋值"，能保证对象始终完整构造。
        Ok(
            StatusView::new(ChainKind::Btc, &self.network, &self.rpc_url)
                .with_height(v.blocks)
                .with_hash(v.best_block_hash)
                // `json!` 宏在编译期展开成 `serde_json::Value` 的构造代码，
                // 语法与 JSON 字面量一致，键名会自动加引号。
                .with_extra(json!({
                    // 标注数据来源（Esplora / bitcoind）：BTC 双数据源下这一点尤为重要，
                    // 因为不同来源返回的字段完整度不同。
                    "source": v.source,
                    "difficulty": v.difficulty,
                    "mempool_txs": v.mempool_txs,
                    "mempool_bytes": v.mempool_bytes,
                    "headers": v.headers,
                    // 中位时间：比特币用过去 11 个块时间戳的中位数，
                    // 防止矿工通过微调时间戳来影响难度调整。
                    "median_time": v.median_time,
                })),
        )
    }

    /// 查询地址余额。
    ///
    /// 领域说明：BTC 的"余额"其实是**索引器算出来的**——
    /// 把该地址所有 UTXO 的金额相加。链上并没有"账户余额"这个实体。
    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        let v = self
            .chain
            .address(address)
            .await
            .map_err(|e| self.fail("查询地址失败", e))?;
        Ok(BalanceView::new(
            ChainKind::Btc,
            &self.network,
            address,
            // `as u128`：**拓宽转换**，u64 → u128 永不溢出，是安全的。
            // 统一模型用 u128 是为了同时容纳 ETH 的 wei（1e18 量级）。
            v.confirmed_balance as u128,
        )
        .with_extra(json!({
            // 未确认余额可正可负：收到未确认的币为正，花出去尚未确认为负。
            // 所以用 i64 而非 u64。
            "unconfirmed_balance": v.unconfirmed_balance,
            "tx_count": v.tx_count,
            "total_received": v.total_received,
            "total_sent": v.total_sent,
            // UTXO 计数：已资助的输出数 − 已花费的输出数 = 当前可用 UTXO 数。
            "funded_txo_count": v.funded_txo_count,
            "spent_txo_count": v.spent_txo_count,
        })))
    }


    /// 查询交易详情。
    ///
    /// 领域说明：BTC 交易可以**多输入多输出**，
    /// 因此 `from` / `to` / `amount` 这三个字段在统一模型里只能是"概览"，
    /// 精确语义由 `extra.inputs` / `extra.outputs` 承载。
    /// 链头高度：最新区块的高度（裸 `u64`）。
    async fn last_block_height(&self) -> Result<u64, SdkError> {
        // 复用后端 `block(None)` 取链尖，再取其高度——一次请求即可。
        let v = self
            .chain
            .block(None)
            .await
            .map_err(|e| self.fail("查询最新区块失败", e))?;
        Ok(v.height)
    }

    /// 按高度查询区块。
    async fn block_by_height(&self, height: u64) -> Result<BlockView, SdkError> {
        let v = self
            .chain
            .block(Some(&height.to_string()))
            .await
            .map_err(|e| self.fail("查询区块失败", e))?;
        let mut view = BlockView::new(ChainKind::Btc, &self.network, v.hash)
            .with_height(v.height)
            .with_timestamp(v.timestamp as i64)
            .with_tx_count(v.tx_count);
        if let Some(prev) = v.prev_hash {
            view = view.with_parent(prev);
        }
        Ok(view.with_extra(json!({
            "size": v.size,
            "weight": v.weight,
            "merkle_root": v.merkle_root,
            "nonce": v.nonce,
            "difficulty": v.difficulty,
            "confirmations": v.confirmations,
            "next_hash": v.next_hash,
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        let v = self
            .chain
            .tx(hash)
            .await
            .map_err(|e| self.fail("查询交易失败", e))?;

        // BTC 没有 EVM 那种"交易回执 + 状态码"的概念：
        // 只要进了区块就是成功，只有还在内存池里才算 Pending。
        // 所以 `TxStatus` 只有 Success / Pending 两种取值。
        let status = if v.confirmed {
            TxStatus::Success
        } else {
            TxStatus::Pending
        };
        // 注意 `new` 的第三个参数用的是入参 `hash` 而非 `v.txid`——
        // 保证"用户查什么就回显什么"，即使后端做了大小写归一化也不会变。
        let mut view = TxView::new(ChainKind::Btc, &self.network, hash, status);

        // BTC 以 UTXO 为模型，没有单一的「付款账户」；取首个非 coinbase 输入作为概览。
        //
        // 语法说明：这是一条**迭代器链**：
        //   `.iter()`      借用遍历（不消耗 `v.inputs`）；
        //   `.find(|i| !i.coinbase)` 取第一个满足条件的元素，返回 `Option<&TxInView>`；
        //   `.and_then(|i| i.address.clone())` 把两层 Option 压平——
        //      输入存在但 `address` 为 `None`（如某些奇异脚本）时整体为 `None`。
        // `and_then` 是 `Option` 的 "flat map"，避免写出 `Option<Option<T>>`。
        if let Some(addr) = v
            .inputs
            .iter()
            .find(|i| !i.coinbase)
            .and_then(|i| i.address.clone())
        {
            view = view.with_from(addr);
        }
        // 取第一个输出作为"收款方"概览：多数普通转账的第一个输出就是收款地址
        //（第二个是找零，币又回到付款方自己）。
        if let Some(addr) = v.outputs.first().and_then(|o| o.address.clone()) {
            view = view.with_to(addr);
        }
        // 以下字段都可能是 `None`（未确认交易没有区块高度与时间，
        // coinbase 交易算不出租金意义上的手续费），所以逐个 `if let` 追加。
        if let Some(fee) = v.fee {
            view = view.with_fee(fee as u128);
        }
        if let Some(height) = v.block_height {
            view = view.with_height(height);
        }
        if let Some(time) = v.block_time {
            view = view.with_timestamp(time as i64);
        }
        if let Some(confirmations) = v.confirmations {
            view = view.with_confirmations(confirmations);
        }

        // 金额语义在多输入输出下不适用，完整明细放在 extra 里由调用方自行计算。

        // `Vec<_>`：让编译器根据 `collect()` 的上下文推断元素类型
        //（这里是 `serde_json::Value`）。写成 `Vec<_>` 比写全类型更省事且不易过时。
        let inputs: Vec<_> = v
            .inputs
            .iter()
            // `json!` 里可以直接嵌 `Option`：
            // `None` 会序列化成 JSON 的 `null`，不会报错。
            .map(|i| {
                json!({
                    "txid": i.txid,
                    "vout": i.vout,
                    "value": i.value,
                    "address": i.address,
                    "script_type": i.script_type,
                    // coinbase 输入（矿工挖矿所得）没有前序 UTXO，
                    // 它的 txid 全为 0，需要单独标记。
                    "coinbase": i.coinbase,
                })
            })
            .collect();
        let outputs: Vec<_> = v
            .outputs
            .iter()
            .map(|o| {
                json!({
                    "index": o.index,
                    "value": o.value,
                    "address": o.address,
                    "script_type": o.script_type,
                })
            })
            .collect();

        Ok(view.with_extra(json!({
            "size": v.size,
            "weight": v.weight,
            // vsize = ceil(weight / 4)，是估算手续费时真正使用的计量单位。
            "vsize": v.vsize,
            "version": v.version,
            "locktime": v.locktime,
            "inputs": inputs,
            "outputs": outputs,
        })))
    }

    /// **无私钥**构造转账：拉 UTXO → 选币 → 搭模板 → 逐输入算 sighash → 交回调用方。
    ///
    /// BTC 只提供**两段式**：本方法是第一段，SDK 只负责构造，
    /// 签名交给调用方（agent）用自己的私钥做，私钥从不进入本进程。
    ///
    /// 为什么没有一体式 `transfer`：它要求把私钥传进 SDK，
    /// 而一旦 SDK 也能签名，就存在两套独立的签名实现——两处对 sighash 的理解
    /// 一旦漂移，只会在广播时被节点拒绝，本地不报任何错。
    /// ⚠️ **BTC 与其它链最大的不同：待签对象有多个。**
    /// UTXO 模型下每个输入各有一个 sighash，N 个输入就是 N 个签名。
    /// `signing_payload_hex` 只装得下第一个（保持契约字段不空），
    /// 完整列表在 `extra.signing_payloads` 里，**签名顺序必须与它一致**。
    ///
    /// 领域说明——为什么 BTC **必须**给 `public_key`：
    /// P2WPKH 的见证里要显式放公钥（BTC 不用可恢复签名），
    /// 而公钥无法从地址反推（地址是公钥的哈希）。
    /// 这与 ETH 不同——ETH 的签名带 recovery id，节点能自己恢复出公钥。
    async fn build_transfer(&self, req: BuildTransferRequest) -> Result<BuildTransferView, SdkError> {
        let network = self.chain.network().network();
        let to = parse_checked_address(&req.to, network)?;
        // 金额统一解析成 satoshi（1 BTC = 1e8 sat）。
        let amount_sat = crate::units::parse_amount(&req.amount)
            .map_err(|e| SdkError::invalid_argument(format!("非法金额: {e}")))?;

        // BTC 一定要公钥：见证/scriptSig 里要放它，且地址由它派生。
        let public_key = req.public_key.as_deref().ok_or_else(|| {
            SdkError::invalid_argument(
                "BTC 的 build_transfer 必须提供 public_key（33 字节压缩公钥的十六进制）：\
                 P2WPKH 的见证需要显式携带公钥，而公钥无法从地址反推",
            )
        })?;
        let public_key = crate::tx::parse_public_key(public_key)
            .map_err(|e| SdkError::invalid_argument(format!("非法 BTC 公钥: {e}")))?;

        // 校验 `from` 与公钥派生出的地址一致。
        //
        // 这条校验是**有意义的**：无私钥就无法证明调用方拥有该地址，
        // 但「给的地址和给的公钥对不上」是能立刻发现的输入错误。
        // 两者不匹配时通常是用错了钱包（同一助记词下的另一个账户）。
        let addresses = crate::tx::key_addresses(&public_key, network);
        let expected = [addresses.p2wpkh.to_string(), addresses.p2pkh.to_string()];
        if !expected.iter().any(|a| a == req.from.trim()) {
            return Err(SdkError::invalid_argument(format!(
                "from({}) 与该公钥派生的地址都不匹配（p2wpkh={}，p2pkh={}）",
                req.from, addresses.p2wpkh, addresses.p2pkh
            )));
        }

        // 费率向数据源要推荐值；未取到时后台内部会退回缺省常量。
        let fee_rate = crate::tx::current_fee_rate(&self.chain).await;
        let built = crate::tx::assemble_unsigned(
            &self.chain,
            &public_key,
            &crate::tx::UnsignedRequest {
                public_key,
                to,
                amount_sat,
                fee_rate,
                // 两段式默认开启 RBF：构造与广播之间可能隔很久，
                // 费率行情会变，留一条「加价替换」的后路比不可替换更安全。
                rbf: true,
            },
        )
        .await
        .map_err(|e| self.fail("构造未签名转账失败", e))?;

        // 待签对象数组：顺序即签名的顺序。
        let payloads: Vec<_> = built
            .signing_payloads
            .iter()
            .map(|p| {
                json!({
                    "index": p.index,
                    "txid": p.txid,
                    "vout": p.vout,
                    "value_sat": p.value,
                    "script_type": p.script_type,
                    // 带 0x 前缀，`signing_payload_hex` 同款格式。
                    "sighash": format!("0x{}", p.sighash),
                })
            })
            .collect();
        let signature_count = payloads.len();
        // `signing_payload_hex` 是契约里的单值字段，装不下 N 个哈希。
        // 取第 0 个填入以保证字段非空可签，完整列表请看 `extra.signing_payloads`。
        let first_payload = built
            .signing_payloads
            .first()
            .map(|p| format!("0x{}", p.sighash))
            .unwrap_or_default();

        let inputs: Vec<_> = built
            .inputs
            .iter()
            .map(|i| {
                json!({
                    "txid": i.txid,
                    "vout": i.vout,
                    "value_sat": i.value,
                    "confirmed": i.confirmed,
                })
            })
            .collect();

        Ok(BuildTransferView::new(
            ChainKind::Btc,
            &self.network,
            req.from,
            req.to,
            built.amount_sat as u128,
            built.unsigned_tx_hex,
            first_payload,
            // 签名曲线。
            "secp256k1",
            // payload **已经是**最终摘要（双 SHA256 的结果），不要再哈希。
            "none",
        )
        .with_extra(json!({
            // —— 这里是真正要用的待签清单 ——
            "signing_payloads": payloads,
            "signature_count": signature_count,
            // 签名格式：**64 字节紧凑格式**（r||s）的十六进制，不是 DER。
            "signature_encoding": "compact-rs-hex",
            // payload 是怎么算出来的（信息性字段）。
            "sighash_algorithm": "sha256d",
            "sighash_type": "SIGHASH_ALL",
            // —— 广播阶段要原样回传 ——
            "submit_context": built.context,
            "public_key": hexutil::encode_hex(&public_key.to_bytes()),
            // —— 费用与找零 ——
            "fee_sat": built.fee,
            "fee_rate_sat_vb": built.fee_rate,
            "vsize_estimate": built.vsize_estimate,
            "change_sat": built.change,
            "change_address": built.change_address,
            "rbf": true,
            "inputs": inputs,
            // —— 调用方指引 ——
            "splice": "not_byte_splicable__pass_signatures_and_submit_context_to_submit_tx",
            "note": "BTC 每个输入各有一个 sighash：请按 signing_payloads 的顺序逐个用 secp256k1 \
                     签出 64 字节（r||s）签名，放进 SubmitRequest.signatures 数组，\
                     并把本响应里的 submit_context 放进 SubmitRequest.context，再调用 submit_tx。\
                     signed_tx_hex 在 BTC 上不使用（留空即可）。",
            "next": "submit_tx",
        })))
    }

    /// 广播已签名交易。BTC 收的是**签名数组 + 上下文**，不是拼好的交易字节。
    ///
    /// 领域说明——为什么不能像 ETH 那样直接收一段字节：
    /// 让 agent 自己拼 BTC 交易，要同时搞对 DER 编码、低 S 归一化、
    /// 见证与 scriptSig 的结构差异。任一处出错，产出的是
    /// **格式合法但语义错误**的交易：本地一切正常，广播才被节点拒。
    /// 所以这里只收签名，由 SDK 重组，并在广播前**逐个验签**。
    ///
    /// 参数约定：
    /// - `signatures`：**按 `signing_payloads` 顺序**排列的 64 字节紧凑签名（十六进制）；
    /// - `context`：`build_transfer` 下发的 `extra.submit_context`，原样回传；
    /// - `signed_tx_hex`：BTC **不使用**（设为 `""` 即可）——最终交易由 SDK 组装。
    async fn submit_tx(&self, req: SubmitRequest) -> Result<SubmitView, SdkError> {
        let encoding = req
            .encoding
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("hex");
        if encoding != "hex" {
            return Err(SdkError::invalid_argument(format!(
                "BTC 签名只接受 hex 编码，收到 {encoding}"
            )));
        }

        let context_value = req.context.ok_or_else(|| {
            SdkError::invalid_argument(
                "BTC 广播必须回传 build_transfer 下发的 extra.submit_context：\
                 交易的输入金额与脚本类型不在交易字节里，缺了它无法重算 sighash",
            )
        })?;
        let context: crate::tx::SubmitContext = serde_json::from_value(context_value)
            .map_err(|e| SdkError::invalid_argument(format!("submit_context 解析失败: {e}")))?;

        // 跨网护栏：拿主网构造的上下文去测试网广播，地址编码不同，
        // 广播出去的钱会打到另一个网络上——这一步必须在**广播前**拦住。
        if context.network != self.network {
            return Err(SdkError::invalid_argument(format!(
                "网络不匹配：该上下文是在 {} 构造的，当前客户端是 {}",
                context.network, self.network
            )));
        }

        let raw_signatures = req.signatures.ok_or_else(|| {
            SdkError::invalid_argument(
                "BTC 广播需要 signatures 数组：每个输入一个 64 字节紧凑签名，\
                 顺序与 build_transfer 下发的 signing_payloads 一致",
            )
        })?;
        let signatures = raw_signatures
            .iter()
            // 闭包而非直接传函数指针：`decode_hex` 收 `&str`，
            // 而 `iter()` 给的是 `&String`，需要一次解引用强制转换。
            .map(|s| hexutil::decode_hex(s))
            .collect::<Result<Vec<_>, SdkError>>()
            .map_err(|e| SdkError::invalid_argument(format!("签名不是合法十六进制: {e}")))?;

        // 重组（内部会重建交易 + 逐个验签 + 上下文自检）。
        let signed = crate::tx::assemble_signed(&context, &signatures)
            .map_err(|e| SdkError::invalid_argument(format!("组装已签名交易失败: {e}")))?;
        let (raw_hex, txid) = crate::tx::finalize(&signed);

        // 广播是唯一**不可逆**的操作，前面所有校验都是为了走到这里时已万无一失。
        let broadcast_txid = self
            .chain
            .broadcast(&raw_hex)
            .await
            .map_err(|e| self.fail("广播交易失败", e))?;

        Ok(SubmitView::new(ChainKind::Btc, &self.network, txid.clone()).with_extra(json!({
            "broadcast": true,
            // 节点返回的 txid 应与本地算出的一致；不一致说明数据源做了非预期处理。
            "node_txid": broadcast_txid,
            "txid_matches_local": broadcast_txid == txid,
            "input_count": context.inputs.len(),
            "signature_count": signatures.len(),
            // 实测体积（签名后），可用于回核对账。
            "vsize": signed.vsize(),
            "raw_tx": raw_hex,
        })))
    }

    /// 由公钥派生 BTC 地址。
    ///
    /// 领域说明：BTC 与 ETH 的派生方式**完全不同**——
    ///   - ETH：`address = keccak256(未压缩公钥后 64 字节)[12..32]`，一种脚本类型；
    ///   - BTC：先 `hash160(= ripemd160(sha256(pubkey)))`，
    ///     再按脚本类型编码成不同地址：`p2wpkh`(bc1q) / `p2pkh`(1…) /
    ///     `p2sh-p2wpkh`(3…) / `p2tr`(bc1p)。
    /// 同一个公钥会派生出**四个互不相同**的地址，它们都能收到币，
    /// 所以这里把主地址定为 p2wpkh，其余放进 `alternatives` 供参考。
    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        // 先做十六进制解码。`?` 自动把 `SdkError` 向上传播——
        // `hexutil::decode_hex` 返回的正是契约层的错误类型，无需转换。
        let raw = hexutil::decode_hex(pubkey)?;
        let pk = PublicKey::from_slice(&raw).map_err(|e| {
            SdkError::invalid_argument(format!(
                // 错误消息里把「合法长什么样」写清楚，
                // 比只说"非法公钥"能省下用户一轮排查。
                "非法 BTC 公钥（{e}）：需为 33 字节压缩格式（02/03 开头）或 65 字节未压缩格式的十六进制"
            ))
        })?;
        // 压缩公钥（33 字节：`02/03` 前缀 + X 坐标）是所有隔离见证地址的基础。
        // 未压缩公钥（65 字节：`04` + X + Y）在这里会被拒绝。
        let compressed = CompressedPublicKey::try_from(pk).map_err(|_| {
            SdkError::invalid_argument(
                // 行尾的 `\` 是 Rust 的**续行转义**：
                // 它会连同后面的换行与缩进一起吃掉，让长字符串能折行书写而不引入空白。
                "BTC 需要压缩公钥（33 字节，02/03 开头）才能派生隔离见证地址；\
                 未压缩公钥请先压缩，或改用 P2PKH"
                    .to_string(),
            )
        })?;

        let network: Network = self.chain.network().network();
        // 创建一次 secp256k1 上下文供 Taproot 派生使用。
        let secp = Secp256k1::new();
        let compressed_bytes = compressed.to_bytes();
        let p2wpkh = Address::p2wpkh(&compressed, network);

        Ok(AddressView::new(
            ChainKind::Btc,
            &self.network,
            // 回显**压缩后**的公钥字节，让调用方知道实际用的是哪个。
            hexutil::encode_hex(&compressed_bytes),
            p2wpkh.to_string(),
            // 脚本类型标签：跨链统一用字符串而非枚举，方便新增链。
            "p2wpkh",
            compressed_bytes.len(),
        )
        .with_extra(json!({
            // 把派生路径写进 extra，作为可读的"自文档"。
            "derivation": "hash160(compressed_pubkey) -> bech32/base58check",
        }))
        .with_alternatives(json!({
            // P2PKH：`1` 开头，base58check 编码，用**未压缩**公钥的 hash160
            // （注意 `pk.pubkey_hash()` 对未压缩/压缩公钥会给出不同的哈希）。
            "p2pkh": Address::p2pkh(pk.pubkey_hash(), network).to_string(),
            // P2SH-P2WPKH：`3` 开头，把 P2WPKH 脚本再包一层 P2SH，
            // 供不支持 bech32 的老钱包使用（兼容性方案）。
            "p2sh_p2wpkh": Address::p2shwpkh(&compressed, network).to_string(),
            // P2TR：`bc1p` 开头，bech32m 编码。
            // `compressed.0` 取出元组结构体内的 `secp256k1::PublicKey`；
            // 第三个参数 `None` 表示没有脚本树（只能密钥路径花费）。
            "p2tr": Address::p2tr(&secp, compressed.0.into(), None, network).to_string(),
        })))
    }
}

// `#[cfg(test)]` 是**条件编译属性**：`mod tests` 只在 `cargo test` 时存在，
// 正式构建会被完全剔除（不占体积、不拖慢编译）。
// `use super::*` 把父模块的所有可见项（含私有项）导入本作用域，
// 于是可以直接调 `derive`、`hexutil` 等，无需再写 `crate::` 前缀。
#[cfg(test)]
mod tests {
    use super::*;

    // 私钥 0x0000...0001 对应的压缩公钥（bitcoin 测试向量）。
    //
    // 这个点其实就是 secp256k1 的**生成元 G**（私钥 = 1），
    // 是密码学库里最经典的测试向量，各语言实现都会用它交叉验证。
    const COMPRESSED: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    // 同一个公钥的未压缩形式：`04` 前缀 + X 坐标 + Y 坐标 = 65 字节。
    const UNCOMPRESSED: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    /// 复刻 `address_from_pubkey` 的派生逻辑，但**不依赖网络数据源**。
    ///
    /// 这样测试只验证"纯派生算法"，不需要起服务或连索引器——
    /// 单元测试应当快且确定，能不碰 IO 就不碰。
    fn derive(hex_pubkey: &str, network: Network) -> Result<AddressView, SdkError> {
        let raw = hexutil::decode_hex(hex_pubkey)?;
        let pk =
            PublicKey::from_slice(&raw).map_err(|e| SdkError::invalid_argument(e.to_string()))?;
        // 压缩公钥是隔离见证地址的前提；未压缩输入会在这里被挡下。
        let compressed = CompressedPublicKey::try_from(pk)
            .map_err(|_| SdkError::invalid_argument("需要压缩公钥"))?;
        let secp = Secp256k1::new();
        let bytes = compressed.to_bytes();
        Ok(AddressView::new(
            ChainKind::Btc,
            // 这里硬编码了 "mainnet"：该字段只是随结果回显的标签，
            // 不影响派生算法（真正的网络由下面 `network` 参数决定）。
            "mainnet",
            hexutil::encode_hex(&bytes),
            Address::p2wpkh(&compressed, network).to_string(),
            "p2wpkh",
            bytes.len(),
        )
        .with_alternatives(json!({
            "p2pkh": Address::p2pkh(pk.pubkey_hash(), network).to_string(),
            "p2tr": Address::p2tr(&secp, compressed.0.into(), None, network).to_string(),
        })))
    }

    /// 与公开测试向量逐一比对，防止依赖库升级后派生结果静默改变。
    #[test]
    fn derives_known_mainnet_addresses() {
        let view = derive(COMPRESSED, Network::Bitcoin).unwrap();
        // 生成器点 G 的 P2WPKH 地址（mempool.space / bitcoin 库一致的输出）。
        assert_eq!(view.address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        // `with_alternatives` 把内容塞进了 `extra` 的 "alternatives" 键下，
        // 所以要从 `view.extra` 这个 `serde_json::Value` 里再取一层。
        let alt = view.extra.get("alternatives").unwrap();
        // `Value` 实现了 `Index<&str>`：键不存在时返回 `Value::Null`
        //（而不是 panic），所以这里能直接下标访问。
        assert_eq!(alt["p2pkh"], "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    /// 同一把公钥在不同网络下的地址完全不同，这是**防跨网误转账**的关键。
    #[test]
    fn testnet_uses_tb1_prefix() {
        let view = derive(COMPRESSED, Network::Testnet).unwrap();
        // 主网是 `bc1q`，测试网是 `tb1q`——前缀里就带了网络标识（bech32 的 hrp）。
        assert!(view.address.starts_with("tb1q"));
    }

    /// 非法输入必须报错而不是产出错误地址。
    #[test]
    fn rejects_uncompressed_and_garbage() {
        // 65 字节未压缩公钥：能解析成 `PublicKey`，但压不进隔离见证地址。
        assert!(derive(UNCOMPRESSED, Network::Bitcoin).is_err());
        // 长度不足（3 字节）的乱码：`PublicKey::from_slice` 直接失败。
        assert!(derive("02abcd", Network::Bitcoin).is_err());
    }

    /// 回归测试：`fail` 必须保留 anyhow 的**整条错误链**，而不只是最外层上下文。
    ///
    /// 领域说明：BTC 适配器普遍用 `anyhow::Context` 给底层 IO 错误套中文上下文
    ///（形如「查询 xx 地址的 UTXO 失败」）。但 `anyhow::Error` 的 `Display` 实现
    /// **只打印最外层那一句**，真正有价值的根因（"connection refused"、
    /// "timed out"、HTTP 状态码）藏在 `source()` 链里。
    /// 旧实现 `format!("{context}: {err}")` 恰好只触发 `Display`，于是根因被丢掉：
    /// 运维只看到「查询 UTXO 失败」，看不出是网络不通还是参数错。
    /// 更隐蔽的危害是——`classify` 靠关键词分类，根因丢失会让它把
    /// 网络故障误判成兜底的 `RpcError`，调用方的重试策略随之失真。
    ///
    /// 语法说明：
    /// - `anyhow::Context` trait 给 `Result` 和 `Option` 都做了实现，
    ///   所以要先造一个 `Result` 才能链式调用 `.context(..)`；
    ///   这里用 `Err::<(), _>(root)` 的** turbofish **指定 Ok 类型是 `()`。
    /// - `unwrap_err()` 在 `Result` 上取出 `E`；因为 `T = ()` 无意义，语义上正好。
    #[test]
    fn fail_keeps_the_root_cause_of_a_nested_anyhow_error() {
        use allchain_core::ErrorCode;
        use anyhow::Context;

        // 造一条「两层」错误：外层中文上下文 + 内层英文根因，复刻真实调用形态。
        let root = anyhow::anyhow!("connection refused (os error 61)");
        let err = Err::<(), _>(root)
            .context("查询 xxx 地址的 UTXO 失败")
            .unwrap_err();

        let sdk = fail("查询地址失败", err);

        // 上下文要保留，否则日志失去可读性。
        assert!(
            sdk.message.contains("查询地址失败"),
            "外层上下文丢了: {}",
            sdk.message
        );
        assert!(
            sdk.message.contains("查询 xxx 地址的 UTXO 失败"),
            "内层上下文丢了: {}",
            sdk.message
        );
        // 最关键的一条：根因必须透出。
        assert!(
            sdk.message.contains("connection refused"),
            "根因被丢掉了: {sdk:?}"
        );
        // 根因关键词必须能驱动分类——这里应判为网络错误，而不是兜底的 RpcError。
        assert_eq!(sdk.code, ErrorCode::NetworkError, "message = {}", sdk.message);
    }

    /// 上一条测试的**反证**：若 `classify` 只看得到外层中文上下文，
    /// 它落到的错误码必然不是 `NetworkError`。
    ///
    /// 没有这条断言，上一条测试可能因为「classify 恰好兜底成 RpcError 也说得通」
    /// 而变成一个恒真断言——反证用来确认「根因确实参与了分类」。
    #[test]
    fn classifying_only_the_outer_context_would_misjudge_the_code() {
        use allchain_core::ErrorCode;

        let only_outer = allchain_core::error::classify("查询地址失败: 查询 UTXO 失败");
        assert_ne!(only_outer.code, ErrorCode::NetworkError);
    }
}
