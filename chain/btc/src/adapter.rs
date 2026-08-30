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
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, SdkError, StatusView,
    TransferRequest, TransferView, TxStatus, TxView, hexutil,
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
    fn fail(&self, context: &str, err: impl std::fmt::Display) -> SdkError {
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

/// 把任意错误附加上中文上下文，再交给 `classify` 归类成 `SdkError`。
///
/// 领域说明：`classify` 会扫描错误文本里的关键词
/// （如 `timeout` / `connection refused` / `404`）
/// 映射成 `ErrorCode::Network` / `Rpc` / `NotFound` 等，
/// 所以**上下文文案必须保留原始错误**，否则分类会失准。
///
/// 语法说明：`impl std::fmt::Display` 是**参数位置的 impl Trait**：
/// 泛型 + 静态分发，任何实现了 `Display` 的类型都能传进来，
/// 比写成 `&dyn Display` 少一次动态分发，也比 `E: Display` 的写法更短。
fn fail(context: &str, err: impl std::fmt::Display) -> SdkError {
    allchain_core::error::classify(&format!("{context}: {err}"))
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

    /// 构造并（可选）广播一笔转账。私钥只在本地参与签名，不出网。
    ///
    /// 语法说明：`req: TransferRequest` 是**按值**接收的。
    /// 契约层这样设计是为了让实现者可以自由决定：
    /// 直接消费字段（如末尾的 `req.to`），还是只借用。
    async fn transfer(&self, req: TransferRequest) -> Result<TransferView, SdkError> {
        // `self.chain.network()` 是 CLI 层的 `NetworkArg`，
        // 再 `.network()` 得到 rust-bitcoin 的 `Network`——两层同名方法的典型"拆解"。
        let network = self.chain.network().network();
        let to = req
            .to
            .trim()
            // turbofish 语法 `parse::<Address<NetworkUnchecked>>()`：
            // 在方法名上直接指定泛型参数，让编译器知道要解析成什么类型。
            .parse::<Address<NetworkUnchecked>>()
            // 这里丢弃了解析器的原始错误（`|e|` 都省了），
            // 改用统一的中文提示，避免把库内部的英文错误直接抛给用户。
            .map_err(|_| SdkError::invalid_argument(format!("非法 BTC 地址: {}", req.to)))?
            // **关键一步**：把「未校验网络的地址」升级成「已校验网络的地址」。
            // 若用户拿主网地址来测试网转账，这里就会报错，
            // 而不是等到广播时才被节点拒绝（那时钱可能已经打错网络了）。
            .require_network(network)
            .map_err(|e| SdkError::invalid_argument(format!("地址网络不匹配: {e}")))?;

        // 金额统一解析成 **satoshi**（1 BTC = 1e8 sat）。
        // 统一模型里 `amount` 是字符串，接受 "0.001" / "0.001btc" / "100000sat" 等多种写法。
        let amount_sat = crate::units::parse_amount(&req.amount)
            .map_err(|e| SdkError::invalid_argument(format!("非法金额: {e}")))?;

        // 走单链 CLI 同一套构造逻辑：选币 → 估费 → 本地签名。
        // 三个尾参依次是：费率（None = 向数据源问推荐值）、
        // legacy（false = 只花 P2WPKH 地址上的币）、rbf（false = 不可替换）。
        // 统一接口刻意不暴露这些细节，避免上层被链特有概念污染。
        let built = crate::transactions::build_transfer(
            &self.chain,
            &req.private_key,
            &to,
            amount_sat,
            None,
            false,
            false,
        )
        .await
        .map_err(|e| self.fail("构造签名转账失败", e))?;

        // dry-run 时不广播，直接返回本地算出的 txid。
        //
        // 语法说明：`if / else` 在 Rust 里是**表达式**，
        // 所以能直接把结果赋给 `txid`；两个分支类型必须相同（都是 `String`）。
        let txid = if req.dry_run {
            // `.clone()`：`built.txid` 后面还要在 `Ok(...)` 里再次用到？
            // 实际没有，但这里保留克隆以免与广播分支的所有权形态不一致。
            built.txid.clone()
        } else {
            // 广播是唯一的**不可逆**操作：进入网络后无法撤回。
            self.chain
                .broadcast(&built.raw_hex)
                .await
                .map_err(|e| self.fail("广播交易失败", e))?
        };

        let inputs: Vec<_> = built
            .inputs
            .iter()
            .map(|i| {
                json!({
                    "txid": i.txid,
                    "vout": i.vout,
                    "value": i.value,
                    "confirmed": i.confirmed,
                })
            })
            .collect();

        Ok(TransferView::new(
            ChainKind::Btc,
            &self.network,
            // `Some(built.from.clone())`：付款方地址由**私钥派生**得到，
            // 所以一定存在；但统一模型里它是 `Option<String>`，
            // 因为有些链（如某些合约调用）没有明确的单一付款账户。
            Some(built.from.clone()),
            // `req.to` 在这里被**移动**进构造器——原样回显用户输入，便于对账。
            req.to,
            amount_sat as u128,
            Some(txid),
            // 第五个参数是"是否已广播"，正好是 `dry_run` 的反义。
            !req.dry_run,
        )
        .with_extra(json!({
            // 手续费用 sat 计（BTC 的"最小可分割单位"），
            // 不用 BTC 小数，避免浮点精度问题。
            "fee_sat": built.fee,
            "fee_rate_sat_vb": built.fee_rate,
            "vsize": built.vsize,
            // 找零：0 表示剩余金额低于 dust 阈值，已并入手续费。
            "change_sat": built.change,
            "inputs": inputs,
            // raw_tx 让调用方可以自行广播或离线存档。
            "raw_tx": built.raw_hex,
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
}
