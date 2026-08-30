//! 链上数据源：Esplora 索引器与 bitcoind JSON-RPC 的统一视图。
//!
//! 地址类查询（余额 / UTXO）必须有索引器，统一走 Esplora；
//! 节点类查询（链状态 / 区块 / 交易 / 费率 / 广播）在配置了 bitcoind 时优先走 RPC。
//!
//! 设计取舍：**能力强的源优先，缺了就降级**。
//! 自建节点信息更全（能给出 headers、difficulty、mempool 明细等 Esplora 没有的字段），
//! 但绝大多数用户没有节点，所以每一类查询都写成
//! 「有节点就用节点，否则回退 Esplora」的两段式，由本模块统一消化这个差异，
//! 上层（adapter）完全不必感知数据来自哪边。
//!
//! ⚠️ 一个已知的实现瑕疵：`bitcoincore_rpc::Client` 是**阻塞式**的，
//! 而这里的公开方法都是 `async fn`。在 tokio 多线程运行时下直接 await 内部的
//! 阻塞调用会占住一个 worker 线程。CLI 场景（请求稀疏）下影响可忽略，
//! 高并发服务场景应改用 `tokio::task::spawn_blocking` 包一层。

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
// `RpcApi` 是 bitcoincore-rpc 的**方法集合 trait**——所有 `get_blockchain_info()`
// 这类方法都定义在它上面，必须先引入作用域才能调用。
use bitcoincore_rpc::{Auth, Client, RpcApi};

use crate::esplora::Esplora;
use crate::network::NetworkArg;

/// bitcoind 认证的两种来源。
///
/// 语法说明：这是一个**带数据的枚举**。Rust 的枚举变体可以携带数据，
/// 且不同变体携带的数据可以不同——这比「一个 struct + 一堆可选字段」更精确，
/// 因为不可能同时出现 user/pass 与 cookie 两种配置。
#[derive(Debug, Clone)]
pub enum NodeAuth {
    /// 用户名 + 密码（`rpcuser` / `rpcpassword`），适合远程节点。
    ///
    /// 语法说明：这是**结构体变体**，字段有名，写法与 struct 声明一致。
    UserPass { user: String, pass: String },
    /// Cookie 文件路径，bitcoind 的默认本地认证方式。
    ///
    /// 语法说明：这是**元组变体**，字段无名，靠位置访问。
    Cookie(PathBuf),
}

/// bitcoind JSON-RPC 连接配置。
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// JSON-RPC 端点（形如 `http://127.0.0.1:8332`）。
    pub url: String,
    /// 认证方式。
    pub auth: NodeAuth,
}

impl NodeConfig {
    /// 建立连接（bitcoind RPC 是阻塞式调用，CLI 场景下直接使用）。
    pub fn connect(&self) -> Result<Client> {
        // `match &self.auth`：**借用**枚举，于是分支里的 `user` / `pass` 是 `&String`。
        // 若写成 `match self.auth` 会把 auth 移出 `&self`（不允许），编译不过。
        let auth = match &self.auth {
            // 结构体变体的模式要写出字段名：`NodeAuth::UserPass { user, pass }`。
            // `user.clone()`：拿到的只是引用，而 `Auth::UserPass` 需要自有 String。
            NodeAuth::UserPass { user, pass } => Auth::UserPass(user.clone(), pass.clone()),
            // 元组变体的模式：`NodeAuth::Cookie(path)`，`path: &PathBuf`。
            NodeAuth::Cookie(path) => Auth::CookieFile(path.clone()),
        };
        // 注意：`Client::new` 只是**建立配置并校验 URL**，不发起网络连接，
        // 真正的连接发生在第一次 RPC 调用时。
        Client::new(&self.url, auth).with_context(|| format!("连接 bitcoind 失败: {}", self.url))
    }
}

/// 统一的链上数据源。
///
/// 持有 Esplora 客户端（必有）与可选的 bitcoind 配置，
/// 对外提供一组**不区分数据来源**的查询方法。
pub struct Chain {
    /// 当前网络，决定地址编码与默认端点。
    network: NetworkArg,
    /// 索引器客户端，地址类查询唯一可用的来源。
    esplora: Esplora,
    /// 可选的自建节点；为 `None` 时所有节点类查询回退 Esplora。
    node: Option<NodeConfig>,
}

impl Chain {
    /// 构造数据源。`node` 为 `None` 表示纯索引器模式。
    pub fn new(network: NetworkArg, esplora_url: &str, node: Option<NodeConfig>) -> Result<Self> {
        Ok(Self {
            network,
            esplora: Esplora::new(esplora_url)?,
            node,
        })
    }

    /// 当前网络。
    pub fn network(&self) -> NetworkArg {
        // `NetworkArg` 是 `Copy` 的，直接按值返回，调用方拿走的是副本。
        self.network
    }

    /// 节点类查询当前实际使用的数据源。
    ///
    /// 返回值是 `&'static str`：两个候选值都是编译期字面量，无需分配。
    pub fn source(&self) -> &'static str {
        // `Option::is_some()` 只判断有无，不移动内部值——
        // 与 `if let Some(..) = &self.node` 等价，但更短。
        if self.node.is_some() {
            "bitcoind"
        } else {
            "esplora"
        }
    }

    /// 节点类查询当前实际访问的端点。
    ///
    /// 返回 `String` 而非 `&str`，因为两个分支的来源不同
    /// （一个要 clone 配置里的 url，一个是 esplora 的借用），
    /// 统一成自有 String 最省事，也让调用方不必处理生命周期。
    pub fn endpoint(&self) -> String {
        match &self.node {
            // `.clone()`：配置需要长期保留，不能把 url 移出去。
            Some(node) => node.url.clone(),
            None => self.esplora.base_url().to_string(),
        }
    }
}

/// 链状态视图。
///
/// 字段大量使用 `Option`：两个数据源能力不对等——
/// bitcoind 能给出 headers / difficulty / mempool 明细，
/// Esplora 只给高度与哈希。用 `Option` 如实表达「该源给不出」，
/// 比填 0 或空串更诚实，也让上层能区分「确实是 0」与「没拿到」。
#[derive(Debug, Clone)]
pub struct StatusView {
    /// 数据来源：`bitcoind` 或 `esplora`。
    pub source: String,
    /// 实际访问的端点。
    pub endpoint: String,
    /// 链名（bitcoind 返回 `main` / `test` / `regtest`，Esplora 走网络短名）。
    pub chain: String,
    /// 已验证的最新区块高度。
    pub blocks: u64,
    /// 已收到的区块头高度；落后于 `blocks` 说明还在同步。
    pub headers: Option<u64>,
    /// 链尖区块哈希。
    pub best_block_hash: String,
    /// 当前挖矿难度（相对创世难度的倍数）。
    pub difficulty: Option<f64>,
    /// 同步进度（0.0 ~ 1.0）。
    pub verification_progress: Option<f64>,
    /// 是否仍在初始区块下载（IBD）阶段。
    pub initial_block_download: Option<bool>,
    /// 最近若干区块时间的**中位数**（防矿工篡改时间戳）。
    pub median_time: Option<u64>,
    /// 内存池中的交易笔数。
    pub mempool_txs: Option<u64>,
    /// 内存池占用的字节数。
    pub mempool_bytes: Option<u64>,
}

/// 区块视图。
///
/// 语法说明：`#[allow(dead_code)]` 抑制「字段从未被读取」警告。
/// 这些字段会在 JSON 序列化 / 打印时用到，但编译器看不到跨模块的使用，
/// 因此显式声明「我知道它们暂时没被读，是有意保留的」。
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BlockView {
    /// 区块哈希。
    pub hash: String,
    /// 区块高度。
    pub height: u64,
    /// 出块时间（Unix 秒）。
    pub timestamp: u64,
    /// 区块内交易数。
    pub tx_count: u64,
    /// 序列化字节数。
    pub size: Option<u64>,
    /// 权重（WU）。
    pub weight: Option<u64>,
    /// Merkle 根，所有交易的哈希汇总。
    pub merkle_root: Option<String>,
    /// 父区块哈希。
    pub prev_hash: Option<String>,
    /// 子区块哈希；链尖区块没有。
    pub next_hash: Option<String>,
    /// PoW 尝试出的随机数。
    pub nonce: Option<u64>,
    /// 难度目标的紧凑表示（十六进制字符串）。
    pub bits: Option<String>,
    /// 该区块的难度值。
    pub difficulty: Option<f64>,
    /// 前 11 个区块时间的中位数。
    pub median_time: Option<u64>,
    /// 确认数；1 表示刚入块。
    pub confirmations: Option<u64>,
}

/// 交易输入视图。
#[derive(Debug, Clone)]
pub struct TxInView {
    /// 被花费的那笔交易的 txid；coinbase 输入填 `"coinbase"`。
    pub txid: String,
    /// 被花费的是那笔交易的第几个输出。
    pub vout: u32,
    /// 该输入的金额（satoshi）。需要回溯上一笔交易，拿不到时为 `None`。
    pub value: Option<u64>,
    /// 该输入对应的地址；非标准脚本或拿不到时为 `None`。
    pub address: Option<String>,
    /// 脚本类型：`p2wpkh` / `p2pkh` / `v0_p2wsh` 等。
    pub script_type: Option<String>,
    /// 是否为 coinbase 输入（即挖矿奖励，凭空造币）。
    pub coinbase: bool,
}

/// 交易输出视图。
#[derive(Debug, Clone)]
pub struct TxOutView {
    /// 输出序号（从 0 开始）。
    pub index: u32,
    /// 金额（satoshi）。
    pub value: u64,
    /// 收款地址；非标准脚本（如 OP_RETURN）时为 `None`。
    pub address: Option<String>,
    /// 脚本类型。
    pub script_type: Option<String>,
}

/// 交易视图。
///
/// ⚠️ 领域说明：**BTC 交易没有单一的「金额」语义**。
/// 一笔交易可以有多个输入与多个输出（收款 + 找零），
/// 所以本结构刻意不设 `amount` 字段——
/// 调用方要拿「转了多少钱」得自己按语义从 `outputs` 里挑。
#[derive(Debug, Clone)]
pub struct TxView {
    /// 交易 ID（对**非见证数据**做两次 SHA256 的结果）。
    pub txid: String,
    /// 版本号。1 = 传统，2 = 支持相对时间锁。
    pub version: i64,
    /// 绝对时间锁；0 表示立即可入块。
    pub locktime: u64,
    /// 序列化字节数。
    pub size: Option<u64>,
    /// 权重（WU）。
    pub weight: Option<u64>,
    /// 虚拟字节数（vB），手续费结算单位。
    pub vsize: Option<u64>,
    /// 手续费（satoshi）= 输入总额 − 输出总额。
    pub fee: Option<u64>,
    /// 是否已入块。
    pub confirmed: bool,
    /// 所在区块高度。
    pub block_height: Option<u64>,
    /// 所在区块哈希。
    pub block_hash: Option<String>,
    /// 出块时间（Unix 秒）。
    pub block_time: Option<u64>,
    /// 确认数。
    pub confirmations: Option<u64>,
    pub inputs: Vec<TxInView>,
    pub outputs: Vec<TxOutView>,
}

/// UTXO 视图。
///
/// 领域说明：**UTXO（未花费交易输出）** 是 BTC 账本的基本单位。
/// 钱包里并没有「余额」这个东西，所谓余额 = 该地址名下所有 UTXO 金额之和。
/// 花一笔钱 = 挑若干 UTXO 整体花掉，差额作为找零回到自己地址。
#[derive(Debug, Clone)]
pub struct UtxoView {
    /// 产生该输出的交易 ID。
    pub txid: String,
    /// 该输出在交易中的序号。`txid + vout` 唯一确定一个 UTXO。
    pub vout: u32,
    /// 金额（satoshi）。
    pub value: u64,
    /// 是否已入块；false 表示还在内存池。
    pub confirmed: bool,
    /// 入块高度。
    pub block_height: Option<u64>,
    /// 入块时间（Unix 秒）。
    pub block_time: Option<u64>,
}

/// 地址视图。
#[derive(Debug, Clone)]
pub struct AddressView {
    /// 地址字符串。
    pub address: String,
    /// 已确认余额（satoshi）= 已确认收入 − 已确认支出。
    pub confirmed_balance: u64,
    /// 未确认变动（正数为待入账，负数为待支出）。
    ///
    /// 用 `i64` 而非 `u64`：待支出时这个值为负，无符号类型表达不了。
    pub unconfirmed_balance: i64,
    /// 涉及该地址的交易总数（已确认 + 内存池）。
    pub tx_count: u64,
    /// 曾收到的 UTXO 总数。
    pub funded_txo_count: u64,
    /// 已花掉的 UTXO 总数。
    pub spent_txo_count: u64,
    /// 累计收到总额（satoshi）。
    pub total_received: u64,
    /// 累计支出总额（satoshi）。
    pub total_sent: u64,
}

impl Chain {
    /// 链状态：优先 bitcoind，回退 Esplora。
    pub async fn status(&self) -> Result<StatusView> {
        // `if let Some(node) = &self.node`：**借用**配置，因此 `node` 可反复使用。
        if let Some(node) = &self.node {
            let client = node.connect()?;
            let info = client
                .get_blockchain_info()
                .context("getblockchaininfo 失败")?;
            // 内存池信息不是关键路径，查不到就降级为 None 而不是整体失败。
            // `.ok()` 把 `Result<T, E>` 转成 `Option<T>`，丢弃错误详情。
            let mempool = client.get_mempool_info().ok();
            return Ok(StatusView {
                source: "bitcoind".to_string(),
                endpoint: node.url.clone(),
                // `{:?}` 用 `Debug` 打印 `bitcoin::Network` 之类的枚举，
                // 得到 "main" / "test" 这样的名字。
                chain: format!("{:?}", info.chain),
                blocks: info.blocks,
                headers: Some(info.headers),
                best_block_hash: info.best_block_hash.to_string(),
                difficulty: Some(info.difficulty),
                verification_progress: Some(info.verification_progress),
                initial_block_download: Some(info.initial_block_download),
                median_time: Some(info.median_time),
                // `mempool.as_ref()` 借出 `Option<&MempoolInfo>`，
                // 避免把 `mempool` 移进闭包导致后面再用时报错。
                mempool_txs: mempool.as_ref().map(|m| m.size as u64),
                mempool_bytes: mempool.as_ref().map(|m| m.bytes as u64),
            });
        }

        // 回退 Esplora：两个请求互不依赖，用 `try_join!` **并发**发出，
        // 省的往返时间约等于一次请求。任一失败则整体提前返回错误。
        let (height, hash) = tokio::try_join!(self.esplora.tip_height(), self.esplora.tip_hash())?;
        Ok(StatusView {
            source: "esplora".to_string(),
            endpoint: self.esplora.base_url().to_string(),
            chain: self.network.as_str().to_string(),
            blocks: height,
            // 以下几项 Esplora 提供不了，如实置 None。
            headers: None,
            best_block_hash: hash,
            difficulty: None,
            verification_progress: None,
            initial_block_download: None,
            median_time: None,
            mempool_txs: None,
            mempool_bytes: None,
        })
    }

    /// 区块查询：可传区块高度或哈希，缺省取链尖。
    pub async fn block(&self, reference: Option<&str>) -> Result<BlockView> {
        // 归一化：`None`、空串、纯空格一律视为「取链尖」。
        let reference = reference.map(str::trim).filter(|s| !s.is_empty());

        if let Some(node) = &self.node {
            let client = node.connect()?;
            let hash = match reference {
                // 没给引用 → 取链尖。
                None => client
                    .get_best_block_hash()
                    .context("getbestblockhash 失败")?,
                // **守卫分支**：纯数字视为高度，需要先用 `getblockhash` 换算成哈希。
                Some(r) if is_height(r) => {
                    let height: u64 = r.parse().context("区块高度超出范围")?;
                    client
                        .get_block_hash(height)
                        .with_context(|| format!("getblockhash {height} 失败"))?
                }
                // 否则按哈希解析。
                Some(r) => r
                    .parse()
                    .map_err(|e| anyhow::anyhow!("非法区块哈希 {r}: {e}"))?,
            };
            let block = client
                .get_block_info(&hash)
                .with_context(|| format!("getblock {hash} 失败"))?;
            return Ok(BlockView {
                hash: block.hash.to_string(),
                // bitcoind 的 height / time / nTx 是有符号或不同宽度，统一转成 u64。
                height: block.height as u64,
                timestamp: block.time as u64,
                tx_count: block.n_tx as u64,
                size: Some(block.size as u64),
                weight: Some(block.weight as u64),
                merkle_root: Some(block.merkleroot.to_string()),
                // `Option::map(闭包)`：有值才变换，为 None 保持 None。
                prev_hash: block.previousblockhash.map(|h| h.to_string()),
                next_hash: block.nextblockhash.map(|h| h.to_string()),
                nonce: Some(block.nonce as u64),
                bits: Some(block.bits),
                difficulty: Some(block.difficulty),
                median_time: block.mediantime.map(|t| t as u64),
                // `confirmations` 在 bitcoind 里是 i32，未确认时可能为 -1，
                // 用 `.max(0)` 夹到 0 再转 u64，避免负值回绕成天文数字。
                confirmations: Some(block.confirmations.max(0) as u64),
            });
        }

        // 回退 Esplora。
        let hash = match reference {
            None => self.esplora.tip_hash().await?,
            Some(r) if is_height(r) => {
                let height: u64 = r.parse().context("区块高度超出范围")?;
                self.esplora.block_hash_at(height).await?
            }
            // Esplora 直接用哈希，不必本地解析校验——服务端会拒绝非法的。
            Some(r) => r.to_string(),
        };
        let block = self.esplora.block(&hash).await?;
        // 确认数 = 当前高度 − 该区块高度 + 1。取不到链尖就放弃填这一项。
        let tip = self.esplora.tip_height().await.ok();
        Ok(BlockView {
            hash: block.id,
            height: block.height,
            timestamp: block.timestamp,
            tx_count: block.tx_count,
            size: block.size,
            weight: block.weight,
            merkle_root: block.merkle_root,
            prev_hash: block.previousblockhash,
            // Esplora 不提供「下一个区块」，故恒为 None。
            next_hash: None,
            nonce: block.nonce,
            // Esplora 的 bits 是整数，这里格式化成比特币惯用的 4 字节十六进制。
            bits: block.bits.map(|b| format!("{b:08x}")),
            difficulty: block.difficulty,
            median_time: block.median_time,
            // `saturating_sub`：**饱和减法**，下溢时停在 0 而不是 panic / 回绕。
            // 理论上 tip 不会小于 block.height，但保险起见用它。
            confirmations: tip.map(|tip| tip.saturating_sub(block.height) + 1),
        })
    }

    /// 交易查询：优先 bitcoind（详尽模式），回退 Esplora。
    ///
    /// 领域说明：bitcoind 的 `getrawtransaction` 默认**只查内存池与未花费输出**，
    /// 想查任意历史交易必须在节点上开启 `txindex=1`。
    /// 这也是「为什么需要索引器」的另一个例证。
    pub async fn tx(&self, txid: &str) -> Result<TxView> {
        // 先本地解析 txid：格式不对就没必要发请求。
        // 注意这里发生了**遮蔽**（shadowing）：新的 `txid` 是 `bitcoin::Txid` 类型，
        // 与外层的 `&str` 参数同名但类型不同——这正是遮蔽带来的便利。
        let txid: bitcoin::Txid = txid
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("非法交易哈希 {txid}: {e}"))?;

        if let Some(node) = &self.node {
            let client = node.connect()?;
            let info = client
                // 第二个参数是区块哈希（给了就能查未开 txindex 的节点），这里给 None。
                .get_raw_transaction_info(&txid, None)
                .with_context(|| format!("getrawtransaction {txid} 失败"))?;

            // `Vec::with_capacity(n)` 预分配容量：已知元素个数，
            // 避免 push 过程中多次扩容搬迁。
            let mut inputs = Vec::with_capacity(info.vin.len());
            // 用 `Option<u64>` 表示「输入总额」：一旦遇到查不到金额的输入，
            // 就整体置 None——因为手续费 = 输入总额 − 输出总额，
            // 缺一项就算不出可信的结果，宁可不给也不要给错的。
            let mut input_sum: Option<u64> = Some(0);
            // `&info.vin` 借用遍历，不动 `info` 的所有权（下面还要用 `info.vout`）。
            for vin in &info.vin {
                // 对**元组** `(Option<Txid>, Option<u32>)` 做模式匹配：
                // 两个都是 Some 才继续，否则视为 coinbase 输入。
                let (txid_in, vout) = match (vin.txid, vin.vout) {
                    (Some(t), Some(v)) => (t, v),
                    _ => {
                        inputs.push(TxInView {
                            txid: "coinbase".to_string(),
                            vout: 0,
                            value: None,
                            address: None,
                            script_type: None,
                            coinbase: true,
                        });
                        // coinbase 是凭空造的币，没有上游金额，总额从此不可知。
                        input_sum = None;
                        // `continue` 跳过本次循环剩下的部分。
                        continue;
                    }
                };
                // 非 coinbase 输入需要回溯上一笔交易才能知道金额（节点需开启 txindex）。
                let value = prevout_value(&client, txid_in, vout);
                // 同时匹配「本次查到的金额」与「累加器当前状态」两个 Option。
                match (value, &mut input_sum) {
                    // `*sum += v`：`sum` 是 `&mut u64`，`*` 解引用后原地累加。
                    (Some(v), Some(sum)) => *sum += v,
                    // 有一项查不到 → 总额作废，但不影响其它输入继续收集。
                    (None, Some(_)) => input_sum = None,
                    // 总额已经是 None 了，保持 None。
                    _ => {}
                }
                inputs.push(TxInView {
                    txid: txid_in.to_string(),
                    vout,
                    value,
                    // bitcoind 的 verbose 输出不给输入地址（要自己按脚本推），留 None。
                    address: None,
                    script_type: None,
                    coinbase: false,
                });
            }

            let outputs: Vec<TxOutView> = info
                .vout
                .iter()
                .map(|vout| TxOutView {
                    index: vout.n,
                    // `to_sat()`：`Amount` → `u64`（satoshi）。
                    // rust-bitcoin 用 `Amount` 新类型承载金额，避免与「字节数」等混用。
                    value: vout.value.to_sat(),
                    // 先试 `address`（单一地址），没有再退到 `addresses` 数组的第一个。
                    // `or_else(闭包)` 惰性求值：前者为 Some 时不执行闭包。
                    address: vout
                        .script_pub_key
                        .address
                        .clone()
                        // `first()` 返回 `Option<&Address>`，`.cloned()` 得到 `Option<Address>`
                        // （等价于 `.cloned()` 之前的 `.cloned()`；对 `Option<&T>` 而言
                        //  `.cloned()` 要求 `T: Clone`）。
                        .or_else(|| vout.script_pub_key.addresses.first().cloned())
                        // `assume_checked()`：bitcoind 返回的地址已知网络正确，
                        // 跳过运行时网络校验，直接转成可打印形式。
                        .map(|a| a.assume_checked().to_string()),
                    // `type_` 带下划线后缀是为了避开 Rust 的关键字 `type`。
                    script_type: vout.script_pub_key.type_.as_ref().map(|t| format!("{t:?}")),
                })
                .collect();

            // 输出总额一定算得出（金额写在输出里）。
            let output_sum: u64 = outputs.iter().map(|o| o.value).sum();
            // `checked_sub`：**溢出安全**的减法。若输入总额小于输出总额
            // （理论上不该发生，出现说明数据源有问题），返回 None 而非回绕。
            let fee = input_sum.and_then(|sum| sum.checked_sub(output_sum));

            return Ok(TxView {
                txid: info.txid.to_string(),
                version: info.version as i64,
                locktime: info.locktime as u64,
                size: Some(info.size as u64),
                // bitcoind 不直接给 weight，只给 vsize，故留 None。
                weight: None,
                vsize: Some(info.vsize as u64),
                fee,
                // 确认数为 0 或 None 都视为未确认。
                confirmed: info.confirmations.unwrap_or(0) > 0,
                // bitcoind 的 verbose 输出不含 blockheight，只有 blockhash。
                block_height: None,
                block_hash: info.blockhash.map(|h| h.to_string()),
                block_time: info.blocktime.map(|t| t as u64),
                confirmations: info.confirmations.map(|c| c as u64),
                inputs,
                outputs,
            });
        }

        // 回退 Esplora：它已把 prevout 展开好，省掉我们回溯上一笔交易的工夫。
        let tx = self.esplora.tx(&txid.to_string()).await?;
        let tip = self.esplora.tip_height().await.ok();
        Ok(TxView {
            txid: tx.txid,
            version: tx.version as i64,
            locktime: tx.locktime as u64,
            size: tx.size,
            weight: tx.weight,
            // Esplora 只给 weight，vsize 由它推出。
            // `div_ceil(4)`：**向上取整**的除法（等价于 ceil(weight / 4)），
            // 比手写 `(w + 3) / 4` 更表意。
            vsize: tx.weight.map(|w| w.div_ceil(4)),
            // Esplora 直接算好了手续费。
            fee: tx.fee,
            confirmed: tx.status.confirmed,
            block_height: tx.status.block_height,
            block_hash: tx.status.block_hash,
            block_time: tx.status.block_time,
            // 对**元组** `Option` 组合做匹配：两个都有值才算得出确认数。
            confirmations: match (tx.status.block_height, tip) {
                (Some(h), Some(tip)) => Some(tip.saturating_sub(h) + 1),
                _ => None,
            },
            inputs: tx
                .vin
                .iter()
                .map(|vin| TxInView {
                    txid: vin.txid.clone(),
                    vout: vin.vout,
                    // `prevout` 是 `Option<Prevout>`：
                    // `as_ref()` 借出引用 → `map` 取值 → 得到 `Option<u64>`。
                    value: vin.prevout.as_ref().map(|p| p.value),
                    // 连续两次 `as_ref().and_then(..)`：先确认 prevout 存在，
                    // 再取出其中的可选字段。`and_then` 会把嵌套的两层 Option 压平。
                    address: vin
                        .prevout
                        .as_ref()
                        .and_then(|p| p.scriptpubkey_address.clone()),
                    script_type: vin
                        .prevout
                        .as_ref()
                        .and_then(|p| p.scriptpubkey_type.clone()),
                    // 字段缺失（`None`）按「非 coinbase」处理，这是安全的一侧。
                    coinbase: vin.is_coinbase.unwrap_or(false),
                })
                .collect(),
            outputs: tx
                .vout
                .iter()
                // `enumerate()` 把 `Item` 变成 `(索引, Item)`——
                // Esplora 的输出没有 index 字段，序号由这里补上。
                .enumerate()
                .map(|(i, vout)| TxOutView {
                    // `i` 是 `usize`，转成结构体要求的 `u32`。
                    index: i as u32,
                    value: vout.value,
                    address: vout.scriptpubkey_address.clone(),
                    script_type: vout.scriptpubkey_type.clone(),
                })
                .collect(),
        })
    }

    /// 原始交易 hex：优先 bitcoind，回退 Esplora。
    pub async fn tx_hex(&self, txid: &str) -> Result<String> {
        let parsed: bitcoin::Txid = txid
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("非法交易哈希 {txid}: {e}"))?;
        if let Some(node) = &self.node {
            let client = node.connect()?;
            return client
                .get_raw_transaction_hex(&parsed, None)
                .with_context(|| format!("getrawtransaction {parsed} 失败"));
        }
        self.esplora.tx_hex(&parsed.to_string()).await
    }

    /// 地址 UTXO 列表（需要索引器，bitcoind 全节点不提供地址索引）。
    ///
    /// 这是**唯一没有 bitcoind 分支**的查询：全节点只按交易索引，
    /// 无法回答「某地址名下有哪些 UTXO」。想自建这个能力得额外跑
    /// Electrum Server / addrindexrs 之类的索引器。
    pub async fn utxos(&self, address: &str) -> Result<Vec<UtxoView>> {
        let utxos = self
            .esplora
            .utxos(address)
            .await
            .with_context(|| format!("查询 {address} 的 UTXO 失败"))?;
        Ok(utxos
            // `into_iter()`：**按值**迭代，把 `Utxo` 消耗掉而非借用，
            // 于是可以直接把它的字段移进新的 `UtxoView`，省去 clone。
            .into_iter()
            .map(|u| UtxoView {
                txid: u.txid,
                vout: u.vout,
                value: u.value,
                confirmed: u.status.confirmed,
                block_height: u.status.block_height,
                block_time: u.status.block_time,
            })
            .collect())
    }

    /// 地址统计（余额 / 收发总额 / 交易数）。
    ///
    /// 领域说明：BTC **没有「余额」这个概念**，只有 UTXO 集合。
    /// 余额 = 累计收到 − 累计支出，本方法就是这么算的。
    pub async fn address(&self, address: &str) -> Result<AddressView> {
        let stats = self
            .esplora
            .address(address)
            .await
            .with_context(|| format!("查询地址 {address} 失败"))?;
        // 解构赋值：把两组统计一次性取出四个数。
        let (confirmed_received, confirmed_sent) = (
            stats.chain_stats.funded_txo_sum,
            stats.chain_stats.spent_txo_sum,
        );
        let (pending_received, pending_sent) = (
            stats.mempool_stats.funded_txo_sum,
            stats.mempool_stats.spent_txo_sum,
        );
        Ok(AddressView {
            address: stats.address,
            // `saturating_sub`：理论上支出不会超过收入，
            // 但索引器数据异常时不应 panic，饱和到 0 更安全。
            confirmed_balance: confirmed_received.saturating_sub(confirmed_sent),
            // 这里**故意**用有符号运算：待支出时结果为负，语义上需要负值。
            // 两个 `as i64` 转换在 u64 最大值范围内不会失真（金额远小于 2^63）。
            unconfirmed_balance: pending_received as i64 - pending_sent as i64,
            // 交易数、UTXO 计数都是已确认与内存池两部分之和。
            tx_count: stats.chain_stats.tx_count + stats.mempool_stats.tx_count,
            funded_txo_count: stats.chain_stats.funded_txo_count
                + stats.mempool_stats.funded_txo_count,
            spent_txo_count: stats.chain_stats.spent_txo_count
                + stats.mempool_stats.spent_txo_count,
            total_received: confirmed_received + pending_received,
            total_sent: confirmed_sent + pending_sent,
        })
    }

    /// 费率估计：返回 (确认目标区块数, sat/vB) 列表。
    ///
    /// 「确认目标」= 期望在多少个区块内被打包，数值越小费率越高。
    /// 常见档位 1 / 3 / 6 / 12 / 25 / 144（144 ≈ 一天）。
    pub async fn fee_estimates(&self) -> Result<Vec<(u16, f64)>> {
        if let Some(node) = &self.node {
            let client = node.connect()?;
            // `[1u16, 3, 6, ..]`：首项标 `1u16` 固定元素类型，后续项自动推断。
            let targets = [1u16, 3, 6, 12, 25, 144];
            let mut estimates = Vec::new();
            for target in targets {
                let rate = client
                    .estimate_smart_fee(
                        target,
                        // `Conservative` 模式偏向「宁可慢一点也要够」，
                        // 适合不想交易卡住的场景（另一种是 Economical）。
                        Some(bitcoincore_rpc::json::EstimateMode::Conservative),
                    )
                    // 估算失败（历史数据不足）是常态，忽略即可。
                    .ok()
                    // `and_then(..)` 压平两层 Option：先要 RPC 成功，再要其中带 fee_rate。
                    .and_then(|result| result.fee_rate);
                if let Some(rate) = rate {
                    // RPC 返回 BTC/kB，换算成 sat/vB：to_sat() / 1000
                    //
                    // 换算推导：1 BTC/kB = 10^8 sat / 1000 字节 = 10^5 sat/字节。
                    // 而 1 vB 按 SegWit 折算约等于 1 字节的非见证数据，
                    // 实务上「BTC/kB ÷ 1000 × 10^8 ÷ 100」= sat/vB，
                    // bitcoincore_rpc 的 `to_sat()` 已给出 sat/kB，故再除以 1000。
                    estimates.push((target, rate.to_sat() as f64 / 1000.0));
                }
            }
            // 全部档位都估不出来（新装节点最常见）才回退 Esplora。
            if !estimates.is_empty() {
                return Ok(estimates);
            }
        }
        self.esplora.fee_estimates().await
    }

    /// 广播原始交易：优先本节点 RPC，回退 Esplora。
    ///
    /// 优先走自己的节点是有实际意义的：本地节点会先做完整的策略校验
    /// （手续费是否够、脚本是否合规、是否双花），
    /// 把明显会被全网拒绝的交易挡在本地，避免交易卡在内存池里出不来。
    pub async fn broadcast(&self, raw_hex: &str) -> Result<String> {
        if let Some(node) = &self.node {
            let client = node.connect()?;
            let txid = client
                .send_raw_transaction(raw_hex)
                .context("sendrawtransaction 失败")?;
            return Ok(txid.to_string());
        }
        self.esplora.broadcast(raw_hex).await
    }
}

/// 判断区块引用是否为高度（纯数字）而非哈希。
///
/// 领域说明：区块哈希是 64 位十六进制，理论上也可能**全是数字**
/// （概率约 (10/16)^64，极小但非零）。实务上这个判定足够可靠。
fn is_height(reference: &str) -> bool {
    // 空串必须排除：否则 `chars().all(..)` 对空集恒为 true，会把空串误判成高度 0。
    !reference.is_empty() && reference.chars().all(|c| c.is_ascii_digit())
}

/// 回溯上一笔交易，取指定输出的金额；失败（未开 txindex）返回 None。
///
/// 领域说明：这正是 UTXO 模型的特点——输入只写「引用哪个输出」，
/// 金额必须回溯上游交易才知道，因此**离线**也算不出手续费。
fn prevout_value(client: &Client, txid: bitcoin::Txid, vout: u32) -> Option<u64> {
    // `.ok()?`：`Result` → `Option`，失败则**直接从本函数返回 None**
    // （`?` 用在 Option 返回类型的函数里就是这个效果）。
    let info = client.get_raw_transaction_info(&txid, None).ok()?;
    info.vout
        .iter()
        // 按输出序号找到对应项。
        .find(|v| v.n == vout)
        // 取金额；找不到也返回 None。
        .map(|v| v.value.to_sat())
}

/// 由 CLI 参数构造节点配置；未给出 --node-url 时返回 None。
///
/// 返回 `Result<Option<NodeConfig>>` 表达两层含义：
/// - `Ok(None)`  —— 用户没配节点，用索引器模式（正常）；
/// - `Ok(Some(..))` —— 配了节点；
/// - `Err(..)`  —— 配了但配得不对（如只给了 user 没给 pass）。
pub fn node_config(
    network: NetworkArg,
    url: Option<String>,
    user: Option<String>,
    pass: Option<String>,
    cookie: Option<PathBuf>,
) -> Result<Option<NodeConfig>> {
    // `match` 作为表达式，把 `Option<String>` 展平成 `String`。
    let url = match url {
        Some(url) => url,
        // 没给 --node-url 就直接退出：说明用户不打算用自建节点。
        // 注意这里是 `return Ok(None)` 而非 `Err`——不配节点是**合法**选择。
        None => return Ok(None),
    };

    // 对**元组**做模式匹配，把 user / pass 的四种组合一次列全。
    // 这样编译器会强制我们处理「只给了一个」的情况，不会漏。
    let auth = match (user, pass) {
        // 两个都给了。
        (Some(user), Some(pass)) => NodeAuth::UserPass { user, pass },
        // 只给其一：直接报错，比静默降级成 cookie 认证更明确。
        (Some(_), None) => bail!("已提供 --node-user 但缺少 --node-pass"),
        (None, Some(_)) => bail!("已提供 --node-pass 但缺少 --node-user"),
        // 都没给：退到 cookie 认证。
        (None, None) => {
            let path = cookie
                // 用户显式指定的 cookie 路径优先。
                .or_else(|| network.default_cookie())
                // 探测不到时给出「该怎么配」的可执行建议，而不是干巴巴的「找不到」。
                .context("未找到 bitcoind cookie，请提供 --cookie 或 --node-user/--node-pass")?;
            NodeAuth::Cookie(path)
        }
    };

    Ok(Some(NodeConfig { url, auth }))
}
