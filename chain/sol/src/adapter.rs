//! sol 链对统一 `ChainClient` 契约的实现。
//!
//! Solana 的 RPC 客户端是**同步阻塞** API，这里统一包在 `spawn_blocking` 中，
//! 避免阻塞 async 运行时。
//!
//! ## 为什么必须 `spawn_blocking`（本文件最重要的设计）
//! tokio 的 async 运行时只有**少量工作线程**（默认等于 CPU 核数），
//! 这些线程靠「任务主动让出（await）」来并发处理成千上万个任务。
//! 一旦某个任务在 `.await` 之间执行了一段**阻塞式**代码（比如同步的 HTTP 请求、
//! 一次可能耗时几百毫秒的 RPC 调用），它就会把那条工作线程整个占死，
//! 排在同一线程上的其它任务全部停摆——这叫「阻塞了运行时」，
//! 表现为整个服务在某个慢节点面前集体卡住，而且极难排查。
//!
//! 官方 `solana-rpc-client` 只提供**同步** API（内部是阻塞的 reqwest），
//! 没有 async 版本。因此本文件的做法是：把每个 RPC 调用包进
//! `tokio::task::spawn_blocking`，把它丢给 tokio 的**专用阻塞线程池**
//! （默认 512 条线程，专门用来跑阻塞任务）。
//! 阻塞线程池被占满只影响并发度，不会连累 async 工作线程，
//! 于是上层的 HTTP / MCP 服务在高并发下依然能响应。
//! 这个封装就是下面 [`SolClient::blocking`] 存在的唯一理由。
//!
//! ## 本链特有的两个坑
//! - **slot 而非高度**：`block()` 只接受 slot（Solana 的区块索引是 slot，
//!   跳块时 slot 与 block_height 不相等），且公共节点只保留最近 1-2 天区块，
//!   所以这里**拒绝**缺省查询最新块，强制调用方显式给 slot。
//! - **`maxSupportedTransactionVersion`**：查询区块/交易时若不显式声明支持 v0，
//!   含 v0 交易的目标会被节点以 JSON-RPC 错误 `-32015` 拒绝。

// `Arc<T>` = Atomically Reference Counted，是**线程安全的引用计数智能指针**。
// 与 `Rc<T>`（单线程版）的区别：`Arc` 的计数用原子指令增减，可跨线程共享，
// 代价是比 `Rc` 略慢。tokio 的 `spawn_blocking` 要求闭包是 `Send + 'static`，
// 直接借用 `&self.client`（非 'static 的引用）是**编译不过**的，
// 因此必须让闭包**持有所有权**——而 `Arc` 让我们能在「持有一份所有权」
// 的同时不复制底层客户端、也不把 `self` 整个搬走。这就是这里用 `Arc` 的全部原因。
use std::sync::Arc;

// `async_trait` 属性宏：把 trait 里的 `async fn` 改写成返回 `Pin<Box<dyn Future>>` 的普通 fn
// （稳定版 Rust 暂不支持在 trait 里直接写 async fn）。详见 core/src/traits.rs 的说明。
use async_trait::async_trait;
// `json!` 宏：用字面量语法构造 `serde_json::Value`，用来填充各 View 的 `extra` 字段。
use serde_json::json;
use solana_commitment_config::CommitmentConfig;
// `Pubkey`：32 字节 ed25519 公钥的包装类型，实现了 `Copy` 与 `FromStr`，
// 它的 `Display` 输出就是 Solana 地址（base58）。
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_types::config::{RpcBlockConfig, RpcTransactionConfig};
// 必须 `use` 进来才能调用 `keypair.pubkey()`——Rust 要求 trait 在作用域内才能用其方法。
use solana_signer::Signer;
use solana_transaction_status_client_types::{
    EncodedTransaction, UiMessage, UiTransactionEncoding, option_serializer::OptionSerializer,
};

use allchain_core::{
    AddressView, BalanceView, BlockView, BuildTransferRequest, BuildTransferView, ChainClient,
    ChainKind, ErrorCode, SdkError, StatusView, SubmitRequest, SubmitView, TransferRequest,
    TransferView, TxStatus, TxView, hexutil,
};

use crate::cluster::{self, ClusterArg};

/// Solana 客户端。
///
/// 字段刻意都是私有的（没有 `pub`）：外部只能通过 `ChainClient` trait 的方法访问它，
/// 拿不到内部的 `RpcClient`，于是「确认级别」「端点」这些配置无法被外部意外改动。
///
/// 它同时满足 `Send + Sync`（`ChainClient` 的 supertrait 要求），
/// 因为三个字段都是 `String` 和 `Arc<RpcClient>`，而 `RpcClient` 本身是 `Send + Sync` 的。
pub struct SolClient {
    /// 网络名（`mainnet` / `devnet` / `testnet` / `localnet` / `custom`）。
    network: String,
    /// 实际连接的 RPC 端点，回显给调用方确认「打的是不是预期节点」。
    rpc_url: String,
    /// 底层的同步 RPC 客户端。
    ///
    /// 包在 `Arc` 里是为了能把它**克隆一份所有权**交给 `spawn_blocking` 的闭包
    /// （闭包必须是 `'static` 的，不能借用 `&self`）。
    /// 多个并发查询共享同一个客户端实例——它是线程安全的，且内部自带 HTTP 连接池，
    /// 复用比每次新建都更高效。
    client: Arc<RpcClient>,
}

// 固有实现块：构造器 + 私有辅助方法。
impl SolClient {
    /// 构造客户端。
    ///
    /// 优先级：**显式 `rpc_url` > 网络名 > 默认 mainnet**。
    /// 给了 `rpc_url` 时网络名一律记为 `"custom"`——因为无法从 URL 反推它属于哪个集群，
    /// 与其猜错不如如实标注。
    ///
    /// 语法说明：两个参数都是 `Option<&str>`（可选的字符串切片）：
    /// `None` 表示「没给」，用 `Option` 而不是空串 `""` 表达缺省，语义更明确。
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        // `Option` 组合子三连，把「可能没给、可能给了空串」归一化成一个 `Option<String>`：
        // - `.map(str::trim)`：`str::trim` 是**函数指针**（不是闭包），签名正好是 `fn(&str) -> &str`，
        //   于是可以对 `Option<&str>` 直接 map；
        // - `.filter(|s| !s.is_empty())`：把空串（含纯空白）筛掉，变成 `None`。
        //   闭包参数是 `|s|` 而非 `|&s|`：因为 `filter` 交给闭包的是 `&&str`，
        //   而 `s.is_empty()` 会自动解引用，所以写 `s` 即可；
        // - `.map(str::to_string)`：`&str` → `String`，取得所有权以便存进结构体。
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        // `match` 的两个分支都返回 `(String, String)` 元组，
        // 再用 `let (a, b) = ..` **解构**（destructuring）成两个变量。
        let (network_name, url) = match custom {
            // 有自定义 URL：网络名固定为 "custom"。
            // `.to_string()` 把 `&'static str` 字面量转成 `String`。
            Some(url) => ("custom".to_string(), url),
            None => {
                // 否则按网络名解析成预置集群。
                let c = parse_network(network)?;
                // `.as_str()` 返回 `&'static str`，再 `.to_string()` 转成 `String`；
                // `.rpc_url()` 同理。两次转换是因为结构体字段类型是 `String`（拥有数据），
                // 不能存一个指向别处的 `&'static str`（虽然这里活得够久，但类型不同意）。
                (c.as_str().to_string(), c.rpc_url().to_string())
            }
        };

        // 建连接。commitment 固定 `confirmed`（速度与可靠性的平衡，见 cluster.rs 的说明）。
        let client = Arc::new(cluster::connect(&url, CommitmentConfig::confirmed()));
        // 字段初始化简写：变量名与字段名相同，`client` 等价于 `client: client`。
        Ok(Self {
            network: network_name,
            rpc_url: url,
            client,
        })
    }

    /// 把同步 RPC 调用搬到阻塞线程池，并把错误统一归类。
    ///
    /// **这是本文件的核心辅助函数**，所有 RPC 调用都经过它。它做三件事：
    /// 1. 克隆一份 `Arc<RpcClient>` 交给闭包，满足 `spawn_blocking` 的 `'static` 要求；
    /// 2. 在阻塞线程池里执行同步调用，不占 async 工作线程；
    /// 3. 把两种不同的失败（任务本身异常 / RPC 返回错误）统一转成 `SdkError`。
    ///
    /// 语法说明：这是个**泛型函数**，逐条拆开 `where` 子句：
    /// - `F: FnOnce(Arc<RpcClient>) -> Result<T, anyhow::Error>`
    ///   → `F` 是「接收一个 `Arc<RpcClient>`、返回 `Result<T, anyhow::Error>`」的可调用物。
    ///   用 `FnOnce` 而不是 `Fn` / `FnMut` 是最宽松的一档：它只保证「至少能调用一次」，
    ///   于是调用方可以传捕获了变量的 `move` 闭包（把变量**移进**闭包），
    ///   而这在 `Fn`（要求可重复调用、不能消耗捕获的变量）下是做不到的。
    /// - `+ Send`
    ///   → 闭包可以**跨线程转移所有权**。`spawn_blocking` 会把闭包送到另一个线程执行，
    ///   没有这个约束编译器会拒绝（这是 Rust 在数据竞争上「编译期拦截」的典型例子）。
    /// - `+ 'static`
    ///   → 闭包里**不含任何指向当前栈帧的借用**（生命周期是整个程序）。
    ///   被派发的线程可能活得比当前函数还久，若闭包借用了局部变量就会悬垂，
    ///   所以必须有这个约束。这也正是上面要用 `Arc::clone` 而不是 `&self.client` 的原因。
    /// - `T: Send + 'static`
    ///   → 返回值同样要能跨线程搬回来，理由同上。
    ///
    /// 参数 `what: &'static str` 是**调用名**（如 "查询余额"），
    /// 它会出现在错误信息里；要求 `'static` 是因为它要跟着闭包/错误一起跨线程。
    async fn blocking<F, T>(&self, what: &'static str, f: F) -> Result<T, SdkError>
    where
        F: FnOnce(Arc<RpcClient>) -> Result<T, anyhow::Error> + Send + 'static,
        T: Send + 'static,
    {
        // `Arc::clone(&self.client)` 只是把引用计数 +1（**不是深拷贝**），成本极低。
        // 写成 `Arc::clone(&x)` 而非 `x.clone()` 是 Rust 的惯例——
        // 后者在 `x` 同时也实现了别的 `Clone` 时容易看不出到底克隆了什么。
        let client = Arc::clone(&self.client);
        // `spawn_blocking` 把闭包丢进 tokio 的**阻塞线程池**，返回一个 `JoinHandle`。
        // `move` 关键字把 `client` 与 `f` 的**所有权**转移进闭包
        // （不用 `move` 的话闭包只会借用它们，而借用活不到 `'static`，编译不过）。
        //
        // 返回值是 `JoinHandle<Result<T, anyhow::Error>>`，因此要 `await` 两次拆壳：
        // 第一次 `.await` 拿到 `Result<Result<T, E>, JoinError>` 的外层。
        tokio::task::spawn_blocking(move || f(client))
            .await
            // 外层错误 = **任务本身panic / 被取消**，属于内部故障，直接归为 Internal。
            // `{what}` / `{e}` 是格式串的内联参数（Rust 2021 特性）。
            .map_err(|e| SdkError::new(ErrorCode::Internal, format!("{what}任务异常: {e}")))?
            // 内层错误 = **RPC 调用本身失败**（网络不通、节点报错、参数非法…）。
            // 交给 core 的 `classify` 按关键词归类（超时→NetworkError、not found→NotFound 等），
            // 于是各链的错误码风格统一，上层不必解析 Solana 特有的错误文案。
            // `{e:?}` 用 `Debug` 打印，因为 anyhow 的错误链信息在 Debug 下最完整。
            .map_err(|e| allchain_core::error::classify(&format!("{what}: {e:?}")))
        // 末行无分号 = 返回这个 `Result<T, SdkError>`。
    }
}

/// 解析网络名；`None` 与空串都视为默认 **mainnet**（与其它链一致：默认主网）。
fn parse_network(raw: Option<&str>) -> Result<ClusterArg, SdkError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        // 没给 / 给了空串，都落到默认分支。
        None => Ok(ClusterArg::Mainnet),
        Some("mainnet") => Ok(ClusterArg::Mainnet),
        Some("devnet") => Ok(ClusterArg::Devnet),
        Some("testnet") => Ok(ClusterArg::Testnet),
        Some("localnet") => Ok(ClusterArg::Localnet),
        // `other` 绑定剩余的所有 `&str`。注意错误信息里把可选值一并列出——
        // 与其让用户去翻文档，不如在报错里直接告诉他能填什么。
        //
        // 这里用 `format!` 拼接 `other`，是 `invalid_argument`（参数类错误）而非网络类错误。
        Some(other) => Err(SdkError::invalid_argument(format!(
            "SOL 不支持的网络: {other}（可选 mainnet / devnet / testnet / localnet）"
        ))),
    }
}

// 下面是** trait 实现块**（`impl Trait for Type`），为 `SolClient` 实现 core 的
// 统一契约。加上 `#[async_trait]` 之后，块里的 `async fn` 会被改写成返回装箱 Future 的
// 普通 fn，于是 `SolClient` 可以被装进 `Box<dyn ChainClient>` / `Arc<dyn ChainClient>`，
// 上层门面据此在运行期按链名分发（运行时多态）。
//
// 实现块里**只**能出现 trait 声明过的方法，不能自己加新方法（那是固有实现块的事）。
#[async_trait]
impl ChainClient for SolClient {
    /// 所属链，恒为 `ChainKind::Sol`。
    ///
    /// `&self` 是不可变借用：这几个元数据方法都只返回构造时就确定好的值，无需 IO。
    fn kind(&self) -> ChainKind {
        // `ChainKind` 是 `Copy` 的，直接返回枚举值本身。
        ChainKind::Sol
    }

    /// 网络名。
    ///
    /// 语法说明：`&self.network` 把 `String` **借成** `&str`（deref 强制转换）。
    /// 返回引用而不是克隆一份 `String`，是因为调用方通常只是读一下，零分配更划算。
    fn network(&self) -> &str {
        &self.network
    }

    /// 实际使用的 RPC 端点，便于调用方判断是否打到了预期节点。
    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        // 一次 `spawn_blocking` 里连做三个 RPC 调用：
        // 它们彼此独立但都需要阻塞 IO，放进**同一个**阻塞任务里可以少一次线程调度，
        // 而且三个调用看到的是同一时刻的节点状态
        // （若分三次派发，中间可能已经跨了好几个 slot，数据会不自洽）。
        let (version, slot, blockhash) = self
            .blocking("查询节点状态", |client| {
                // 闭包体是**同步**代码，可以直接用 `?`（错误类型是 anyhow 的）。
                // 三个 `?` 中任意一个失败，整个闭包就提前返回 `Err`。
                let version = client.get_version()?;
                let slot = client.get_slot()?;
                let blockhash = client.get_latest_blockhash()?;
                // 把三个结果打包成元组返回；`version.solana_core` 是形如 "1.18.4" 的版本字符串。
                Ok((version.solana_core, slot, blockhash.to_string()))
            })
            .await?;

        // 注意：`latest_height` 填的是 **slot** 而不是 block_height。
        // 统一契约的 `height` 语义是「链的进度指示」，而在 Solana 上 slot 才是那个
        // 严格递增且可直接用于查询的量（跳块时 block_height 会落后于 slot）。
        Ok(
            StatusView::new(ChainKind::Sol, &self.network, &self.rpc_url)
                .with_height(slot)
                .with_hash(blockhash)
                .with_version(version),
        )
    }

    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        // 地址解析是**纯本地**计算，不碰网络，所以在 async 上下文里直接做，
        // 没必要占一个阻塞线程。
        //
        // `parse::<Pubkey>()` 的 `::<>` 叫 **turbofish**，用来显式指定泛型参数
        // （这里是 `FromStr` 的目标类型）。
        // `map_err(|_| ..)` 丢弃底层错误细节——它只会说 "Invalid character"，
        // 换成带原始输入的中文提示对调用方更有价值。
        let pubkey = address
            .trim()
            .parse::<Pubkey>()
            .map_err(|_| SdkError::invalid_argument(format!("非法 SOL 地址: {address}")))?;

        // `move` 闭包：把 `pubkey` 移进闭包。必须 `move`，否则闭包只是借用
        // 栈上的局部变量，活不到 `'static`，`spawn_blocking` 会拒绝。
        // 因为 `Pubkey: Copy`，这里实际是复制一份进去，闭包外的 `pubkey` 依然可用。
        let lamports = self
            .blocking("查询余额", move |client| {
                Ok(client.get_balance(&pubkey)?)
            })
            .await?;

        // `lamports: u64` 转成 `u128`：统一契约用 u128 承载所有链的最小单位整数
        // （NEAR 的 yoctoNEAR 需要 24 位小数，u64 装不下）。
        // `as u128` 是**无损**的拓宽转换，不会溢出。
        // `BalanceView::new` 会按 `ChainKind::Sol` 的 9 位精度自动算出 `balance_ui`。
        Ok(BalanceView::new(
            ChainKind::Sol,
            &self.network,
            address,
            lamports as u128,
        ))
    }



    /// 链头高度：最新 slot（裸 `u64`）。
    async fn last_block_height(&self) -> Result<u64, SdkError> {
        // SOL 刻意不允许「不指定 slot 查最新块」（公共节点只保留最近 1-2 天区块），
        // 故链头高度走 `get_slot` 显式取得。
        self.blocking("查询最新 slot", |client| Ok(client.get_slot()?)).await
    }

    /// 按 slot 查询区块。
    async fn block_by_height(&self, height: u64) -> Result<BlockView, SdkError> {
        let slot = parse_slot(Some(&height.to_string()))?;
        let block = self
            .blocking("查询区块", move |client| {
                let config = RpcBlockConfig {
                    encoding: Some(UiTransactionEncoding::Json),
                    transaction_details: None,
                    rewards: Some(false),
                    commitment: None,
                    max_supported_transaction_version: Some(0),
                };
                Ok(client.get_block_with_config(slot, config)?)
            })
            .await?;
        let mut view = BlockView::new(ChainKind::Sol, &self.network, block.blockhash)
            .with_parent(block.previous_blockhash)
            .with_tx_count(block.transactions.as_deref().unwrap_or_default().len() as u64);
        if let Some(h) = block.block_height { view = view.with_height(h); }
        if let Some(time) = block.block_time { view = view.with_timestamp(time); }
        Ok(view.with_extra(json!({
            "slot": slot,
            "parent_slot": block.parent_slot,
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        // Solana 的「交易哈希」就是它的**签名**（base58 编码的 64 字节），
        // 一个串即可查询，不需要区块号或发送者（这点与 NEAR 完全不同）。
        // `.parse()` 的目标类型由 `blocking` 闭包里 `get_transaction_with_config(&signature, ..)`
        // 的用法反推为 `Signature`。
        let signature = hash
            .trim()
            .parse()
            .map_err(|_| SdkError::invalid_argument(format!("非法交易签名: {hash}")))?;

        let tx = self
            .blocking("查询交易", move |client| {
                let config = RpcTransactionConfig {
                    encoding: Some(UiTransactionEncoding::Json),
                    commitment: None,
                    // 同样必须声明，否则查 v0 交易会被节点拒绝。
                    max_supported_transaction_version: Some(0),
                };
                Ok(client.get_transaction_with_config(&signature, config)?)
            })
            .await?;

        // `.as_ref()` 借出 `Option<&UiTransactionStatusMeta>`：后面还要多次读 meta，
        // 若不用 `as_ref` 就会把字段移走，之后再用会编译报错。
        let meta = tx.transaction.meta.as_ref();
        // 状态判定分三档，注意顺序：`None`（没元数据）与「执行失败」是**不同**的事。
        let status = match meta {
            // 拿不到元数据 → 无法判定，归为 Unknown（而不是 Failed）。
            None => TxStatus::Unknown,
            // `Some(m) if m.err.is_none()` 是**带守卫的匹配臂**（match guard）：
            // 先匹配 `Some(m)`，再用 `if` 追加条件。Solana 用 `Option<TransactionError>`
            // 表示错误，`None` 即成功。
            Some(m) if m.err.is_none() => TxStatus::Success,
            Some(_) => TxStatus::Failed,
        };

        // Solana 上交易的「所在区块」只有 slot，没有高度，
        // 所以统一契约的 `height` 这里填的是 slot（与 status() 的取法保持一致）。
        let mut view =
            TxView::new(ChainKind::Sol, &self.network, hash, status).with_height(tx.slot);
        if let Some(time) = tx.block_time {
            view = view.with_timestamp(time);
        }
        // `meta.map(|m| m.fee)`：`Option<&Meta>` → `Option<u64>`（fee 是 Copy 的），
        // 于是「没元数据」与「有元数据」两种情况被统一成一个 `Option` 来处理。
        if let Some(fee) = meta.map(|m| m.fee) {
            // Solana 的手续费单位是 lamport，`as u128` 无损拓宽。
            view = view.with_fee(fee as u128);
        }

        // extra 先放入 slot，下面再按需**增量追加**其它键。
        let mut extra = json!({ "slot": tx.slot });

        // 账户列表：首账户通常即 fee payer，可视作付款方。
        //
        // `if let ... = &tx.transaction.transaction`：只在 JSON 编码分支里才取得到账户列表
        // （二进制编码下账户信息无法直接读出）。
        if let EncodedTransaction::Json(ui) = &tx.transaction.transaction {
            // message 有两种形态，取账户列表的方式不同：
            // - Parsed：节点已解析成结构体，账户带 pubkey 与其它元信息，要 `.to_string()`；
            // - Raw：账户**已经是** base58 字符串，直接 clone 即可。
            let keys: Vec<String> = match &ui.message {
                UiMessage::Parsed(m) => m
                    .account_keys
                    .iter()
                    .map(|a| a.pubkey.to_string())
                    .collect(),
                UiMessage::Raw(m) => m.account_keys.clone(),
            };
            // Solana 交易的**第一个账户按约定就是 fee payer**（手续费支付者），
            // 把它作为 `from` 是启发式推断——严格来说 Solana 没有「发送方」这一概念，
            // 一笔交易可能有多个签名者。
            if let Some(first) = keys.first() {
                view = view.with_from(first.clone());
            }
            // 索引赋值：`Value` 实现了 `IndexMut<&str>`，
            // 于是 `extra["account_keys"] = json!(keys)` 可以直接插入/覆盖一个键。
            // 注意两点：
            // 1. 若 `extra` 不是对象（比如是 Null），这种赋值会 **panic**；
            //    这里它刚由 `json!({..})` 构造，必是对象，所以安全；
            // 2. 对**不存在的键**赋值会自动插入，无需预先建空对象。
            extra["account_keys"] = json!(keys);
        }

        if let Some(m) = meta {
            extra["pre_balances"] = json!(m.pre_balances);
            extra["post_balances"] = json!(m.post_balances);
            // `OptionSerializer::Some` 而非 `Option::Some`：Solana SDK 用它区分
            // 「显式空值」与「字段被省略」，两种在 JSON 里的表现不同。
            // 这里的 `compute_units_consumed` 是 `OptionSerializer<u64>`。
            if let OptionSerializer::Some(units) = m.compute_units_consumed {
                extra["compute_units"] = json!(units);
            }
            // log_messages 是 `OptionSerializer<Vec<String>>`，不是 `Copy` 的，
            // 因此在 `&m.log_messages` 上匹配，绑定出 `&Vec<String>`。
            if let OptionSerializer::Some(logs) = &m.log_messages {
                extra["log_messages"] = json!(logs);
            }
        }

        Ok(view.with_extra(extra))
    }

    async fn transfer(&self, req: TransferRequest) -> Result<TransferView, SdkError> {
        // 语法说明：参数 `req: TransferRequest` 是**按值接收**，适配器拥有它、
        // 可以自由取走其中的字段（下面 `req.to` 就被直接 move 进了 `TransferView::new`）。
        //
        // 三步解析全部是**纯本地**计算，任何一个失败都只是参数问题（InvalidArgument），
        // 不需要联网，因此放在 `spawn_blocking` 之前——让错误尽早、便宜地暴露。
        let to: Pubkey = req
            .to
            .trim()
            .parse()
            .map_err(|_| SdkError::invalid_argument(format!("非法 SOL 地址: {}", req.to)))?;
        // 金额是「人类可读的 SOL 字符串」（如 "0.5"），按 9 位精度转成 lamport。
        let lamports = crate::units::parse_sol(&req.amount)
            .map_err(|e| SdkError::invalid_argument(format!("非法金额: {e}")))?;
        // 私钥支持 JSON 数组 / base58 两种写法，详见 tx.rs。
        let keypair = crate::tx::parse_keypair(&req.private_key)
            .map_err(|e| SdkError::invalid_argument(format!("非法私钥: {e}")))?;
        // 付款地址由**私钥推导**（Solana 上地址 = 公钥的 base58），
        // 与统一契约里的 `TransferRequest::from` 无关——该字段只给 NEAR 这种命名账户链用。
        // `pubkey()` 来自 `Signer` trait，`.to_string()` 得到 base58 地址。
        let from = keypair.pubkey().to_string();
        // 提前把 `dry_run` 拷出来（`bool` 是 `Copy` 的），
        // 因为 `req` 稍后会被 move 进闭包，闭包里不能再借用它的字段。
        let dry_run = req.dry_run;

        // 构造、签名、（可选）广播**全部**放在一个阻塞任务里：
        // 这三步都需要同步 RPC（取 blockhash、发交易、轮询确认），
        // 放进同一个任务可以避免多次线程调度，也省去在 async 与阻塞之间来回切换。
        let (signature, blockhash) = self
            .blocking("转账", move |client| {
                // 1) 本地构造并签名（内部会取一次最新 blockhash）。
                let built = crate::tx::build_signed_transfer(&client, &keypair, &to, lamports)?;
                // 2) dry-run：只签名不广播，直接返回本地签名结果。
                if dry_run {
                    return Ok((built.signature, built.recent_blockhash));
                }
                // 3) 真发：广播并**轮询等待确认**（同步阻塞，可能耗时数秒）。
                let confirmed = client
                    .send_and_confirm_transaction(&built.tx)
                    .map_err(|e| {
                        // 包一层更具体的上下文：官方 SDK 的报错通常是
                        // "Transaction simulation failed"，看不出到底为什么失败。
                        // 用 `anyhow!` 宏现场构造一个 anyhow 错误。
                        anyhow::anyhow!("广播交易失败（账户可能不存在或余额不足）: {e}")
                    })?;
                Ok((confirmed, built.recent_blockhash))
            })
            .await?;

        // `&self.network` 是 `&String`，而 `TransferView::new` 的参数是 `impl Into<String>`，
        // `&String` 满足 `Into<String>`（会 clone 一份），所以可以直接传引用。
        Ok(TransferView::new(
            ChainKind::Sol,
            &self.network,
            Some(from),
            // `req.to` 在此被 move（前面只用了 `req.to.trim()` 的借用，所有权仍在）。
            req.to,
            lamports as u128,
            Some(signature.to_string()),
            // `broadcast` 字段 = 是否真的广播了，正好是 `!dry_run`。
            !req.dry_run,
        )
        // blockhash 回显出来，便于调用方核对交易锚定的区块（排查交易过期问题时很有用）。
        .with_extra(json!({ "recent_blockhash": blockhash })))
    }

    /// **无私钥**构造转账：取最新 blockhash、组装 SystemProgram.transfer，产出待签消息。
    ///
    /// 与 [`ChainClient::transfer`] 的分工：`transfer` 是**一段式**（私钥进 SDK，
    /// 签名广播都在 SDK 内）；本方法是**两段式**的第一段——只组装，
    /// 签名交给调用方（agent）用自己的私钥做，私钥从不进入本进程。
    ///
    /// 调用方拿到结果后应：
    ///   1. 对 `signing_payload_hex` 做 ed25519 签名（Solana 不做二次哈希，直接签这串字节）；
    ///   2. 把签名填回 `unsigned_tx_hex` 里的 `signatures[0]`，得到可广播交易；
    ///   3. 交给 [`Self::submit_tx`] 广播。
    ///
    /// 领域说明：blockhash 有**有效期**（约 150 个块，主网约 1 分钟）。
    /// 因此构造与广播之间不能拖太久，否则交易会被节点以 `BlockhashNotFound` 拒绝。
    /// 这与 ETH 那种「签完可以慢慢发」的模型截然不同，是本链独有的时间约束。
    async fn build_transfer(
        &self,
        req: BuildTransferRequest,
    ) -> Result<BuildTransferView, SdkError> {
        // 两个地址与金额都是**纯本地**解析，失败即为参数错误，
        // 不必联网——让错误尽早、便宜地暴露。
        let from: Pubkey = req
            .from
            .trim()
            .parse()
            .map_err(|_| SdkError::invalid_argument(format!("非法 SOL 付款地址: {}", req.from)))?;
        let to: Pubkey = req
            .to
            .trim()
            .parse()
            .map_err(|_| SdkError::invalid_argument(format!("非法 SOL 收款地址: {}", req.to)))?;
        let lamports = crate::units::parse_sol(&req.amount)
            .map_err(|e| SdkError::invalid_argument(format!("非法金额: {e}")))?;

        // 取 blockhash 需要同步 RPC，故整个构造过程放进阻塞线程池。
        let unsigned = self
            .blocking("构造未签名转账", move |client| {
                crate::tx::build_unsigned_transfer(&client, &from, &to, lamports)
            })
            .await?;

        Ok(BuildTransferView::new(
            ChainKind::Sol,
            &self.network,
            req.from,
            req.to,
            lamports as u128,
            unsigned.unsigned_tx_hex,
            unsigned.signing_payload_hex,
            "ed25519",
            // Solana 不做二次哈希：ed25519 直接对消息字节签名
            // （SHA-512 摘要在 ed25519 算法内部完成），故这里记为 `none`。
            "none",
        )
        .with_extra(json!({
            "recent_blockhash": unsigned.recent_blockhash,
            "lamports": unsigned.lamports,
            // 提示 blockhash 的时效性约束，避免调用方把待签交易存起来过夜再签。
            "note": "blockhash 约 150 个块后过期，请在 1 分钟内签名并广播",
            "next": "submit_tx",
        })))
    }

    /// 广播已签名交易，返回签名（Solana 里签名即 txid）。
    ///
    /// 领域说明：只做 `send_transaction`，**不等待确认**。
    /// 广播成功 ≠ 落块——交易可能因 blockhash 过期、余额不足或程序错误被丢弃，
    /// 要确认结果请用 [`ChainClient::tx`] 查签名状态。
    ///
    /// 编码说明：`encoding` 支持 `base64`（生态惯例，各钱包适配器均如此）
    /// 与 `hex`，缺省按 `base64` 处理——因为上游签名服务（`../sign`）返回的就是 base64。
    async fn submit_tx(&self, req: SubmitRequest) -> Result<SubmitView, SdkError> {
        // 归一化：没传 / 空串都折算成缺省的 base64。
        let encoding = req
            .encoding
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("base64");

        let raw = match encoding {
            "hex" => hexutil::decode_hex(&req.signed_tx_hex)?,
            "base64" => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(req.signed_tx_hex.trim())
                    .map_err(|e| {
                        SdkError::invalid_argument(format!("已签名交易不是合法 base64: {e}"))
                    })?
            }
            other => {
                return Err(SdkError::invalid_argument(format!(
                    "SOL 已签名交易只接受 base64 或 hex 编码，收到 {other}"
                )))
            }
        };
        if raw.is_empty() {
            return Err(SdkError::invalid_argument("已签名交易为空"));
        }

        let signature = self
            .blocking("广播已签名交易", move |client| {
                crate::tx::broadcast_raw(&client, &raw)
            })
            .await?;

        Ok(SubmitView::new(ChainKind::Sol, &self.network, signature.to_string()).with_extra(json!({
            "broadcast": true,
            "encoding": encoding,
        })))
    }

    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        // 解析成 32 字节（接受 base58 或十六进制两种写法，见 parse_pubkey_bytes）。
        let bytes = parse_pubkey_bytes(pubkey)?;
        // `Pubkey::new_from_array` 接收 `[u8; 32]`（**定长数组**，长度写进类型里），
        // 这就是上一步要返回数组而不是 `Vec<u8>` 的原因——类型对得上，无需运行时检查。
        let address = Pubkey::new_from_array(bytes);

        // Solana 的地址就是 ed25519 公钥的 base58 编码，二者是同一个字符串。
        //
        // 因此 `pubkey` 与 `address` 两个字段填的是**同一个值**（都取 `address.to_string()`）：
        // 这与 ETH（地址 = keccak 哈希后 20 字节）、BTC（哈希 + 校验和）形成鲜明对比。
        // 代价是 Solana 地址**没有校验和**，输错一个字符会得到另一个合法地址。
        Ok(AddressView::new(
            ChainKind::Sol,
            &self.network,
            address.to_string(),
            address.to_string(),
            "ed25519",
            // 公钥字节数，恒为 32；回显出来便于调用方核对输入是否被正确解析。
            bytes.len(),
        )
        .with_extra(json!({
            // 十六进制形式，便于与其它链 / 硬件钱包对齐。
            "pubkey_hex": hexutil::encode_hex_prefixed(&bytes),
            // 写明派生方式，让「同一个串」这件事在输出里自解释。
            "derivation": "base58(ed25519_pubkey)",
        })))
    }
}

/// 解析 32 字节 ed25519 公钥。
///
/// 接受两种写法：base58（即 Solana 地址本身，最常用）或十六进制（需为
/// 64 个十六进制字符；建议显式加 `0x` 前缀以消除歧义）。
///
/// 语法说明：返回 `[u8; 32]`（**定长数组**）而不是 `Vec<u8>`：
/// 长度正确性是 ed25519 公钥的一部分，用数组把「必须是 32 字节」
/// 这个约束编码进类型里，调用方（这里是 `Pubkey::new_from_array`）就无需再检查。
fn parse_pubkey_bytes(raw: &str) -> Result<[u8; 32], SdkError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(SdkError::invalid_argument("SOL 公钥不能为空"));
    }

    // 判定是否为十六进制，三种情况任一成立即可：
    // 1) 显式带 `0x` / `0X` 前缀——最可靠，优先采纳；
    // 2) 长度恰好 64（32 字节 = 64 个十六进制字符）**且**全是十六进制字符。
    //
    // 为什么不全判前缀：Solana 用户最常给的就是 base58 地址，
    // 强迫他们加 `0x` 不友好，于是用「长度 + 字符集」做启发式判定。
    // 潜在歧义：一个 32 字节的 base58 串通常有 43-44 个字符，不会误判；
    // 但纯数字/纯 a-f 的 64 字符 base58 串理论上存在，所以文档里建议显式加前缀。
    let looks_hex = trimmed.starts_with("0x")
        || trimmed.starts_with("0X")
        // `.chars().all(|c| c.is_ascii_hexdigit())`：`is_ascii_hexdigit` 认 0-9 / a-f / A-F。
        || (trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()));

    // `let bytes: Vec<u8> = if .. { .. } else { .. }`：`if/else` 是**表达式**，
    // 两个分支返回同类型的值，整体可以赋给变量。这是 Rust 里没有三元运算符的原因。
    let bytes: Vec<u8> = if looks_hex {
        // `hexutil::decode_hex` 已经返回 `SdkError`（core 统一错误类型），故直接 `?`。
        hexutil::decode_hex(trimmed)?
    } else {
        // base58：先校验字符集，长度不对时给出明确提示。
        bs58_decode(trimmed).map_err(|e| SdkError::invalid_argument(format!("{e}")))?
    };

    // `Vec<u8>` → `[u8; 32]`：`try_into()` 是 `TryFrom`/`TryInto` trait 提供的**可失败**转换
    // （对比 `into()` 是无失败的）。长度不符时返回 `Err(Vec<u8>)`——
    // 注意错误里带回了**原始向量**，所以下面的闭包能拿到它报出实际长度。
    //
    // `map_err(|got: Vec<u8>| ..)` 里给闭包参数标了类型，这是必须的：
    // 否则编译器无法推断 `got` 的类型（闭包的入参类型不像函数那样能从签名读出）。
    bytes.try_into().map_err(|got: Vec<u8>| {
        SdkError::invalid_argument(format!(
            "SOL 公钥需为 32 字节（base58 或 64 位十六进制），实际 {} 字节",
            got.len()
        ))
    })
    // 末行无分号 = 返回这个 `Result<[u8; 32], SdkError>`。
}

/// 复用 `tx.rs` 中已有的最小 base58 解码实现，避免为此新增依赖。
///
/// `tx.rs` 里那一份是为了解析私钥写的，本文件解析公钥正好能用同一个实现
/// （两者都是「base58 → 字节」）。唯一区别是错误文案，这里包一层换成公钥语境。
fn bs58_decode(input: &str) -> Result<Vec<u8>, SdkError> {
    // `crate::tx::bs58_decode` 返回 `anyhow::Result<Vec<u8>>`，
    // 这里把 anyhow 的错误转成 `SdkError::invalid_argument`（参数类错误）。
    // `format!("{e}")` 把 anyhow 的错误 `Display` 出来拼进中文提示。
    crate::tx::bs58_decode(input)
        .map_err(|e| SdkError::invalid_argument(format!("非法 base58 公钥: {e}")))
}

/// 解析区块引用：空 -> 当前 slot；否则必须是 slot 数字。
///
/// 注意 Solana 的区块按 **slot** 索引而非区块高度，两者在无跳块时才相等。
fn parse_slot(reference: Option<&str>) -> Result<u64, SdkError> {
    match reference.map(str::trim).filter(|s| !s.is_empty()) {
        // **刻意拒绝**「不指定就查最新块」：
        // 公共节点默认只保留最近 1-2 天（约 15 万-20 万个 slot）的区块，
        // 「最新区块」这个看似无害的请求在限流严重或节点落后时极易失败，
        // 且失败原因（BlockNotAvailable）对调用方极其费解。
        // 与其给一个时灵时不灵的行为，不如强制调用方显式指定目标。
        None => Err(SdkError::invalid_argument(
            "SOL 查询区块必须显式指定 slot（公共节点通常只保留最近 1-2 天的区块）",
        )),
        // 只接受纯数字：Solana 的 `getBlock` **不接受区块哈希**（这与很多链不同），
        // 所以这里连尝试解析哈希的必要都没有，直接按 slot 整数处理。
        Some(s) => s.parse().map_err(|_| {
            SdkError::invalid_argument(format!("非法 slot: {s}（Solana 按 slot 查询，需为整数）"))
        }),
    }
}

/// 单元测试模块：`#[cfg(test)]` 保证只在 `cargo test` 时编译。
///
/// 这里只测**纯本地**逻辑（公钥解析），不涉及任何网络调用——
/// 联网测试会因公共节点限流而变得不稳定（flaky），且拖慢 CI。
#[cfg(test)]
mod tests {
    use super::*;

    // 系统程序：32 字节全零，base58 表示为 32 个 1。
    const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

    /// base58 与十六进制两种写法应解析出**同一个** 32 字节公钥。
    #[test]
    fn base58_and_hex_produce_same_address() {
        // 常量是 `&'static str`。`.unwrap()` 在测试里是安全的：失败即 panic，测试失败。
        let from_b58 = parse_pubkey_bytes(SYSTEM_PROGRAM).unwrap();
        // `hexutil::encode_hex(&from_b58)` 把字节转成十六进制，再拼上 `0x` 前缀。
        // 注意这里 `&from_b58` 是 `&[u8; 32]`，会自动强制转换成 `&[u8]`（参数类型）。
        let from_hex =
            parse_pubkey_bytes(&format!("0x{}", hexutil::encode_hex(&from_b58))).unwrap();
        assert_eq!(from_b58, from_hex);
        // 往返验证：字节 → Pubkey → base58 地址，应还原成原始地址串。
        assert_eq!(Pubkey::new_from_array(from_b58).to_string(), SYSTEM_PROGRAM);
    }

    /// 不带 `0x` 前缀、但长度恰好 64 的十六进制也应被识别。
    #[test]
    fn accepts_bare_64_char_hex() {
        // `[7u8; 32]` 是**数组重复表达式**：32 个值为 7 的 u8。
        // `u8` 后缀是必须的，否则整数字面量默认是 `i32`。
        let hex_key = hexutil::encode_hex(&[7u8; 32]);
        let parsed = parse_pubkey_bytes(&hex_key).unwrap();
        assert_eq!(parsed, [7u8; 32]);
    }

    /// 各类非法输入都必须报错。
    #[test]
    fn rejects_wrong_length_and_bad_chars() {
        // 空串。
        assert!(parse_pubkey_bytes("").is_err());
        // base58 中不含 0 / O / I / l
        assert!(parse_pubkey_bytes("0OIl").is_err());
        // 31 字节的 base58
        //
        // `"1".repeat(31)` 造 31 个 '1'。注意它会被判为 hex 吗？
        // 长度 31 != 64，且不以 0x 开头，因此走 base58 分支，解码出 31 个零字节 → 长度不符。
        assert!(parse_pubkey_bytes(&"1".repeat(31)).is_err());
        // `"ab".repeat(31)` = 62 个 'a'/'b'：全是十六进制字符但长度是 62（不是 64），
        // 因此**不会**被判为 hex，走 base58 分支解码后长度也不对 → 报错。
        //
        // 这两条覆盖了「长度过短」的两种典型输入。
        assert!(parse_pubkey_bytes(&"ab".repeat(31)).is_err());
    }
}
