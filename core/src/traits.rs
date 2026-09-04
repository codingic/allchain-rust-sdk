//! 统一链能力 trait：四链适配器共同实现的查询与转账契约。
//!
//! 设计意图：这是整个 SDK 的**收敛点**。acli 门面、CLI / HTTP / MCP 三种形态
//! 都只依赖本 trait，不认识任何具体链的 SDK 类型。各链 crate 在自己的
//! `adapter.rs` 里 `impl ChainClient for XxxAdapter`，新增一条链时
//! 上层代码一行都不用改。

// `async_trait` 是社区 crate 提供的**属性宏**。
use async_trait::async_trait;

// 从 crate 根一次性引入模型与错误类型（这些类型在 lib.rs 里已重导出）。
use crate::{
    AddressView, BalanceView, BlockView, BuildTransferRequest, BuildTransferView, ChainKind,
    SdkError, StatusView, SubmitRequest, SubmitView, TransferRequest, TransferView, TxView,
};

/// 一条链的最小可用能力集。
///
/// 只读查询为必实现项；`transfer`（签名广播）由支持写操作的链实现，
/// 未实现的链走默认分支返回 `UNSUPPORTED`，不影响既有调用方。
///
/// 语法说明：`trait A: B` 中的 `: B` 是 **supertrait**（父 trait）约束，
/// 表示「要实现 `ChainClient`，必须先满足 `Send + Sync`」。
/// - `Send`   ：值可以安全地**跨线程转移所有权**（进 `thread::spawn`）；
/// - `Sync`   ：`&T` 可以安全地**跨线程共享**（进 `Arc<T>` 后被多线程读）。
/// 异步运行时（tokio）会在线程之间搬运任务，没有这两个约束，
/// 适配器就没法放进 tokio 的并发任务里，因此这里必须显式要求。
///
/// 语法说明：`#[async_trait]` 是必需的——在当前的稳定版 Rust 中，
/// trait 里**不能直接写 `async fn`**（返回值是匿名 Future，会让 trait 不再是
/// 对象安全的，且缺少生命周期支持）。该属性宏在编译期把每个 `async fn`
/// 改写成返回 `Pin<Box<dyn Future + Send + 'async_trait>>` 的普通 `fn`，
/// 也就是把 Future **装箱**（boxing）到堆上，用一次堆分配换取「trait 里能写异步方法」。
/// 代价是每次调用多一次堆分配；好处是 `Box<dyn ChainClient>` 这种
/// trait object 依然可用——上层正是靠 `Box<dyn ChainClient>` / `Arc<dyn ChainClient>`
/// 在**运行期**按链名分发到不同适配器（运行时多态）。
#[async_trait]
pub trait ChainClient: Send + Sync {
    /// 所属链。
    ///
    /// `&self` 是**不可变借用**：只读、不取得所有权、允许多个借用同时存在。
    /// 这几个元数据方法都是同步的——它们只返回适配器构造时就确定好的值，无需 IO。
    fn kind(&self) -> ChainKind;

    /// 当前连接的网络名，如 `mainnet` / `testnet` / `devnet` / `sepolia`。
    ///
    /// 语法说明：返回 `&str` 而不是 `String`，表示「借用适配器内部的那份字符串」。
    /// 这里发生了**生命周期省略**（lifetime elision）：完整写法是
    /// `fn network<'a>(&'a self) -> &'a str`，编译器按规则自动把返回值的生命周期
    /// 绑到 `&self` 上，含义是「返回的引用不能活得比 `self` 更久」——
    /// 这正是借用检查器要保证的事。
    fn network(&self) -> &str;

    /// 实际使用的 RPC 端点，便于调用方判断是否打到了预期节点。
    fn rpc_url(&self) -> &str;

    /// 链与节点状态。
    ///
    /// 语法说明：`async fn` + `Result<T, E>`：要么 `Ok(视图)`，要么 `Err(SdkError)`。
    /// 所有失败都统一成 `SdkError`，调用方不需要知道底层是 JSON-RPC 还是 REST。
    async fn status(&self) -> Result<StatusView, SdkError>;

    /// 查询地址/账户余额。
    ///
    /// 参数 `&str` 而非 `String`：只是借来读一下，没必要让调用方把字符串所有权交出来。
    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError>;

    /// 查询**链头高度**（最新区块的位置）。
    ///
    /// 领域说明：这是三个区块查询里最轻的一个——通常只需一次 RPC。
    /// 而「取最新区块」往往要先问高度、再按高度拉块（两次请求）。
    /// 只想确认同步进度或做轮询时，用它比拉整个区块划算得多。
    ///
    /// 返回值是裸 `u64` 而不是 View：调用方要的就是一个数字，
    /// 而 `chain` / `network` / `rpc_url` 已由外层信封（`Envelope`）提供，
    /// 没必要在 `data` 里重复一遍。
    ///
    /// 各链的「高度」含义并不相同：
    /// - ETH / BTC / NEAR / APT / AR / CKB / FIL —— 区块高度；
    /// - SOL —— **slot**（与区块高度是两个不同的概念）；
    /// - SUI —— checkpoint 序号；
    /// - TON —— masterchain 的 seqno。
    ///
    /// 统一叫「高度」，是因为它们都是**该链用于寻址区块的主序号**，
    /// 且都是本 SDK 支持的唯一寻址方式——按哈希查块已被有意移除：
    /// SOL / SUI / TON 这类按序号寻址的链根本没有对应的 RPC 端点，
    /// 与其让一半的链返回 `UNSUPPORTED`，不如让契约在十条链上完全一致。
    async fn last_block_height(&self) -> Result<u64, SdkError>;

    /// 按高度查询区块。
    ///
    /// `height` 用 `u64` 而非 `&str`：高度本来就是数字，
    /// 用字符串再靠「是否全是数字」去猜是高度还是哈希，
    /// 既让调用方多一次解析，也让非法输入只能等到运行期才暴露。
    /// 改成类型化参数后，这类问题由编译器挡住。
    async fn block_by_height(&self, height: u64) -> Result<BlockView, SdkError>;

    /// 查询交易。
    async fn tx(&self, hash: &str) -> Result<TxView, SdkError>;

    /// 由公钥派生地址。**纯本地计算**，不访问 RPC。
    ///
    /// - 公钥的编码格式由各链适配器自行规定，并在错误信息中说明；
    /// - 返回值里的 `network` 仍取当前客户端的网络，因为 BTC 的 bech32 hrp
    ///   与 base58 版本字节随网络而变；
    /// - 默认实现返回 `UNSUPPORTED`，新链接入时可以选择不实现。
    ///
    /// 语法说明：trait 里带**方法体**的 `async fn` 就是**默认实现**（default method）。
    /// 实现者可以原样继承，也可以覆写。这样「新增一条链」时只需要
    /// 实现它真正支持的能力，其余自动降级为 `UNSUPPORTED` 而不是编译报错，
    /// 从而让 trait 可以**向后兼容地扩展**。
    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        // 默认分支不消费参数，显式绑定以避免误用。
        // `let _ = pubkey;` 中的 `_` 是通配符模式：它**不会**触发
        // 「未使用变量」警告，同时表明「我确实知道这个参数存在但用不上」。
        // 与之相近的 `_pubkey`（下划线前缀命名）也能消除警告，但那是改名，语义略不同。
        let _ = pubkey;
        // `format!` 里的 `{}` 会调用 `ChainKind` 的 `Display` 实现（定义在 chain.rs），
        // 打印出 `"eth"` 这类短名，于是错误信息跨链风格统一。
        Err(SdkError::unsupported(format!(
            "{} 尚不支持由公钥派生地址",
            self.kind()
        )))
    }

    /// 转账：本地构造、签名并广播（`dry_run` 为 `true` 时只签名不广播）。
    ///
    /// 私钥只参与本地签名，不离开本进程。金额为人类可读原生单位。
    /// 默认返回 `UNSUPPORTED`，支持写操作的链才需要实现。
    ///
    /// 语法说明：参数 `req: TransferRequest` 是**按值接收**（不是 `&TransferRequest`）：
    /// 请求体被整个交给了适配器，适配器可以自由消费其中的字段（比如把 `private_key`
    /// 用完就地清零），调用方也不该在之后复用同一个请求。
    async fn transfer(&self, req: TransferRequest) -> Result<TransferView, SdkError> {
        // 同上一个默认分支：显式丢弃参数，避免未使用警告。
        let _ = req;
        Err(SdkError::unsupported(format!(
            "{} 尚不支持转账",
            self.kind()
        )))
    }

    /// 「无私钥」转账构造：仅凭 `from` / `to` / `amount` 组装未签名交易并返回待签对象。
    ///
    /// 领域说明——与 [`Self::transfer`] 的分工：
    /// - `transfer` 是**一体式**：需要 `private_key`，包办构造 + 签名 + 广播；
    /// - `build_transfer` 是**两段式的第一阶段**：**不接收私钥**，只构造。
    ///   私钥留在调用方（agent）手里，SDK 拿到链上状态后返回未签名交易与待签对象，
    ///   由 agent 签名，再经 [`Self::submit_tx`] 广播。
    ///
    /// 为什么必须这样拆：构造交易**必须**依赖链上状态（nonce / gas / 最近 blockhash /
    /// UTXO 等），agent 离线构造不出来；而私钥一旦交给 SDK 就多一处泄漏面。
    ///
    /// 返回的 `signing_payload_hex` 是**真正要签的那段字节**，它与 `unsigned_tx_hex`
    /// 在多数链上并不相同（详见 `BuildTransferView` 的文档），调用方不应自行推导。
    /// 默认返回 `UNSUPPORTED`，由支持的链覆写。
    async fn build_transfer(
        &self,
        req: BuildTransferRequest,
    ) -> Result<BuildTransferView, SdkError> {
        let _ = req;
        Err(SdkError::unsupported(format!(
            "{} 尚不支持无私钥构造转账",
            self.kind()
        )))
    }

    /// 广播一笔**调用方已签名**的交易（`build_transfer` 的第二阶段）。
    ///
    /// 领域说明：只接收签完名的交易字节，不接触任何私钥。与 `build_transfer`
    /// 配对，构成「SDK 构造 → agent 签名 → SDK 广播」的闭环。
    ///
    /// 注意 AR 也支持本方法：它虽然无法**无私钥构造**（需要 RSA 公钥模数），
    /// 但广播本身不需要私密材料，调用方用别的方式签出的交易同样可以提交。
    async fn submit_tx(&self, req: SubmitRequest) -> Result<SubmitView, SdkError> {
        let _ = req;
        Err(SdkError::unsupported(format!(
            "{} 尚不支持广播已签名交易",
            self.kind()
        )))
    }
}
