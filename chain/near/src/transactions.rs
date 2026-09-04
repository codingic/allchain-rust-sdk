//! 交易构造、离线签名与广播（broadcast_tx_commit）。
//!
//! ## NEAR 交易的四步流程
//! 1. **取 nonce**：向节点查询当前 access key 的 nonce，然后 **+1**。
//!    （nonce 是每把密钥独立递增的，不是每个账户一个，见 queries.rs 的说明。）
//! 2. **取近期区块哈希**：交易必须锚定一个近期区块哈希，过旧会被节点拒绝。
//!    这与 Solana 的 blockhash 机制异曲同工，但 NEAR 的有效窗口更长。
//! 3. **本地签名**：用 `InMemorySigner` 对交易哈希做 ed25519 签名。
//!    **私钥全程不离开本进程**，这是本 SDK 的安全底线。
//! 4. **广播并等待**：`broadcast_tx_commit` 会一直阻塞到交易最终确认才返回。
//!    这也是本模块所有 `send_*` 函数都相当耗时的原因。
//!
//! 前两步需要联网，第三步纯本地，第四步联网且最慢——
//! 把它们拆成 `build_signed` + 单独的广播调用，是为了支持 dry-run（只签名不广播）。
//!
//! ## 第二种形态：无私钥的两段式流程
//! 上面那条路要求本进程持有私钥。对 agent 场景来说这不可接受，于是另有：
//! - [`Self::build_unsigned_transfer`]：联网取 nonce 与区块哈希，组装交易，
//!   返回「待签的 32 字节」+「带占位签名的交易外壳」，**全程不接触私钥**；
//! - [`Self::broadcast_raw`]：只负责把签完名的交易字节丢给节点。
//!
//! 关于待签字节，NEAR 与 SOL 有一个关键差别，务必分清：
//! - **SOL**：ed25519 直接签「消息体本身」（几百字节）；
//! - **NEAR**：ed25519 签的是 `sha256(borsh(Transaction))` 这 **32 字节摘要**。
//! 因此 [`UnsignedTransfer::signing_payload_hex`] 只有 32 字节，
//! 而 `unsigned_tx_hex` 是几百字节的外壳——两者长度差了一个数量级，
//! 一眼就能看出拿错了。

// `FromStr` 必须引入作用域，才能对 `SecretKey` 调用 `.parse()` / `from_str(..)`。
use std::str::FromStr;

use anyhow::{Context, Result};
// `InMemorySigner`：把私钥放在内存里的签名器实现；
// `SecretKey`：私钥枚举（ed25519 / secp256k1）；
// `Signer`：签名器 trait，提供 `public_key()` 与 `sign()`。
use near_crypto::{InMemorySigner, PublicKey, SecretKey, Signature, Signer};
use near_jsonrpc_client::{JsonRpcClient, methods};
// NEAR 的交易体是「一个接收者 + 一组 Action」：
// - `Action::Transfer`       → 原生转账；
// - `Action::FunctionCall`   → 调用合约方法；
// 还有 CreateAccount / DeployContract / Stake / AddKey / DeleteKey / DeleteAccount 等。
use near_primitives::action::{Action, FunctionCallAction, TransferAction};
// `CryptoHash`：NEAR 的 32 字节哈希类型（交易哈希、区块哈希都是它）。
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{SignedTransaction, Transaction, TransactionV0};
// `AccountId` 具名账户；`Balance` 金额包装；`Gas` gas 包装。
use near_primitives::types::{AccountId, Balance, Gas};

use crate::queries;

/// 解析 `ed25519:...` 形式的私钥。
///
/// NEAR 的私钥规范表示是 `ed25519:<base58>`（也支持 `secp256k1:<base58>`），
/// 与公钥的表示法对称。这个「带类型前缀」的设计比裸十六进制更不容易搞混。
///
/// 语法说明：`SecretKey::from_str(..)` 之所以能调用，
/// 是因为文件头引入了 `FromStr` trait——Rust 要求 trait 在作用域内才能用它的方法。
pub fn parse_secret_key(raw: &str) -> Result<SecretKey> {
    // `.trim()` 是必须的：从文件读入的私钥末尾常带换行符。
    // `.context(..)` 把 `SecretKey` 的解析错误包上中文说明。
    SecretKey::from_str(raw.trim()).context("解析私钥失败（期望 ed25519:... 格式）")
}

/// 本地构造并签名后的交易（未广播）。
///
/// 把构造结果整体返回而不是直接广播，是为了支持 **dry-run**：
/// 调用方可以先拿到 `tx_hash`（这笔交易应有的哈希）做展示/校验，再决定是否广播。
/// adapter 层正是这么用的。
pub struct BuiltTx {
    /// 交易哈希。它同时也是链上查询这笔交易的 ID（配合 sender 账户）。
    pub tx_hash: CryptoHash,
    /// 已签名的完整交易体，可直接交给 `broadcast_tx_commit`。
    pub signed: SignedTransaction,
    /// 付款账户（签名者）。
    pub signer_id: AccountId,
    /// 收款账户（交易的接收者，注意它不一定是最终收款方——跨合约调用时会变）。
    pub receiver_id: AccountId,
    /// 本次使用的 nonce，便于调用方记录与重试。
    pub nonce: u64,
    /// 交易锚定的近期区块哈希。
    pub block_hash: CryptoHash,
}

// ---------------------------------------------------------------------------
// 无私钥（two-stage）流程
// ---------------------------------------------------------------------------

/// 占位签名的 borsh 编码：`0x00`（ed25519 的类型标签）+ 64 字节全零签名。
///
/// 为什么用「反序列化这 65 个字节」而不是直接构造 `Signature::ED25519(..)`：
/// `Signature::ED25519` 内部装的是 `ed25519_dalek::Signature`，而 near-crypto 0.37
/// **没有**把这个类型再导出——要用就得在 Cargo.toml 里额外钉一个 ed25519-dalek 版本。
/// 走官方解码器还有个附带好处：这 65 字节的布局一旦被上游改动，测试会立刻变红。
const PLACEHOLDER_SIGNATURE_BYTES: [u8; 65] = [0u8; 65];

/// 由交易各字段组装**未签名**的 `Transaction`（纯函数，不联网、不打印）。
///
/// 抽成函数的意义在于让「签过名的路径」与「无私钥的路径」共用同一份字段拼装代码——
/// 否则两条路各自拼一遍，将来加字段时极易只改一处，
/// 表现为「本地签名能过、无私钥构造出来的交易上链被拒」这类难查的偏差。
fn unsigned_transaction(
    nonce: u64,
    block_hash: CryptoHash,
    signer_id: AccountId,
    public_key: PublicKey,
    receiver_id: AccountId,
    actions: Vec<Action>,
) -> Transaction {
    // `Transaction::V0(TransactionV0 { .. })`：NEAR 的交易结构体带**版本枚举**，
    // 为将来的协议升级留出空间（类似 Solana 的 legacy / v0 交易）。目前只有 V0 一种。
    Transaction::V0(TransactionV0 {
        signer_id,
        // 交易的公钥字段必须与签名所用密钥匹配，节点会据此找到对应的 access key。
        public_key,
        nonce,
        receiver_id,
        block_hash,
        // `actions` 是 `Vec<Action>`，**按值移入**（不需要 clone，因为我们拥有它）。
        actions,
    })
}

/// 未签名转账：交给 agent 的「待签信封」。
///
/// 领域说明——两个 hex 字段的分工：
/// - `signing_payload_hex`（32 字节）= `sha256(borsh(Transaction))`，**真正要签的东西**；
/// - `unsigned_tx_hex`（几百字节）= `borsh(SignedTransaction)`，但签名字段是**全零占位**。
///   agent 签完后把最后 64 字节替换成自己的签名，就得到可广播的完整交易。
///
/// 之所以要加占位签名、而不是直接给 `borsh(Transaction)` 让 agent 自己尾部追加
/// 「`0x00` + 签名」：覆盖字节比拼接字节更难出错——拼接时若漏掉那个类型标签字节，
/// 节点会给一个「反序列化失败」的模糊错误，而覆盖操作没有这种失误空间。
pub struct UnsignedTransfer {
    /// 带占位签名的完整交易字节（borsh，带 `0x` 前缀）。
    pub unsigned_tx_hex: String,
    /// 真正要签的 32 字节摘要（带 `0x` 前缀）。对它做一次 ed25519 即可。
    pub signing_payload_hex: String,
    /// 付款账户。
    pub signer_id: AccountId,
    /// 收款账户。
    pub receiver_id: AccountId,
    /// 交易体里写明的签名公钥（必须与 agent 手里的私钥配对）。
    pub public_key: PublicKey,
    /// 本次使用的 nonce。
    pub nonce: u64,
    /// 交易锚定的近期区块哈希。
    pub block_hash: CryptoHash,
    /// 转账金额（yoctoNEAR）。
    pub deposit: u128,
}

/// 组装未签名转账（**纯函数**：不联网、不打印、不签名）。
///
/// 与 [`build_unsigned_transfer`] 的分工和 ETH / SOL 那侧完全一致：
/// 联网取元数据的部分单独放在 async 包装里，这里只管序列化——
/// 于是「字节对不对」这件事可以离线测试，不必依赖公共 RPC 节点。
pub fn assemble_unsigned(
    nonce: u64,
    block_hash: CryptoHash,
    signer_id: AccountId,
    public_key: PublicKey,
    receiver_id: AccountId,
    deposit: u128,
) -> Result<UnsignedTransfer> {
    let unsigned = unsigned_transaction(
        nonce,
        block_hash,
        signer_id.clone(),
        public_key.clone(),
        receiver_id.clone(),
        // 与 `transfer()` 一样：金额单位是 yoctoNEAR，换算在边界（adapter）完成。
        vec![Action::Transfer(TransferAction {
            deposit: Balance::from_yoctonear(deposit),
        })],
    );

    // 待签摘要 = `sha256(borsh(Transaction))`。`get_hash_and_size()` 一次给出
    // 「摘要」与「交易体字节数」两样东西：字节数用于计费，本 SDK 不需要，故用 `_size` 丢弃
    // （下划线前缀的变量名不会触发「未使用变量」警告）。
    let (tx_hash, _size) = unsigned.get_hash_and_size();

    // 外壳：签名字段填占位的完整交易。`SignedTransaction::new` 的 `#[borsh(init=init)]`
    // 会在构造时顺带把 hash / size 算好，这两个字段标了 `#[borsh(skip)]`，不参与序列化。
    let placeholder: Signature = borsh::from_slice(&PLACEHOLDER_SIGNATURE_BYTES)
        .context("构造 ed25519 占位签名失败")?;
    let shell = SignedTransaction::new(placeholder, unsigned);
    let shell_bytes = borsh::to_vec(&shell).context("序列化未签名交易失败")?;

    Ok(UnsignedTransfer {
        // `hex::encode` 产出不带前缀的小写十六进制，统一由 SDK 侧补上 `0x`。
        unsigned_tx_hex: format!("0x{}", hex::encode(&shell_bytes)),
        // `tx_hash.as_ref()` 把 `CryptoHash` 借成 `&[u8]`（见 `impl AsRef<[u8]>`）。
        signing_payload_hex: format!("0x{}", hex::encode(tx_hash.as_ref())),
        signer_id,
        receiver_id,
        public_key,
        nonce,
        block_hash,
        deposit,
    })
}

/// 联网版：取 nonce 与近期区块哈希，然后交给 [`assemble_unsigned`] 组装。
///
/// `public_key` 是必填的——无私钥流程无从推导它，必须由调用方（adapter）给出：
/// 要么 agent 显式指定，要么从账户名反推，要么查链上 access key 列表。
pub async fn build_unsigned_transfer(
    client: &JsonRpcClient,
    signer_id: &AccountId,
    public_key: &PublicKey,
    receiver_id: &AccountId,
    deposit: u128,
    nonce_override: Option<u64>,
) -> Result<UnsignedTransfer> {
    // 1) 默认以当前 nonce + 1 构造交易（NEAR 的 nonce 是**每把 key 独立**递增的）。
    let nonce = match nonce_override {
        Some(nonce) => nonce,
        // 走数据层函数而不是 `view_access_key`：后者会 `println!`，
        // 在 HTTP / MCP 服务里会污染 stdout。
        None => queries::fetch_access_key_nonce(client, signer_id, public_key).await? + 1,
    };

    // 2) 交易必须锚定一个近期区块哈希（过旧会被节点拒绝）。
    let status = client
        .call(methods::status::RpcStatusRequest)
        .await
        .context("获取最新区块哈希失败")?;

    // 3) 组装（纯本地）。
    assemble_unsigned(
        nonce,
        status.sync_info.latest_block_hash,
        signer_id.clone(),
        public_key.clone(),
        receiver_id.clone(),
        deposit,
    )
}

/// 广播**已签名**的交易字节，只发不等确认。
///
/// 领域说明：走的是 `broadcast_tx_async`，发完即返回交易哈希。
/// 与 `broadcast_tx_commit`（阻塞到最终确认，1-3 秒）相比，
/// 它更适合 HTTP / MCP 这类长驻服务——不会因为链上拥堵而卡住一个请求。
///
/// 代价是**广播成功 ≠ 上链成功**：nonce 冲突、余额不足、签名与公钥不匹配等错误
/// 都要等交易真正执行时才暴露。要确认结果请用 `tx(<hash>@<sender>)` 查询。
pub async fn broadcast_raw(client: &JsonRpcClient, raw: &[u8]) -> Result<CryptoHash> {
    // 反序列化会走 `SignedTransaction` 的 `#[borsh(init=init)]`，
    // 顺带重算交易哈希与大小——所以这里拿到的对象是完整的、可直接广播的。
    let signed: SignedTransaction =
        borsh::from_slice(raw).context("解析已签名交易失败（期望 borsh(SignedTransaction)）")?;

    client
        .call(methods::broadcast_tx_async::RpcBroadcastTxAsyncRequest {
            signed_transaction: signed,
        })
        .await
        .context("广播交易失败")
}

/// 通用的「取 nonce -> 取最新区块哈希 -> 本地签名」流程（不打印不广播）。
///
/// `nonce_override` 用于离线签名或联调：指定后跳过链上查询 nonce 这一步，
/// 直接以给定值构造交易（仍需自行保证该 nonce 未被使用）。
pub async fn build_signed(
    client: &JsonRpcClient,
    signer_id: &AccountId,
    secret_key: &SecretKey,
    receiver_id: &AccountId,
    actions: Vec<Action>,
    nonce_override: Option<u64>,
) -> Result<BuiltTx> {
    // `let signer: Signer = ...`：`Signer` 是 trait，这里用它做**类型标注**，
    // 表示「我不关心具体类型，只要有签名能力就行」。
    // 写成标注而非 `let signer = ..` 是为了让读代码的人一眼看出这是个签名器。
    //
    // `InMemorySigner::from_secret_key(..)` 需要**拥有** account_id 与 secret_key，
    // 而参数都是借用，因此两处都要 `.clone()`。
    let signer: Signer = InMemorySigner::from_secret_key(signer_id.clone(), secret_key.clone());

    // 1) 默认以当前 nonce + 1 构造交易，避免并发交易相互覆盖。
    let nonce = match nonce_override {
        // 显式指定时直接用（调用方自己负责保证该 nonce 未被使用）。
        Some(nonce) => nonce,
        // 否则查链上当前值再 +1。
        // 注意 `queries::view_access_key` 会顺带**打印** nonce 与权限信息——
        // 它在 CLI 路径下是想要的行为，在 adapter 路径下则只是多了点输出。
        None => queries::view_access_key(client, signer_id, &signer.public_key()).await? + 1,
    };

    // 2) 交易必须锚定一个近期区块哈希（过旧会被节点拒绝）。
    let status = client
        .call(methods::status::RpcStatusRequest)
        .await
        .context("获取最新区块哈希失败")?;

    // 与无私钥路径共用同一个纯函数组装交易体，保证两条路拼出的字节完全一致。
    // `signer.public_key()` 在这里被**移动**进结构体，故下面不能再借用 `signer` 的该字段。
    let unsigned = unsigned_transaction(
        nonce,
        // 锚定最新区块哈希。
        status.sync_info.latest_block_hash,
        signer_id.clone(),
        // 交易的公钥字段必须与签名所用密钥匹配，节点会据此找到对应的 access key。
        signer.public_key(),
        receiver_id.clone(),
        actions,
    );

    // 3) 本地离线签名：私钥不会离开本进程。
    //
    // `get_hash_and_size()` 同时返回「待签名的哈希」与「交易序列化后的大小」。
    // 大小用于计费（NEAR 按交易字节数收费），本 SDK 不需要，故用 `_size` 丢弃
    // （下划线前缀的变量名不会触发「未使用变量」警告）。
    let (tx_hash, _size) = unsigned.get_hash_and_size();
    // `signer.sign(tx_hash.as_ref())`：对哈希的字节切片做 ed25519 签名。
    // `as_ref()` 把 `CryptoHash` 借成 `&[u8]`。
    // `SignedTransaction::new(签名, 交易)` 把两者打包。
    let signed = SignedTransaction::new(signer.sign(tx_hash.as_ref()), unsigned);

    Ok(BuiltTx {
        tx_hash,
        signed,
        signer_id: signer_id.clone(),
        receiver_id: receiver_id.clone(),
        nonce,
        block_hash: status.sync_info.latest_block_hash,
    })
}

/// 通用的「取 nonce -> 取最新区块哈希 -> 本地签名 -> 广播并等待最终性」流程。
///
/// `nonce_override` 用于离线签名或联调：指定后跳过链上查询 nonce 这一步，
/// 直接以给定值构造交易（仍需自行保证该 nonce 未被使用）。
pub async fn send_tx(
    client: &JsonRpcClient,
    signer_id: &AccountId,
    secret_key: &SecretKey,
    receiver_id: &AccountId,
    actions: Vec<Action>,
    nonce_override: Option<u64>,
) -> Result<CryptoHash> {
    // 复用构造逻辑：dry-run 与真发走**同一条构造路径**，不会出现「试跑正常、真发出问题」。
    let built = build_signed(
        client,
        signer_id,
        secret_key,
        receiver_id,
        actions,
        nonce_override,
    )
    .await?;

    println!("tx_hash      : {}", built.tx_hash);
    println!("signer       : {}", built.signer_id);
    println!("receiver     : {}", built.receiver_id);
    println!("nonce        : {}", built.nonce);
    println!("block_hash   : {}", built.block_hash);

    // 4) 广播并等待交易达到最终性。
    //
    // `broadcast_tx_commit` 是最「重」的广播方式：它会一直**阻塞**
    // 直到交易最终确认（Final）才返回，因此耗时通常在 1-3 秒。
    // 追求低延迟的场景可以改用 `broadcast_tx_async`（发完即返）再自行轮询。
    let outcome = client
        .call(methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
            // 按值移入：交易体所有权交给请求结构。
            signed_transaction: built.signed,
        })
        .await
        .context("广播交易失败")?;

    // `{:#?}` = pretty debug，多行缩进打印（NEAR 的状态枚举嵌套较深，一行放不下）。
    println!("status       : {:#?}", outcome.status);
    println!(
        "gas_burnt    : {:.2} TGas",
        // gas unit → TGas：除以 10^12。`as f64` 转换是安全的（gas 不是金额，精度不敏感）。
        // `{:.2}` 保留两位小数。
        outcome.transaction_outcome.outcome.gas_burnt.as_gas() as f64 / 1e12
    );
    // 逐条打印 receipt：跨合约调用、转账到账、gas 退款都会各产生一个 receipt。
    // `.iter().enumerate()` 同时给出下标与元素。
    for (i, receipt) in outcome.receipts_outcome.iter().enumerate() {
        // `executor_id` 是**实际执行**这个 receipt 的账户——
        // 跨合约调用时它与 `receiver_id` 不同，排查问题时很有用。
        println!("receipt[{i}]   : {}", receipt.outcome.executor_id);
        println!("  status: {:?}", receipt.outcome.status);
        for line in &receipt.outcome.logs {
            println!("  log: {line}");
        }
    }
    // 返回本地算出的交易哈希（它与链上 ID 一致，可用于后续查询）。
    Ok(built.tx_hash)
}

/// 原生 NEAR 转账。
///
/// 语法说明：`deposit: u128` 的单位是 **yoctoNEAR**（最小单位），
/// 不是可读的 NEAR。调用方需先用 `units::parse_near` 把 "1.5" 这类字符串换算过来
/// （adapter 里就是这么做的），本函数不做任何换算——
/// 「单位统一在边界处理」比「每个函数各猜一次」更不容易出错。
pub async fn transfer(
    client: &JsonRpcClient,
    signer_id: &AccountId,
    secret_key: &SecretKey,
    receiver_id: &AccountId,
    deposit: u128,
    nonce_override: Option<u64>,
) -> Result<CryptoHash> {
    // 透传给 `send_tx`，唯一的区别是构造一个 `Transfer` action。
    // `Balance::from_yoctonear(deposit)` 把 u128 包成 NEAR 的金额类型——
    // 包装类型的作用是让「yactoNEAR 金额」与「普通整数」在类型层面区分开。
    send_tx(
        client,
        signer_id,
        secret_key,
        receiver_id,
        vec![Action::Transfer(TransferAction {
            deposit: Balance::from_yoctonear(deposit),
        })],
        nonce_override,
    )
    .await
}

/// 调用合约的变更方法（会消耗 gas，需要签名）。
///
/// 与 `queries::call_function`（只读、免费、立即返回）相对：
/// 这里调用的是**变更方法**，需要签名、广播、等待确认，并消耗 gas。
///
/// 语法说明：`#[allow(clippy::too_many_arguments)]` 关掉 clippy 的「参数过多」告警。
/// 本函数有 8 个参数确实偏多，但它们都是一次合约调用的必要信息
/// （签名者、密钥、合约、方法名、参数、gas、附带金额、nonce 覆盖），
/// 拆成配置结构体反而会让「简单调用」变啰嗦，因此选择保留并显式豁免。
#[allow(clippy::too_many_arguments)]
pub async fn function_call(
    client: &JsonRpcClient,
    signer_id: &AccountId,
    secret_key: &SecretKey,
    contract_id: &AccountId,
    method_name: &str,
    args: Vec<u8>,
    gas: u64,
    deposit: u128,
    nonce_override: Option<u64>,
) -> Result<CryptoHash> {
    send_tx(
        client,
        signer_id,
        secret_key,
        contract_id,
        // `Action::FunctionCall` 装的是一个 **`Box<FunctionCallAction>`**：
        // 装 Box 是因为 `FunctionCallAction` 比其它 action 大得多（含方法名与参数字节），
        // 装箱后 `Action` 枚举本身就不会因这一个变体而被撑大，
        // 所有 `Vec<Action>` 的内存占用都跟着变小。
        vec![Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: method_name.to_string(),
            // `args` 是 `Vec<u8>`，**按值移入**（调用方已交出所有权，无需 clone）。
            args,
            // `Gas::from_gas(gas)`：把 gas unit 包成 NEAR 的 Gas 类型。
            gas: Gas::from_gas(gas),
            // `deposit` 是随调用附带的**存款**（yoctoNEAR）。
            // 很多合约的 payable 方法要求附带金额，纯查询方法填 0 即可。
            deposit: Balance::from_yoctonear(deposit),
        }))],
        nonce_override,
    )
    .await
}

/// 单元测试模块：`#[cfg(test)]` 保证只在 `cargo test` 时编译。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::units::parse_near;
    use near_crypto::KeyType;
    // `Digest` trait 必须引入作用域，`Sha256::digest(..)` 才可调用——
    // 与 `FromStr` 同理：Rust 要求 trait 在作用域内才能用它的方法。
    use sha2::Digest;

    /// 离线验证 send_tx 的本地部分：构造 -> 签名 -> 哈希/签名校验，全程不触网。
    ///
    /// 它验证的是 `send_tx` 里**前三步**（构造 + 签名），把第 1、2、4 步（需要联网）
    /// 直接跳过：nonce 写死 42、block_hash 用 `Default::default()`（全零）。
    /// 这样测试既快又不依赖外部节点——联网测试会因公共节点限流而变得不稳定。
    #[test]
    fn send_tx_signs_offline() {
        // `from_seed` 用固定种子生成密钥：**确定性**的，
        // 每次运行得到同一把密钥，测试才可复现。
        // （生产环境应当用随机种子，`KeyType::ED25519` 是 NEAR 的默认曲线。）
        let secret_key = SecretKey::from_seed(KeyType::ED25519, "near-rpc-cli-test-seed");
        // NEAR 的账户名是**具名账户**，不是地址。
        // `"alice.near".parse().unwrap()` 靠 `AccountId: FromStr` 完成解析。
        let signer_id: AccountId = "alice.near".parse().unwrap();
        let receiver_id: AccountId = "bob.near".parse().unwrap();

        let signer: Signer = InMemorySigner::from_secret_key(signer_id.clone(), secret_key);
        let unsigned = Transaction::V0(TransactionV0 {
            // 这里 `signer_id` 被**移入**结构体（上面那次 `.clone()` 就是为了留一份给签名器）。
            signer_id,
            public_key: signer.public_key(),
            nonce: 42,
            receiver_id,
            // 全零哈希：离线测试不关心它是否会被节点接受。
            // `Default::default()` 依赖 `CryptoHash: Default`。
            block_hash: Default::default(),
            actions: vec![Action::Transfer(TransferAction {
                // 用真实的换算函数构造金额，顺带验证 `parse_near` 的行为。
                deposit: Balance::from_yoctonear(parse_near("1.5").unwrap()),
            })],
        });

        let (tx_hash, size) = unsigned.get_hash_and_size();
        // 序列化后的大小必然大于 0，这是最基本的健全性检查。
        assert!(size > 0);

        let signed = SignedTransaction::new(signer.sign(tx_hash.as_ref()), unsigned);
        // 签名只追加签名字段，不改变交易体，因此哈希必须保持一致。
        assert_eq!(signed.get_hash(), tx_hash);
        // 用公钥**验证**签名：这是整个离线流程的核心断言——
        // 它证明「签名确实由这把私钥产生，且覆盖的是这份交易体」。
        assert!(
            signed
                .signature
                .verify(tx_hash.as_ref(), &signer.public_key())
        );
    }

    // -----------------------------------------------------------------------
    // 无私钥流程的离线测试
    //
    // 原则与 ETH / SOL 那侧一致：**不拿自己的公式当标准**。
    // 「签一下再验一下」对任意 32 字节都成立，抓不到「摘要算错了」这类缺陷，
    // 所以下面每条断言都对着外部真值：独立实现的 sha256，或官方的 `SignedTransaction::new`。
    // -----------------------------------------------------------------------

    // 固定种子 → 确定性密钥，测试才可复现。与 `send_tx_signs_offline` 用同一把。
    const TEST_SEED: &str = "near-rpc-cli-test-seed";

    /// 用固定输入组装一笔未签名转账：nonce / block_hash / 金额全部写死。
    ///
    /// block_hash 刻意用**非零**字节：全零会掩盖「忘了把 block_hash 写进交易体」
    /// 这类缺陷（拼不拼进去，字节数都一样，只有内容不同）。
    fn fixed_unsigned() -> UnsignedTransfer {
        let secret_key = SecretKey::from_seed(KeyType::ED25519, TEST_SEED);
        let signer: Signer = InMemorySigner::from_secret_key(TEST_SIGNER.parse().unwrap(), secret_key);
        assemble_unsigned(
            TEST_NONCE,
            // `CryptoHash` 是元组结构体且字段公开，可直接用字节数组构造。
            CryptoHash([0xab; 32]),
            TEST_SIGNER.parse().unwrap(),
            signer.public_key(),
            TEST_RECEIVER.parse().unwrap(),
            parse_near(TEST_AMOUNT).unwrap(),
        )
        .unwrap()
    }

    const TEST_SIGNER: &str = "alice.near";
    const TEST_RECEIVER: &str = "bob.near";
    const TEST_AMOUNT: &str = "1.5";
    const TEST_NONCE: u64 = 42;

    /// 去掉 `0x` 前缀后解码十六进制。
    fn decode_prefixed(raw: &str) -> Vec<u8> {
        hex::decode(raw.trim_start_matches("0x")).unwrap()
    }

    /// **对拍**：待签摘要必须等于 `sha256(borsh(Transaction))`，用独立实现算一遍。
    ///
    /// 这条测试是「无私钥流程」的地基。若 `signing_payload_hex` 给错（比如误把
    /// 几百字节的交易体本身当摘要），agent 签出来的是一个**格式完全合法、
    /// 但节点永远拒收**的签名——不报错，只在链上静默失败，排查成本极高。
    #[test]
    fn signing_payload_is_sha256_of_the_borsh_body() {
        let unsigned = fixed_unsigned();

        // 1) 摘要必须是 32 字节，且**不是**交易体本身。
        let payload = decode_prefixed(&unsigned.signing_payload_hex);
        assert_eq!(payload.len(), 32, "待签摘要必须是 32 字节");

        // 2) 独立重算：自己 borsh 一遍交易体，再用 sha2 crate 直接算摘要，
        //    不碰 NEAR 的 `get_hash_and_size()`。
        //
        //    交易体 = 外壳去掉尾部 65 字节的签名（见下一条测试对这 65 字节的验证）。
        let shell = decode_prefixed(&unsigned.unsigned_tx_hex);
        let body = &shell[..shell.len() - 65];
        let expected = sha2::Sha256::digest(body);
        assert_eq!(
            payload,
            expected.as_slice(),
            "待签摘要应等于 sha256(borsh(Transaction))"
        );
    }

    /// 外壳布局：尾部 65 字节必须是「`0x00` 类型标签 + 64 字节全零占位签名」，
    /// 前面是完整的交易体。这条断言直接决定 agent 的「覆盖最后 64 字节」是否成立。
    #[test]
    fn placeholder_signature_occupies_the_trailing_65_bytes() {
        let unsigned = fixed_unsigned();
        let shell = decode_prefixed(&unsigned.unsigned_tx_hex);

        // 留出余量判断：外壳一定比签名长（交易体本身就有上百字节）。
        assert!(shell.len() > 65);
        let tail = &shell[shell.len() - 65..];

        // `0x00` 是 near-crypto 里 ed25519 签名的 borsh 类型标签。
        assert_eq!(tail[0], 0x00, "签名类型标签必须是 ed25519 的 0x00");
        assert!(
            tail[1..].iter().all(|b| *b == 0),
            "占位签名的 64 字节必须全零"
        );

        // 前面部分必须能反序列化成一个 `Transaction`（证明它没有多/少任何字段）。
        let body = &shell[..shell.len() - 65];
        let tx: Transaction = borsh::from_slice(body).unwrap();
        // `tx.nonce()` 返回的是 `TransactionNonce` 枚举（普通 key / gas key 两种），
        // 再 `.nonce()` 才取出里面的 u64。
        assert_eq!(tx.nonce().nonce(), TEST_NONCE);
        assert_eq!(tx.signer_id().as_str(), TEST_SIGNER);
        assert_eq!(tx.receiver_id().as_str(), TEST_RECEIVER);
    }

    /// **端到端复现**：模拟 agent 的完整操作（解码摘要 → ed25519 签名 → 覆盖尾部
    /// 64 字节），结果必须与官方 `SignedTransaction::new` 构造出的对象**逐字节相同**。
    ///
    /// 这条测试覆盖的是「文档里教给 agent 的那套操作是否真的能work」——
    /// 它同时验证了占位签名的位置、类型标签、以及 ed25519 签的是不是那 32 字节。
    #[test]
    fn splicing_a_signature_reproduces_the_official_signed_transaction() {
        let secret_key = SecretKey::from_seed(KeyType::ED25519, TEST_SEED);
        let signer_id: AccountId = TEST_SIGNER.parse().unwrap();
        let signer: Signer = InMemorySigner::from_secret_key(signer_id.clone(), secret_key);
        let public_key = signer.public_key();

        let unsigned = fixed_unsigned();
        let mut shell = decode_prefixed(&unsigned.unsigned_tx_hex);
        let payload = decode_prefixed(&unsigned.signing_payload_hex);

        // --- agent 侧操作 1：对这 32 字节做一次 ed25519 签名 ---
        // `signer.sign(..)` 就是裸 ed25519（内部没有再做任何哈希），
        // 与 agent 用自己的库签同一段字节是等价的。
        let signature = signer.sign(&payload);
        // 取出签名的 64 个原始字节：走 borsh 编码再跳过 1 字节类型标签，
        // 免去直接依赖 `ed25519_dalek`（near-crypto 没有再导出它）。
        let signature_bytes = borsh::to_vec(&signature).unwrap();
        assert_eq!(signature_bytes.len(), 65);

        // --- agent 侧操作 2：覆盖外壳的最后 64 字节 ---
        let tail = shell.len() - 64;
        shell[tail..].copy_from_slice(&signature_bytes[1..]);

        // --- SDK 侧：反序列化并广播前的自检 ---
        let spliced: SignedTransaction = borsh::from_slice(&shell).unwrap();

        // --- 与官方路径对拍 ---
        let official = SignedTransaction::new(
            signer.sign(payload.as_slice()),
            unsigned_transaction(
                TEST_NONCE,
                CryptoHash([0xab; 32]),
                signer_id,
                public_key.clone(),
                TEST_RECEIVER.parse().unwrap(),
                vec![Action::Transfer(TransferAction {
                    deposit: Balance::from_yoctonear(parse_near(TEST_AMOUNT).unwrap()),
                })],
            ),
        );
        assert_eq!(spliced.signature, official.signature);
        assert_eq!(spliced.get_hash(), official.get_hash());
        // 逐字节比较序列化结果——比逐字段比较更严格。
        assert_eq!(borsh::to_vec(&spliced).unwrap(), borsh::to_vec(&official).unwrap());

        // 最后确认：签名能验过，且覆盖的正是我们声明的那 32 字节摘要。
        assert!(spliced.signature.verify(&payload, &public_key));
    }

    /// 外壳必须能被重新反序列化，且保留全部关键字段（nonce / 账户 / 金额）。
    ///
    /// 这是一条「格式闭环」测试：它保证 `unsigned_tx_hex` 与 `broadcast_raw`
    /// 之间走的是同一个编码，不会出现「构造出来、广播时解不开」。
    #[test]
    fn shell_round_trips_through_borsh() {
        let unsigned = fixed_unsigned();
        let signed: SignedTransaction = borsh::from_slice(&decode_prefixed(&unsigned.unsigned_tx_hex))
            .expect("外壳必须能反序列化成 SignedTransaction");

        assert_eq!(signed.transaction.nonce().nonce(), TEST_NONCE);
        assert_eq!(signed.transaction.signer_id().as_str(), TEST_SIGNER);
        assert_eq!(signed.transaction.receiver_id().as_str(), TEST_RECEIVER);
        assert_eq!(
            signed.transaction.public_key().clone(),
            unsigned.public_key
        );
        // 交易体锚定的区块哈希必须与返回给调用方的一致。
        assert_eq!(signed.transaction.block_hash(), &CryptoHash([0xab; 32]));
    }
}
