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

// `FromStr` 必须引入作用域，才能对 `SecretKey` 调用 `.parse()` / `from_str(..)`。
use std::str::FromStr;

use anyhow::{Context, Result};
// `InMemorySigner`：把私钥放在内存里的签名器实现；
// `SecretKey`：私钥枚举（ed25519 / secp256k1）；
// `Signer`：签名器 trait，提供 `public_key()` 与 `sign()`。
use near_crypto::{InMemorySigner, SecretKey, Signer};
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

    // `Transaction::V0(TransactionV0 { .. })`：NEAR 的交易结构体带**版本枚举**，
    // 为将来的协议升级留出空间（类似 Solana 的 legacy / v0 交易）。
    // 目前只有 V0 一种。
    let unsigned = Transaction::V0(TransactionV0 {
        signer_id: signer_id.clone(),
        // 交易的公钥字段必须与签名所用密钥匹配，节点会据此找到对应的 access key。
        public_key: signer.public_key(),
        nonce,
        receiver_id: receiver_id.clone(),
        // 锚定最新区块哈希。
        block_hash: status.sync_info.latest_block_hash,
        // `actions` 是 `Vec<Action>`，**按值移入**（不需要 clone，因为我们拥有它）。
        actions,
    });

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
}
