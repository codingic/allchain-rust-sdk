//! CKB **无私钥两段式**转账的纯逻辑：构造 → 交出待签摘要 → 回填签名。
//!
//! 与一体式 `transfer` 的关系：两者共用同一批 ckb-sdk 组件，只是把
//! 「签名」这一步从 SDK 内部挪到了调用方（agent）。私钥从头到尾不进 SDK。
//!
//! # CKB 签名的三个反直觉事实
//!
//! 这三点决定了本模块的形态，任何一点理解错都会产出「能构造、能广播、
//! 但节点永远拒绝」的交易：
//!
//! ## 1. 要签的不是交易哈希，而是一段拼出来的 witness 摘要
//!
//! `secp256k1_blake160_sighash_all` 锁脚本验签时，节点算的是（官方
//! `ckb-sdk` `unlock::generate_message`，本模块直接调用它、不自己复刻）：
//!
//! ```text
//! blake2b(
//!     tx.hash()                                  // 32B，不含 witness
//!  || u64_le(len(init_witness))                  // 8B
//!  || init_witness                               // 首个 witness，lock 字段置为 65 个零
//!  || Σ ( u64_le(len(w)) || w )                  // 本组其余 witness
//!  || Σ ( u64_le(len(w)) || w )                  // 未被任何 input 覆盖的 witness
//! )
//! ```
//!
//! 即：**同一笔交易的每个 lock group 各有一个不同的待签摘要**。
//! 若交易有 3 个不同所有者的 input，agent 就要签 3 次。
//! 这也是 `SubmitRequest.signatures` 是数组的原因。
//!
//! ## 2. 交易哈希不含 witness，签名前后不变
//!
//! CKB 的 `tx.hash()` 只对「raw transaction」（inputs / outputs / cell_deps /
//! header_deps）取哈希，witness 不在其中。这与比特币（segwit 后 txid 不含
//! witness，但 wtxid 含）和以太坊（签名改变 tx hash）都不同。
//!
//! 好处：**构造完就能算出最终上链的交易哈希**，可以在签名前就回显给调用方，
//! 广播后节点返回的也是同一个值，可直接对账。
//!
//! ## 3. 签名是 65 字节可恢复签名，recovery id 不加 27
//!
//! 与 Filecoin 相同（`r(32) || s(32) || v(1)`，`v ∈ 0..=3`），
//! 与以太坊 EIP-155 的 `v = 27/28 + chain_id*2` 不同。
//! 链上靠 `v` 从签名反推公钥，再算 `blake160(pubkey)` 与锁脚本的
//! `args` 比对——**交易里根本不带公钥**，所以 recovery id 是必需的。
//!
//! # 为什么不能用官方 `SecpSighashUnlocker`
//!
//! 官方 `SecpSighashUnlocker` 的 `match_args` 会转问 `Signer::match_id`，
//! 而 `SecpCkbRawKeySigner::match_id` 是查「我手里有哪把私钥」。
//! 也就是说：**官方 unlocker 必须持有私钥才能认领这个锁**。
//! 两段式流程里 SDK 恰恰没有私钥，于是需要 `PlaceholderUnlocker`
//! ——它只认「args 长度是 20 字节」这一脚本形态，不认人。

use async_trait::async_trait;
use ckb_types::{
    bytes::Bytes,
    core::TransactionView,
    packed::{Script, Transaction},
    prelude::*,
};
use serde::{Deserialize, Serialize};

use allchain_core::{ErrorCode, SdkError, hexutil};

use official_ckb_sdk::{
    traits::TransactionDependencyProvider,
    types::{ScriptGroup, ScriptGroupType},
    unlock::{ScriptUnlocker, UnlockError, fill_witness_lock, generate_message},
};

use crate::address;

/// secp256k1 可恢复签名长度：`r(32) || s(32) || v(1)`。
pub const SIGNATURE_LEN: usize = 65;
/// recovery id 的合法上界。CKB 与 Filecoin 一样 **不加 27**。
pub const MAX_RECOVERY_ID: u8 = 3;
/// 待签摘要长度（blake2b-256 输出）。
pub const DIGEST_LEN: usize = 32;
/// secp256k1_blake160 单签锁的 `args` 长度：blake160(压缩公钥) = 20 字节。
pub const LOCK_ARGS_LEN: usize = 20;
/// 占位 witness 中 `lock` 字段的长度（65 字节全零，与签名等长，
/// 好让「平衡容量」阶段算出的交易体积与最终一致）。
pub const PLACEHOLDER_LOCK_LEN: usize = 65;

/// 一个 lock group 的待签信息。
///
/// 之所以不直接序列化官方 `ScriptGroup`：它只派生了
/// `Clone / Eq / PartialEq / Debug`，**没有** serde 的
/// `Serialize`/`Deserialize`，无法进 JSON 上下文。而上下文要跨进程
/// （SDK → agent → SDK）传输，必须能序列化，故在此定义等价结构。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignGroup {
    /// 锁脚本的 molecule 字节（十六进制，带 `0x`）。可无损还原 `packed::Script`。
    pub script_hex: String,
    /// 锁脚本的 `args`（即 blake160）。冗余存一份：验签时要用它比对，
    /// 免得每次都从 `script_hex` 解一遍。
    pub args_hex: String,
    /// 该组覆盖的 input 下标。`[0]` 是签名要写入的那个 witness 位置。
    pub input_indices: Vec<usize>,
    /// 32 字节待签摘要（十六进制，带 `0x`）。
    pub signing_digest: String,
}

/// `build_transfer` → `submit_tx` 之间要传递的全部信息。
///
/// 领域说明：为什么必须把它整体回传，而不是只回传 `unsigned_tx_hex`
/// 让 submit 时重新推导——因为 `gen_script_groups` 需要**逐个 input 回溯
/// 前序交易**才能拿到被花费 cell 的 lock script。submit 时重新查一遍，
/// 不仅多花 N 次 RPC，更糟的是：若期间有 cell 被花费，查到的就是
/// 另一份数据，签出来的摘要与交易对不上。上下文记下来才是原子的。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitContext {
    /// 构造时使用的网络名。submit 时用于拦截「主网构造、测试网广播」。
    pub network: String,
    /// 未签名交易的 molecule 字节（十六进制，带 `0x`），witness 里是 65 字节占位。
    pub tx_hex: String,
    /// 交易哈希。CKB 的哈希**不含 witness**，故签名前后一致，
    /// 可以当作这份上下文的完整指纹（见 `rebuild_transaction`）。
    pub tx_hash: String,
    /// 按 `input_indices[0]` 升序排列的待签组。顺序即签名的对应顺序。
    pub groups: Vec<SignGroup>,
    /// 发送方地址。
    pub from: String,
    /// 接收方地址。
    pub to: String,
    /// 转账金额（shannon）。
    pub amount_shannon: String,
}

/// 只填占位 witness 的 unlocker——**不持有、也不需要私钥**。
///
/// 领域说明：CKB 的手续费按交易体积算，而签名占 65 字节。
/// 所以必须「先用 65 字节占位符把交易体积算准」，再去平衡容量与找零，
/// 否则最后填进真签名时交易变大，手续费就不够了。
/// 这就是官方 `build_balanced` 里 `fill_placeholder_witnesses` 那一层的意义。
pub struct PlaceholderUnlocker;

// `#[async_trait]` 是必需的：官方 `ScriptUnlocker` trait 本身用它标注过。
// 少了这一行，实现里的 `async fn` 不会被自动改写成
// `Pin<Box<dyn Future + Send>>`，编译器会说「返回类型不匹配」。
#[async_trait]
impl ScriptUnlocker for PlaceholderUnlocker {
    /// 只按**脚本形态**认领：secp256k1_blake160 单签锁的 args 恰好 20 字节。
    ///
    /// 对比官方 `SecpSighashUnlocker::match_args`，它多一步
    /// `self.signer.match_id(args)`，即「这笔锁是不是我的私钥对应的」。
    /// 这里做不到也不该做——SDK 没有私钥。
    fn match_args(&self, args: &[u8]) -> bool {
        args.len() == LOCK_ARGS_LEN
    }

    /// 两段式流程里永远不会走到这里：签名由 agent 完成。
    ///
    /// 写成显式报错而非 `unimplemented!()`：`unimplemented!()` 触发的是
    /// panic，会直接打断 MCP / HTTP server 的进程；返回 `Err` 则会
    /// 被上层转成正常的错误响应。
    async fn unlock_async(
        &self,
        _tx: &TransactionView,
        _script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        Err(UnlockError::Other(anyhow::anyhow!(
            "PlaceholderUnlocker 只负责填占位 witness，签名应由调用方完成"
        )))
    }

    /// 填入 65 字节全零的 `lock` 字段——与官方 `SecpSighashUnlocker` 逐字节一致
    /// （`fill_witness_lock(tx, group, Bytes::from(vec![0u8; 65]))`），
    /// 因此这里直接复用官方函数，不自己拼 molecule。
    async fn fill_placeholder_witness_async(
        &self,
        tx: &TransactionView,
        script_group: &ScriptGroup,
        _tx_dep_provider: &dyn TransactionDependencyProvider,
    ) -> Result<TransactionView, UnlockError> {
        fill_witness_lock(
            tx,
            script_group,
            Bytes::from(vec![0u8; PLACEHOLDER_LOCK_LEN]),
        )
    }
}

/// 计算某个 lock group 的 32 字节待签摘要。
///
/// 直接委托给官方 `generate_message`，**不自己复刻哈希拼接**。
/// 理由：这段拼接有五段、涉及两处小端 `u64` 长度前缀与两类 witness 分组，
/// 手写时任何一处偏差都会产出「长度仍是 32 字节、但链上永远验不过」的值。
/// 官方函数还在，就没有理由抄一份可能抄错的实现。
pub fn group_signing_digest(
    tx: &TransactionView,
    script_group: &ScriptGroup,
) -> Result<[u8; DIGEST_LEN], SdkError> {
    let digest = generate_message(tx, script_group, Bytes::from(vec![0u8; PLACEHOLDER_LOCK_LEN]))
        .map_err(|e| SdkError::new(ErrorCode::ParseError, format!("计算待签摘要失败: {e}")))?;
    // `try_into()`：`Bytes`（变长）→ `[u8; 32]`（定长）。可能失败，故返回 Result。
    let arr: [u8; DIGEST_LEN] = digest
        .to_vec()
        .try_into()
        .map_err(|_| SdkError::new(ErrorCode::ParseError, "待签摘要不是 32 字节"))?;
    Ok(arr)
}

/// 把官方 `ScriptGroup` 转成可序列化的 `SignGroup`。
///
/// 语法说明：`&ScriptGroup` 是不可变借用——函数只读它，不取得所有权，
/// 调用方之后还能继续用。若写成 `ScriptGroup`（值），调用方就得
/// 先 `clone()`，白白复制一份 script 与两个下标数组。
pub fn to_sign_group(
    tx: &TransactionView,
    script_group: &ScriptGroup,
) -> Result<SignGroup, SdkError> {
    let digest = group_signing_digest(tx, script_group)?;
    let args = script_group.script.args().raw_data();
    Ok(SignGroup {
        // `as_bytes()` 来自 `Entity` trait：取 molecule 序列化后的字节。
        // 注意它返回 `Bytes`（值），而 `hexutil` 收 `&[u8]`，所以要补一个 `&`
        // ——`&Bytes` 会经 `Deref` 自动转成 `&[u8]`，但 `Bytes` 本身不会。
        script_hex: hexutil::encode_hex_prefixed(&script_group.script.as_bytes()),
        args_hex: hexutil::encode_hex_prefixed(&args),
        input_indices: script_group.input_indices.clone(),
        signing_digest: hexutil::encode_hex_prefixed(&digest),
    })
}

/// 由序列化形态还原官方 `ScriptGroup`（供 `fill_witness_lock` / `generate_message` 使用）。
///
/// 领域说明：`ScriptGroup::from_lock_script` 只填 `script` 与 `group_type`，
/// `input_indices` 是空的——而 `fill_witness_lock` 正是靠 `input_indices[0]`
/// 决定「往第几个 witness 里写签名」。漏了这一步会把签名写到
/// witness 0（最典型的表现是：交易能广播，节点报 `InvalidSignature`）。
pub fn rebuild_script_group(group: &SignGroup) -> Result<ScriptGroup, SdkError> {
    let script = decode_script(&group.script_hex)?;
    let mut rebuilt = ScriptGroup::from_lock_script(&script);
    rebuilt.input_indices = group.input_indices.clone();
    // group_type 在 `from_lock_script` 里已设为 Lock，这里断言一次：
    // 若哪天上游改了默认行为，宁可立刻失败，也不要静默按错误类型处理。
    debug_assert_eq!(rebuilt.group_type, ScriptGroupType::Lock);
    Ok(rebuilt)
}

/// 交易 → molecule 十六进制（带 `0x`）。
pub fn encode_transaction(tx: &TransactionView) -> String {
    hexutil::encode_hex_prefixed(&tx.data().as_bytes())
}

/// 把签名**覆盖式**写回该 lock group 的第一个 witness。
///
/// # 为什么不能复用官方 `fill_witness_lock`
///
/// 官方 `fill_witness_lock` 内部是
/// `if witness.lock().is_none() { ..填.. }`——**只在 lock 字段为空时才写**。
/// 它天生是给「填 65 字节占位」这一步用的（那时 lock 恰好是空的）。
///
/// 而回填真签名时，lock 字段里已经躺着 65 个零字节，`is_none()` 为 false，
/// 于是函数**静默地什么都不做**：交易原封不动地返回，没有报错、
/// 没有警告，广播后节点报 `InvalidSignature`，排查时很难想到
/// 「签名其实根本没写进去」。这是本模块踩过的真实坑。
///
/// 因此这里自己实现，且**无条件覆盖** lock 字段。
/// 逻辑与官方 `SecpSighashScriptSigner::sign_tx_with_owner_id` 的收尾一致
/// （它也是覆盖而非填入），`tx.rs` 里有逐字节对拍测试守着这一点。
pub fn fill_signature(
    tx: &TransactionView,
    script_group: &ScriptGroup,
    signature: &[u8; SIGNATURE_LEN],
) -> Result<TransactionView, SdkError> {
    let witness_idx = script_group.input_indices[0];
    let mut witnesses: Vec<ckb_types::packed::Bytes> = tx.witnesses().into_iter().collect();
    // 占位阶段保证过 witness 数量足够，但上下文可能来自外部，
    // 这里再兜一次，避免下标越界 panic。
    while witnesses.len() <= witness_idx {
        witnesses.push(Default::default());
    }
    let witness_data = witnesses[witness_idx].raw_data();
    let witness = if witness_data.is_empty() {
        ckb_types::packed::WitnessArgs::default()
    } else {
        ckb_types::packed::WitnessArgs::from_slice(witness_data.as_ref()).map_err(|e| {
            SdkError::new(
                ErrorCode::ParseError,
                format!("第 {witness_idx} 个 witness 不是合法的 WitnessArgs: {e}"),
            )
        })?
    };
    // 与 `fill_witness_lock` 的唯一实质差别：这里**没有** `is_none()` 守卫。
    let filled = witness
        .as_builder()
        .lock(Some(Bytes::from(signature.to_vec())).pack())
        .build();
    witnesses[witness_idx] = filled.as_bytes().pack();
    Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
}

/// molecule 十六进制 → 交易。
pub fn decode_transaction(raw: &str) -> Result<TransactionView, SdkError> {
    let body = raw.trim();
    let bytes = hexutil::decode_hex(body)
        .map_err(|e| SdkError::invalid_argument(format!("CKB 交易不是合法十六进制: {e}")))?;
    // `Entity::from_slice` 会校验 molecule 的 total_size 与各字段 offset，
    // 数据被截断或篡改时在这里就失败，不会带着坏数据走到广播。
    let packed = Transaction::from_slice(&bytes).map_err(|e| {
        SdkError::new(ErrorCode::ParseError, format!("解析 CKB 交易失败: {e}"))
    })?;
    // `into_view()` 是 molecule 类型 → 便捷视图的转换，后者才缓存哈希。
    Ok(packed.into_view())
}

/// 还原交易并做**哈希自检**：确认它与构造时记录的是同一笔。
///
/// 领域说明：这是「上下文被篡改」的最后一道闸。上下文会经过 agent 的手，
/// 可能被存数据库、可能跨进程传输。若 `tx_hex` 被换成另一笔交易，
/// 签名与摘要就都对不上（表现为含糊的验签失败）。
/// 这里先比对哈希，能把故障定位到「交易被换了」而不是「签名有问题」。
pub fn rebuild_transaction(context: &SubmitContext) -> Result<TransactionView, SdkError> {
    let tx = decode_transaction(&context.tx_hex)?;
    let actual = format!("0x{:x}", tx.hash());
    // 大小写不敏感比较：上下文可能经过大小写不敏感的中间件。
    if !actual.eq_ignore_ascii_case(&context.tx_hash) {
        return Err(SdkError::invalid_argument(format!(
            "上下文自检失败：交易体算出的哈希({actual})与记录的哈希({})不一致，\
             交易内容可能被替换",
            context.tx_hash
        )));
    }
    Ok(tx)
}

/// 十六进制 → `packed::Script`。
pub fn decode_script(raw: &str) -> Result<Script, SdkError> {
    let bytes = hexutil::decode_hex(raw.trim())
        .map_err(|e| SdkError::invalid_argument(format!("CKB 锁脚本不是合法十六进制: {e}")))?;
    Script::from_slice(&bytes)
        .map_err(|e| SdkError::new(ErrorCode::ParseError, format!("解析 CKB 锁脚本失败: {e}")))
}

/// 解析上下文里的摘要字段（带或不带 `0x` 前缀）→ 32 字节数组。
///
/// 领域说明：摘要在上下文里是十六进制字符串（要给人看、要进 JSON），
/// 但签名与验签都要的是定长字节数组。这层转换集中在一处，
/// 免得调用方各写一份、各自处理 `0x` 前缀与长度校验。
pub fn decode_digest_hex(raw: &str) -> Result<[u8; DIGEST_LEN], SdkError> {
    let body = raw.trim();
    let bytes = hexutil::decode_hex(body)
        .map_err(|e| SdkError::invalid_argument(format!("上下文里的待签摘要非法: {e}")))?;
    // 先取长度再 `try_into`：后者会**移动** `bytes`，
    // 之后就再也不能读 `bytes.len()` 了（借用检查器会拒绝）。
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| SdkError::invalid_argument(format!("待签摘要需为 {DIGEST_LEN} 字节，实际 {len} 字节")))
}

/// 解析 agent 给的 65 字节签名。
///
/// 领域说明：`v > 3` 的显式校验是有针对性的——
/// 以太坊生态的库普遍在 recovery id 上加 27 或 `chain_id * 2 + 35`。
/// 这类值在 `RecoverableSignature::from_compact` 里**未必**报错，
/// 但恢复出的公钥是错的，最终表现是「签名有效、广播被拒」，
/// 从错误信息完全看不出根因。这里提前拦下并说明。
pub fn parse_signature(raw: &str) -> Result<[u8; SIGNATURE_LEN], SdkError> {
    let body = raw.trim();
    let bytes = hexutil::decode_hex(body)
        .map_err(|e| SdkError::invalid_argument(format!("CKB 签名不是合法十六进制: {e}")))?;
    if bytes.len() != SIGNATURE_LEN {
        return Err(SdkError::invalid_argument(format!(
            "CKB 签名需为 {SIGNATURE_LEN} 字节（r||s||v），实际 {} 字节",
            bytes.len()
        )));
    }
    let recovery_id = bytes[SIGNATURE_LEN - 1];
    if recovery_id > MAX_RECOVERY_ID {
        return Err(SdkError::invalid_argument(format!(
            "CKB 签名的 recovery id 需为 0..={MAX_RECOVERY_ID}（CKB 不加 27），收到 {recovery_id}；\
             若你的签名库来自以太坊生态，请把 v 减 27"
        )));
    }
    let mut out = [0u8; SIGNATURE_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// 由摘要与签名恢复出**压缩公钥**（33 字节）。
///
/// 领域说明：这正是 CKB 节点做的第一步。账户地址是公钥的哈希，
/// 交易里不带公钥，节点只能靠 recovery id 反推。
/// 所以「能恢复出公钥」本身就说明签名在数学上是自洽的，
/// 但**还不能**说明签名人对——那是 `verify_signature` 的事。
pub fn recover_pubkey(
    digest: &[u8; DIGEST_LEN],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<Vec<u8>, SdkError> {
    use secp256k1::{Message, Secp256k1, ecdsa::RecoverableSignature, ecdsa::RecoveryId};

    // `Secp256k1::new()` 会生成 secp256k1 的查表上下文，开销不小（毫秒级），
    // 所以只在这里建一次。注意它**不需要** `signing` feature：
    // 只做验签/恢复时，`Secp256k1::verification_only()` 更快，
    // 但签名的构造可能发生在同一上下文，统一用 `new()` 更省心。
    let secp = Secp256k1::new();
    // `RecoveryId` 只实现了 `TryFrom<i32>`（见 secp256k1 0.30 的
    // `ecdsa/recovery.rs`），没有 `from_i32` / `from_u8` 这样的命名构造器，
    // 所以这里走 trait 转换。虽然 `parse_signature` 已经拦过 `v <= 3`，
    // 但 `recover_pubkey` 是 `pub`，独立调用时仍要自己兜住非法值。
    let recovery_id = RecoveryId::try_from(i32::from(signature[SIGNATURE_LEN - 1])).map_err(|e| {
        SdkError::invalid_argument(format!(
            "非法的 recovery id {}: {e}（需为 0..={MAX_RECOVERY_ID}）",
            signature[SIGNATURE_LEN - 1]
        ))
    })?;
    let sig = RecoverableSignature::from_compact(&signature[..64], recovery_id)
        .map_err(|e| SdkError::invalid_argument(format!("解析签名的 r||s 失败: {e}")))?;
    // `Message::from_digest` 收的是**已经哈希过**的 32 字节摘要，
    // 内部不会再哈希。对应的 `from_digest_slice` / `from_hashed_data` 语义不同，
    // 用错会得到一对「都跑得通、结果无关」的函数。
    let message = Message::from_digest(*digest);
    let pubkey = secp
        .recover_ecdsa(&message, &sig)
        .map_err(|e| SdkError::invalid_argument(format!("由签名恢复公钥失败: {e}")))?;
    // `serialize()` 给出**压缩**格式（33 字节），正是 blake160 的输入。
    // 若误用 `serialize_uncompressed()`（65 字节），派生出的地址会完全不同。
    Ok(pubkey.serialize().to_vec())
}

/// 验签：恢复公钥 → `blake160` → 与锁脚本的 `args` 比对。
///
/// 领域说明：这是**端到端**的正确性证明，也是 CKB 与账户模型链的关键差异。
/// 交易里没有任何「付款人」字段——付款人身份完全由
/// 「签名的公钥哈希 == 被花费 cell 的 lock args」这一等式确立。
/// 只检查「签名格式合法」或「签名能恢复出公钥」都说明不了任何事：
/// 真正的风险是「签名有效，但签的是别人的锁」，
/// 此时交易结构完好、广播后节点会报 `InvalidSignature`，
/// 白白浪费一次 RPC 与调用方的排查时间。
pub fn verify_signature(
    digest: &[u8; DIGEST_LEN],
    signature: &[u8; SIGNATURE_LEN],
    lock_args: &[u8],
) -> Result<String, SdkError> {
    let pubkey = recover_pubkey(digest, signature)?;
    let blake160 = address::ckb_blake160(&pubkey);
    if blake160 != lock_args {
        return Err(SdkError::invalid_argument(format!(
            "签名验证失败：签名恢复出的 blake160({}) 与锁脚本的 args({}) 不一致，\
             这笔签名不属于该 cell 的所有者",
            hexutil::encode_hex_prefixed(&blake160),
            hexutil::encode_hex(lock_args),
        )));
    }
    Ok(hexutil::encode_hex_prefixed(&blake160))
}

// 单元测试：`#[cfg(test)]` 保证只在 `cargo test` 时编译。
#[cfg(test)]
mod tests {
    use super::*;

    use ckb_types::core::{ScriptHashType, TransactionBuilder};
    use ckb_types::packed::{CellInput, CellOutput, OutPoint};
    use official_ckb_sdk::constants::SIGHASH_TYPE_HASH;
    use official_ckb_sdk::traits::SecpCkbRawKeySigner;
    use official_ckb_sdk::unlock::{ScriptSigner, SecpSighashScriptSigner};
    use official_ckb_sdk::util::serialize_signature;
    use secp256k1::{Secp256k1, SecretKey};

    use crate::address::LockScript;

    /// 测试私钥。取自公开的 ganache 测试账户 #0，**不含任何真实资产**。
    ///
    /// 为什么不用 `0x00..01` 这种「好看」的私钥：上下文里含交易字节的十六进制，
    /// 而占位 witness 是 65 个零字节（= 130 个连续的 `0` 字符）。
    /// 若私钥本身也以长串零开头，下面那条「上下文中不含私钥」的断言
    /// 就会与这些零串**误撞**——测试红得莫名其妙。
    /// 用非零私钥可以从根上避开这类假阳性。
    const TEST_PRIVKEY: &str =
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d";
    /// 测试私钥（公开 ganache 账户 #1），用于造「签名人不对」的反例。
    const OTHER_PRIVKEY: &str =
        "6cbed15c793ce57650b9877cf6fa156fbef513c4e6134f022a85b1ffdd59b2a1";

    fn test_secret(hex_priv: &str) -> SecretKey {
        SecretKey::from_slice(&hexutil::decode_hex(hex_priv).unwrap()).unwrap()
    }

    fn test_blake160(hex_priv: &str) -> [u8; 20] {
        let key = test_secret(hex_priv);
        let secp = Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &key);
        address::ckb_blake160(&pubkey.serialize())
    }

    fn sighash_script(args: [u8; 20]) -> Script {
        Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type)
            .args(Bytes::from(args.to_vec()).pack())
            .build()
    }

    /// 造一笔**纯离线**的假交易：2 个 input，两者锁脚本相同（同一个所有者），
    /// witness 已填好 65 字节占位。不涉及任何 RPC。
    fn sample_tx(args: [u8; 20]) -> TransactionView {
        let lock = sighash_script(args);
        let placeholder = ckb_types::packed::WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; PLACEHOLDER_LOCK_LEN])).pack())
            .build();
        TransactionBuilder::default()
            .input(CellInput::new(OutPoint::new(Default::default(), 0), 0))
            .input(CellInput::new(OutPoint::new(Default::default(), 1), 0))
            .output(CellOutput::new_builder().lock(lock).capacity(100u64).build())
            .output_data(Bytes::default())
            .witness(placeholder.as_bytes().pack())
            .witness(placeholder.as_bytes().pack())
            .build()
    }

    /// agent 侧的签名动作：拿 32 字节摘要，用私钥签出 65 字节可恢复签名。
    fn agent_sign(digest: &[u8; DIGEST_LEN], hex_priv: &str) -> [u8; SIGNATURE_LEN] {
        use secp256k1::Message;
        let key = test_secret(hex_priv);
        let message = Message::from_digest(*digest);
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa_recoverable(&message, &key);
        // 用官方 `serialize_signature` 拼字节，而不是自己拼：
        // `RecoverableSignature::serialize_compact()` 返回的是
        // `(RecoveryId, [u8; 64])` **元组**，需要自己把 recovery id
        // 追加到第 65 位（`i32::from(recid) as u8`）。官方函数封装好了这一步，
        // 用它就与 `SecpCkbRawKeySigner` 的产出完全同源。
        serialize_signature(&sig)
    }

    fn sample_group(args: [u8; 20], input_indices: Vec<usize>) -> ScriptGroup {
        let mut group = ScriptGroup::from_lock_script(&sighash_script(args));
        group.input_indices = input_indices;
        group
    }

    /// **对拍**：两段式路径产出的交易，必须与官方一体式签名器逐字节相同。
    ///
    /// 这是本模块最重要的一条测试。它把「我手写的摘要计算 / 签名解析 /
    /// witness 回填」整条链路与官方 `SecpSighashScriptSigner` 对齐：
    /// 只要任何一步有偏差，两边的 molecule 字节就会不同。
    ///
    /// 注意它**不需要**外部真值常量——官方实现本身就是参照物。
    #[test]
    fn two_stage_path_matches_the_official_signer_byte_for_byte() {
        let args = test_blake160(TEST_PRIVKEY);
        let tx = sample_tx(args);
        let group = sample_group(args, vec![0, 1]);

        // 路径 A（官方一体式）：私钥进 SDK，官方签名器一次做完。
        let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![test_secret(TEST_PRIVKEY)]);
        let script_signer = SecpSighashScriptSigner::new(Box::new(signer));
        let official_tx = script_signer.sign_tx(&tx, &group).unwrap();

        // 路径 B（两段式）：SDK 只算摘要 → agent 签名 → SDK 回填。
        let digest = group_signing_digest(&tx, &group).unwrap();
        let signature = agent_sign(&digest, TEST_PRIVKEY);
        let two_stage_tx = fill_signature(&tx, &group, &signature).unwrap();

        assert_eq!(
            official_tx.data().as_bytes(),
            two_stage_tx.data().as_bytes(),
            "两段式路径必须与官方签名器产出完全相同的交易字节"
        );
        // 反证一：换个私钥，交易字节必须不同——否则这条断言是恒真的。
        let wrong = agent_sign(&digest, OTHER_PRIVKEY);
        let wrong_tx = fill_signature(&tx, &group, &wrong).unwrap();
        assert_ne!(official_tx.data().as_bytes(), wrong_tx.data().as_bytes());
        // 反证二：签名必须真的进了 witness。
        // 少了这条，若回填函数静默失效（比如误用 `fill_witness_lock`），
        // 上面的 assert_eq 仍能捕获，但失败信息会指向「字节不同」而非
        // 「签名没写入」，排查方向完全不同。这里给出更精确的断言。
        let signed_witness = two_stage_tx
            .witnesses()
            .get(0)
            .map(|w| w.raw_data())
            .unwrap_or_default();
        assert!(
            signed_witness
                .windows(SIGNATURE_LEN)
                .any(|w| w == signature),
            "签名应出现在第 0 个 witness 中"
        );
    }

    /// 官方 `fill_witness_lock` 的语义陷阱：**只填空的 lock 字段，不覆盖**。
    ///
    /// 领域说明：这条测试把上面那段注释里描述的行为固化下来。
    /// 若将来升级 ckb-sdk 后这个语义变了，`fill_signature` 的
    /// 存在理由也随之改变——这里会立刻红，提醒重新评估。
    #[test]
    fn filling_a_non_empty_witness_lock_is_a_no_op_in_the_official_helper() {
        let args = test_blake160(TEST_PRIVKEY);
        let tx = sample_tx(args);
        let group = sample_group(args, vec![0, 1]);
        let digest = group_signing_digest(&tx, &group).unwrap();
        let signature = agent_sign(&digest, TEST_PRIVKEY);

        // 用官方 helper 去「回填」：因为 lock 字段已有 65 个零，它什么都不做。
        let attempted =
            fill_witness_lock(&tx, &group, Bytes::from(signature.to_vec())).unwrap();
        assert_eq!(
            attempted.data().as_bytes(),
            tx.data().as_bytes(),
            "官方 fill_witness_lock 遇到非空 lock 字段时应原样返回"
        );

        // 而我们自己的 `fill_signature` 必须真的把它写进去。
        let filled = fill_signature(&tx, &group, &signature).unwrap();
        assert_ne!(filled.data().as_bytes(), tx.data().as_bytes());
    }

    /// 交易哈希**不含 witness**：签名前后一致。
    ///
    /// 领域说明：这条性质是 `SubmitContext.tx_hash` 能当指纹用的前提。
    /// CKB 与以太坊相反（ETH 的 tx hash 随签名改变），值得单独锁死。
    #[test]
    fn the_tx_hash_does_not_change_when_signatures_are_filled_in() {
        let args = test_blake160(TEST_PRIVKEY);
        let tx = sample_tx(args);
        let group = sample_group(args, vec![0, 1]);
        let before = tx.hash();

        let digest = group_signing_digest(&tx, &group).unwrap();
        let signature = agent_sign(&digest, TEST_PRIVKEY);
        let signed = fill_signature(&tx, &group, &signature).unwrap();

        assert_eq!(before, signed.hash());
    }

    /// 待签摘要**不**依赖锁脚本本身，只依赖 `tx.hash()` 与各 witness 的布局。
    ///
    /// 领域说明：这是 CKB sighash_all 的一条重要语义，也是最容易猜错的地方。
    /// 直觉上「不同所有者的 input 该签不同的东西」，但实际上
    /// `generate_message` 只吸收：交易哈希 + 本组各 witness 的内容与位置。
    /// 锁脚本（含 args/blake160）**不在**哈希输入里——
    /// 身份是靠「恢复出的公钥 blake160 == 被花费 cell 的 lock args」在链上校验的，
    /// 不是靠把 args 签进去。
    ///
    /// 这条测试把这个事实固化下来：将来若有人「修正」成把 lock script 也算进去，
    /// 这里会立刻红。
    #[test]
    fn the_digest_does_not_depend_on_the_lock_script_itself() {
        let owner_a = test_blake160(TEST_PRIVKEY);
        let owner_b = test_blake160(OTHER_PRIVKEY);
        let tx = sample_tx(owner_a);

        // 两个 group 覆盖范围完全相同（都是 input 0），只有脚本不同。
        let group_a = sample_group(owner_a, vec![0]);
        let group_b = sample_group(owner_b, vec![0]);

        assert_eq!(
            group_signing_digest(&tx, &group_a).unwrap(),
            group_signing_digest(&tx, &group_b).unwrap(),
            "锁脚本不参与待签摘要的计算"
        );
    }

    /// 分组范围不同 → 摘要不同（本组其余 witness 会被吸收进哈希）。
    ///
    /// 这才是「多 input 各签一次」的真正来源：
    /// `generate_message` 会把本组 **input_indices[1..]** 对应的 witness
    /// 以 `u64_le(len) || data` 的形式逐个吸收。范围不同，摘要就不同。
    #[test]
    fn groups_covering_different_inputs_yield_different_digests() {
        let args = test_blake160(TEST_PRIVKEY);
        let tx = sample_tx(args);

        // 只覆盖 input 0：other_witnesses 为空。
        let narrow = sample_group(args, vec![0]);
        // 覆盖 input 0 与 1：other_witnesses 会多吸收 witness[1]。
        let wide = sample_group(args, vec![0, 1]);

        let digest_narrow = group_signing_digest(&tx, &narrow).unwrap();
        let digest_wide = group_signing_digest(&tx, &wide).unwrap();
        assert_ne!(digest_narrow, digest_wide);
    }

    /// 摘要随交易内容变化——锁死「摘要确实覆盖了交易体」。
    #[test]
    fn the_digest_covers_the_transaction_body() {
        let args = test_blake160(TEST_PRIVKEY);
        let tx = sample_tx(args);
        let group = sample_group(args, vec![0, 1]);
        let digest = group_signing_digest(&tx, &group).unwrap();

        // 改动输出 capacity（即改了交易体，但一个 witness 都没动）。
        let tweaked = tx
            .as_advanced_builder()
            .set_outputs(vec![
                CellOutput::new_builder()
                    .lock(sighash_script(args))
                    .capacity(999u64)
                    .build(),
            ])
            .build();
        assert_ne!(group_signing_digest(&tweaked, &group).unwrap(), digest);
    }

    /// 摘要也随 witness 变化——锁死「摘要覆盖了本组其余 witness」。
    ///
    /// 领域说明：这是 CKB 与比特币 legacy sighash 的重大差异。
    /// CKB 的 sighash_all 把**本组所有 witness** 都纳入摘要，
    /// 因此「签名后别人再往同组塞一个 witness」是做不到的。
    #[test]
    fn the_digest_covers_the_other_witnesses_in_the_group() {
        let args = test_blake160(TEST_PRIVKEY);
        let tx = sample_tx(args);
        let group = sample_group(args, vec![0, 1]);
        let digest = group_signing_digest(&tx, &group).unwrap();

        // 只改 input 1 的 witness（本组第二个），input 0 的占位保持原样。
        let mut witnesses: Vec<ckb_types::packed::Bytes> =
            tx.witnesses().into_iter().collect::<Vec<_>>();
        witnesses[1] = Bytes::from(vec![7u8; 8]).pack();
        let tweaked = tx.as_advanced_builder().set_witnesses(witnesses).build();

        assert_ne!(group_signing_digest(&tweaked, &group).unwrap(), digest);
    }

    /// 端到端：签名 → 验签，恢复出的 blake160 与锁脚本 args 一致。
    #[test]
    fn a_valid_signature_verifies_against_the_lock_args() {
        let args = test_blake160(TEST_PRIVKEY);
        let tx = sample_tx(args);
        let group = sample_group(args, vec![0, 1]);
        let digest = group_signing_digest(&tx, &group).unwrap();
        let signature = agent_sign(&digest, TEST_PRIVKEY);

        let recovered = verify_signature(&digest, &signature, &args).unwrap();
        assert_eq!(recovered, hexutil::encode_hex_prefixed(&args));
    }

    /// 换了私钥，验签必须失败。
    #[test]
    fn a_signature_from_the_wrong_key_is_rejected() {
        let args = test_blake160(TEST_PRIVKEY);
        let tx = sample_tx(args);
        let group = sample_group(args, vec![0, 1]);
        let digest = group_signing_digest(&tx, &group).unwrap();
        let signature = agent_sign(&digest, OTHER_PRIVKEY);

        let err = verify_signature(&digest, &signature, &args).unwrap_err();
        assert!(
            err.to_string().contains("签名验证失败"),
            "错误信息应说明是签名与锁不匹配，实际: {err}"
        );
    }

    /// 以太坊风格的 recovery id（+27）必须被拒。
    #[test]
    fn an_ethereum_style_recovery_id_is_rejected() {
        let mut sig = [0u8; SIGNATURE_LEN];
        sig[SIGNATURE_LEN - 1] = 27;
        let raw = hexutil::encode_hex(&sig);
        let err = parse_signature(&raw).unwrap_err();
        assert!(err.to_string().contains("减 27"), "应给出可操作的提示: {err}");
    }

    #[test]
    fn malformed_signatures_are_rejected() {
        // 长度不对
        assert!(parse_signature("00ff").is_err());
        // 不是十六进制
        assert!(parse_signature(&"zz".repeat(SIGNATURE_LEN)).is_err());
        // 恰好 65 字节且 v 合法 → 通过
        let mut ok = [0u8; SIGNATURE_LEN];
        ok[SIGNATURE_LEN - 1] = 1;
        assert!(parse_signature(&hexutil::encode_hex(&ok)).is_ok());
        // 边界：v = 3 合法，v = 4 不合法
        ok[SIGNATURE_LEN - 1] = 3;
        assert!(parse_signature(&hexutil::encode_hex(&ok)).is_ok());
        ok[SIGNATURE_LEN - 1] = 4;
        assert!(parse_signature(&hexutil::encode_hex(&ok)).is_err());
    }

    /// 交易 molecule 编解码必须无损往返。
    #[test]
    fn transaction_encoding_roundtrips() {
        let args = test_blake160(TEST_PRIVKEY);
        let tx = sample_tx(args);
        let hex = encode_transaction(&tx);
        assert!(hex.starts_with("0x"));
        let back = decode_transaction(&hex).unwrap();
        assert_eq!(tx.data().as_bytes(), back.data().as_bytes());
        assert_eq!(tx.hash(), back.hash());
    }

    /// 被截断的交易必须报错，而不是带着坏数据往下走。
    #[test]
    fn a_truncated_transaction_is_rejected() {
        let args = test_blake160(TEST_PRIVKEY);
        let full = encode_transaction(&sample_tx(args));
        let truncated = &full[..full.len() - 8];
        assert!(decode_transaction(truncated).is_err());
    }

    /// `SignGroup` → `ScriptGroup` 往返必须保住 `input_indices`。
    ///
    /// 领域说明：`input_indices` 决定签名写进第几个 witness。
    /// 官方 `ScriptGroup::from_lock_script` 不会填它，
    /// 这个测试专门防「还原时忘了补回来」。
    #[test]
    fn sign_group_roundtrip_preserves_input_indices() {
        let args = test_blake160(TEST_PRIVKEY);
        let tx = sample_tx(args);
        let group = sample_group(args, vec![0, 1]);

        let sign_group = to_sign_group(&tx, &group).unwrap();
        assert_eq!(sign_group.input_indices, vec![0, 1]);
        assert_eq!(sign_group.args_hex, hexutil::encode_hex_prefixed(&args));

        let rebuilt = rebuild_script_group(&sign_group).unwrap();
        assert_eq!(rebuilt.input_indices, group.input_indices);
        assert_eq!(rebuilt.script.as_bytes(), group.script.as_bytes());
    }

    /// 上下文 JSON 往返：跨进程传输后依然可用。
    #[test]
    fn submit_context_survives_a_json_roundtrip() {
        let args = test_blake160(TEST_PRIVKEY);
        let tx = sample_tx(args);
        let group = sample_group(args, vec![0, 1]);
        let sign_group = to_sign_group(&tx, &group).unwrap();

        let context = SubmitContext {
            network: "mainnet".to_string(),
            tx_hex: encode_transaction(&tx),
            tx_hash: format!("0x{:x}", tx.hash()),
            groups: vec![sign_group],
            from: "ckb1from".to_string(),
            to: "ckb1to".to_string(),
            amount_shannon: "100000000".to_string(),
        };
        let json = serde_json::to_string(&context).unwrap();
        let back: SubmitContext = serde_json::from_str(&json).unwrap();

        assert_eq!(back.network, "mainnet");
        assert_eq!(back.groups.len(), 1);
        assert_eq!(back.groups[0].signing_digest, context.groups[0].signing_digest);
        // 还原出的交易仍通过哈希自检。
        assert!(rebuild_transaction(&back).is_ok());
    }

    /// 篡改交易体 → 哈希自检失败。
    #[test]
    fn tampering_with_the_tx_body_breaks_the_hash_self_check() {
        let args = test_blake160(TEST_PRIVKEY);
        let tx = sample_tx(args);
        let group = sample_group(args, vec![0, 1]);
        let sign_group = to_sign_group(&tx, &group).unwrap();

        let mut context = SubmitContext {
            network: "mainnet".to_string(),
            tx_hex: encode_transaction(&tx),
            tx_hash: format!("0x{:x}", tx.hash()),
            groups: vec![sign_group],
            from: "ckb1from".to_string(),
            to: "ckb1to".to_string(),
            amount_shannon: "100000000".to_string(),
        };
        // 把交易换成「给 999 shannon 的输出」，但哈希字段不改。
        let tweaked = tx
            .as_advanced_builder()
            .set_outputs(vec![
                CellOutput::new_builder()
                    .lock(sighash_script(args))
                    .capacity(999u64)
                    .build(),
            ])
            .build();
        context.tx_hex = encode_transaction(&tweaked);

        let err = rebuild_transaction(&context).unwrap_err();
        assert!(
            err.to_string().contains("上下文自检失败"),
            "应明确指出交易被替换: {err}"
        );
    }

    /// 契约测试：上下文里绝不能出现私钥。
    ///
    /// 领域说明：这是本模块存在的全部理由。上下文会被序列化成 JSON
    /// 发给 agent、可能被写进日志与数据库。一旦私钥混入，
    /// 「无私钥两段式」的设计就整体失效了。
    #[test]
    fn context_never_carries_the_private_key() {
        let args = test_blake160(TEST_PRIVKEY);
        let tx = sample_tx(args);
        let group = sample_group(args, vec![0, 1]);
        let sign_group = to_sign_group(&tx, &group).unwrap();

        let context = SubmitContext {
            network: "mainnet".to_string(),
            tx_hex: encode_transaction(&tx),
            tx_hash: format!("0x{:x}", tx.hash()),
            groups: vec![sign_group],
            from: "ckb1from".to_string(),
            to: "ckb1to".to_string(),
            amount_shannon: "100000000".to_string(),
        };
        let json = serde_json::to_string(&context).unwrap();
        assert!(
            !json.contains(TEST_PRIVKEY),
            "上下文中不应出现私钥：{json}"
        );
        // 字段级检查：上下文里不应存在任何能盛放私钥的字段。
        // 比单纯的子串匹配更贴合契约——它守的是「这个数据结构
        // 根本没有存放私钥的位置」，而不只是「这一次恰好没放进去」。
        let value = serde_json::to_value(&context).unwrap();
        let field_names: Vec<&str> = value
            .as_object()
            .expect("上下文是 JSON 对象")
            .keys()
            .map(String::as_str)
            .collect();
        for name in field_names {
            assert!(
                !name.contains("priv") && !name.contains("secret") && !name.contains("key"),
                "上下文不应含私钥类字段，发现 `{name}`"
            );
        }
        // 摘要是交易与 witness 的哈希，不该等于私钥本身。
        assert_ne!(context.groups[0].signing_digest, format!("0x{TEST_PRIVKEY}"));
    }

    /// `PlaceholderUnlocker` 的认领规则：只认 20 字节 args。
    #[test]
    fn placeholder_unlocker_matches_sighash_shaped_args_only() {
        let unlocker = PlaceholderUnlocker;
        assert!(unlocker.match_args(&[0u8; LOCK_ARGS_LEN]));
        // 多签锁的 args 是 blake160(multisig 脚本)，长度也是 20，
        // 但本模块当前不支持其签名流程——这里只保证形态匹配。
        assert!(!unlocker.match_args(&[0u8; 19]));
        assert!(!unlocker.match_args(&[0u8; 21]));
        assert!(!unlocker.match_args(&[0u8; 28]));
    }

    /// 派生出的地址与本 crate 的 `address` 模块一致（锁死 code_hash / hash_type）。
    #[test]
    fn address_derivation_agrees_with_the_address_module() {
        let args = test_blake160(TEST_PRIVKEY);
        let lock = LockScript::sighash_blake160(args);
        // 地址模块按主网编码；这里只确认同一份 args 编出稳定结果。
        let mainnet = address::encode_address(&lock, true);
        let testnet = address::encode_address(&lock, false);
        assert!(mainnet.starts_with("ckb1"));
        assert!(testnet.starts_with("ckt1"));
        // 往返
        let (decoded, is_main) = address::decode_address(&mainnet).unwrap();
        assert!(is_main);
        assert_eq!(decoded, lock);
    }
}
