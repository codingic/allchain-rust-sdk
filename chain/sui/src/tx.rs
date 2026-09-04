//! 交易的「无私钥」构造与广播，以及**与 `transfer` 共用的签名原语**。
//!
//! ## 本模块存在的直接原因：现有签名路径少了一步 BLAKE2b
//! 官方离线签名规范（`docs.sui.io/learn/cryptography/sui-offline-signing`）要求的管线是：
//!
//! ```text
//! message = [0,0,0] || bcs(TransactionData)     # 3 字节 intent 前缀
//! digest  = blake2b256(message)                 # ← 这一步容易被漏掉
//! sig     = ed25519_sign(private_key, digest)   # 签的是 32 字节摘要，不是 message
//! encoded = 0x00 || sig || public_key           # 97 字节
//! ```
//!
//! 漏掉 `blake2b256` 时**本地一切正常**：签名算得出来、验签也能过（因为验的是
//! 同一段字节）。只有节点会拒——报 `InvalidSignature`，而报错文案完全不会提示
//! 「你忘了哈希」。这类缺陷只能靠**外部真值**发现，本模块的
//! `signing_digest_is_the_blake2b_of_the_intent_message` 用的就是官方文档里
//! 那笔真实交易的 `(tx_bytes, signature)` 对。
//!
//! ## 与其余 ed25519 链的形态对比
//! | 链 | 待签对象 | 是否二次哈希 |
//! |---|---|---|
//! | SOL | `Message::serialize()` 原文 | 否 |
//! | APT | `sha3_256("APTOS::RawTransaction") || bcs(RawTx)` | 否 |
//! | NEAR | `sha256(borsh(Transaction))` | 是（sha256） |
//! | **SUI** | **`blake2b256([0,0,0] || bcs(TransactionData))`** | **是（blake2b-256）** |
//!
//! 四者各不相同，这正是 SDK 必须显式回传 `signing_payload_hex` 与
//! `hash_algorithm` 的原因。
//!
//! ## 广播格式：`txBytes` 与 `signatures` 是两个参数
//! GraphQL 的 `executeTransactionBlock(txBytes, signatures)` 里，
//! `txBytes` 是 `bcs(TransactionData)`——**不带** intent 前缀、**不含**签名。
//! 这一点已用官方文档示例的 base64 解码确认（首字节 `0x00` 是 V1 tag，
//! 第二字节 `0x00` 是 ProgrammableTransaction kind，第三字节已是 inputs 数量）。
//! 把 `bcs(SignedTransaction)` 整体塞进去会在节点侧反序列化失败。

use std::str::FromStr;

// `Blake2bVar` 是**可变输出长度**的 BLAKE2b：Sui 的签名摘要要 32 字节。
use blake2::Blake2bVar;
// digest 生态把「输入」与「输出」拆成两个 trait：`Update` 给 `.update(..)`，
// `VariableOutput` 给 `.finalize_variable(..)`。两个都得引入。
use blake2::digest::{Update, VariableOutput};

use allchain_core::{ErrorCode, SdkError};
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use sui_sdk_types::{
    Address, Argument, Command, Digest, GasPayment, Input, Intent, IntentAppId, IntentScope,
    IntentVersion, ObjectReference, ProgrammableTransaction, SignatureScheme, SignedTransaction,
    SplitCoins, Transaction, TransactionExpiration, TransactionKind, TransferObjects, UserSignature,
};

use crate::adapter::{DEFAULT_GAS_BUDGET, SuiClient};

/// ed25519 的 `UserSignature` 编码总长：1 字节方案标志 + 64 字节签名 + 32 字节公钥。
///
/// 领域说明：Sui 把公钥**放进**签名里，这一点与 NEAR / APT 不同（那两条链的
/// 公钥在交易体或 authenticator 里）。好处是节点无需查账户即可定位密钥。
const USER_SIGNATURE_LEN: usize = 97;

/// 占位签名：64 字节全零。
///
/// 它只用来把 `UserSignature` 的**长度与布局**占住，好让 agent 之后
/// 「按偏移覆盖 64 字节」即可。全零不是合法签名，但不影响序列化。
const PLACEHOLDER_SIGNATURE: [u8; 64] = [0u8; 64];

/// 组装未签名转账所需的全部输入。
///
/// 与 APT 那侧同样收成结构体：字段超过 7 个会触发 clippy 的
/// `too_many_arguments`，而收成结构体的真正好处是调用方必须**逐字段命名**，
/// 不会把同类型的 `amount` 与 `gas_price` 填反。
pub struct TransferParams {
    /// 付款地址（32 字节）。
    pub sender: Address,
    /// 付款账户的 ed25519 公钥（32 字节），会写进 `UserSignature`。
    pub public_key: [u8; 32],
    /// 收款地址。
    pub receiver: Address,
    /// 金额（最小单位 MIST，1 SUI = 1e9 MIST）。
    pub amount: u64,
    /// gas 付款用的 coin 对象引用（同时作为转账源）。
    pub coin: ObjectReference,
    /// 参考 gas 单价，从 `epoch.referenceGasPrice` 读取。
    pub gas_price: u64,
    /// gas 上限。
    pub gas_budget: u64,
}

/// 未签名转账：交给 agent 的「待签信封」。
#[derive(Debug, Clone)]
pub struct UnsignedTransfer {
    /// 带**占位签名**的完整交易字节（`bcs(SignedTransaction)`，带 `0x` 前缀）。
    pub unsigned_tx_hex: String,
    /// 真正要签的 32 字节摘要（带 `0x` 前缀）：`blake2b256([0,0,0] || bcs(TransactionData))`。
    pub signing_payload_hex: String,
    /// 广播时单独提交的 `bcs(TransactionData)`（带 `0x` 前缀），便于调用方核对。
    pub tx_bytes_hex: String,
    /// 付款地址。
    pub sender: Address,
    /// 收款地址。
    pub receiver: Address,
    /// 写进 `UserSignature` 的公钥。
    pub public_key: [u8; 32],
    /// 转账金额（MIST）。
    pub amount: u64,
    /// gas 付款对象（coin object id）。
    pub gas_coin_id: Address,
    /// gas 单价。
    pub gas_price: u64,
    /// gas 上限。
    pub gas_budget: u64,
    /// **签名在 `unsigned_tx_hex` 中的字节偏移**：把从 `signing_payload_hex`
    /// 得到的 64 字节写到这里，即完成签名装配。
    pub signature_offset: usize,
}

/// Sui 的 **intent 消息**：`[scope, version, app_id] || bcs(TransactionData)`。
///
/// 领域说明：这三字节是**域名分隔**（domain separation）——
/// 没有它，同一把密钥给「个人消息」签的字节就能被当成交易提交。
/// Sui 的取值是 `TransactionData=0, V0=0, Sui=0`，即 `[0, 0, 0]`。
///
/// 语法说明：`Vec::with_capacity` 预留容量后再 `extend_from_slice`，
/// 全程只分配一次；若改成 `vec![0,0,0]` 再 `extend`，会多一次拷贝。
pub fn intent_message(tx: &Transaction) -> Result<Vec<u8>, SdkError> {
    let body = bcs::to_bytes(tx)
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("交易序列化失败: {e}")))?;
    let intent =
        Intent::new(IntentScope::TransactionData, IntentVersion::V0, IntentAppId::Sui).to_bytes();

    let mut out = Vec::with_capacity(intent.len() + body.len());
    out.extend_from_slice(&intent);
    out.extend_from_slice(&body);
    Ok(out)
}

/// 真正要签的 32 字节摘要 = `blake2b256(intent_message(tx))`。
///
/// **这是本模块最关键的一个函数**，也是最容易写错的地方：ed25519 签的是
/// 这个**摘要**，而不是 intent 消息原文。
///
/// 语法说明：BLAKE2 把「输出长度」写进参数块参与运算，所以
/// `Blake2bVar::new(32)` 的结果**不等于** `Blake2bVar::new(64)` 截断到 32 字节。
/// 这里必须原生取 32 字节输出，不能先算 64 再切——正是官方规范的做法。
pub fn signing_digest(tx: &Transaction) -> Result<[u8; 32], SdkError> {
    let message = intent_message(tx)?;
    // 32 在 BLAKE2b 的合法输出范围 1..=64 内，`new` 失败只可能是程序员错误，
    // 故用 `expect` 而不是把不可能的错误往上抛。
    let mut hasher = Blake2bVar::new(32).expect("BLAKE2b 输出长度 32 合法");
    hasher.update(&message);
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .expect("输出缓冲区长度与 new(32) 一致");
    Ok(digest)
}

/// 构造占位 `UserSignature`：`0x00 || [0u8; 64] || public_key`。
///
/// 领域说明：占位时**公钥必须是真值**——它参与广播，节点靠它定位签名密钥。
/// 若占位公钥也写零，agent 忘了覆盖就会提交一笔「签名人未知」的交易，
/// 报错会比「签名无效」更难定位。
fn placeholder_signature(public_key: &[u8; 32]) -> Result<UserSignature, SdkError> {
    let mut bytes = Vec::with_capacity(USER_SIGNATURE_LEN);
    bytes.push(SignatureScheme::Ed25519 as u8);
    bytes.extend_from_slice(&PLACEHOLDER_SIGNATURE);
    bytes.extend_from_slice(public_key);
    // `UserSignature::from_bytes` 会顺带校验公钥长度与曲线合法性，
    // 故这里等于白拿一道强校验。
    UserSignature::from_bytes(&bytes)
        .map_err(|e| SdkError::invalid_argument(format!("构造占位 UserSignature 失败: {e}")))
}

/// 组装未签名转账（**纯函数**：不联网、不签名）。
///
/// 与 NEAR / APT 那侧同样的分工：联网取 coin 与 gas 价的部分放在
/// [`build_unsigned_transfer`] 里，这里只管序列化，
/// 于是「字节对不对」可以完全离线验证。
pub fn assemble_unsigned(p: TransferParams) -> Result<UnsignedTransfer, SdkError> {
    let tx = build_transaction(&p)?;

    // 待签摘要：走本模块唯一的摘要实现，两条签名路径共用，杜绝两边写法漂移。
    let digest = signing_digest(&tx)?;
    let tx_bytes = bcs::to_bytes(&tx)
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("交易序列化失败: {e}")))?;

    // 外壳：装一个占位签名，让整体布局与最终形态一致。
    let shell_tx = SignedTransaction {
        transaction: tx,
        signatures: vec![placeholder_signature(&p.public_key)?],
    };
    let shell = bcs::to_bytes(&shell_tx)
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("未签名交易序列化失败: {e}")))?;

    // 签名的偏移 = 末尾往前跳过「公钥 32 字节」再往前 64 字节。
    //
    // 为什么不写死常量：`bcs(SignedTransaction)` 的尾部布局是
    // `uleb(签名数) || uleb(97) || flag || sig(64) || pubkey(32)`，
    // 前置的两个 ULEB 长度会随签名数量变化。从**末尾**反推则与前缀无关。
    let signature_offset = shell
        .len()
        .checked_sub(32 + 64)
        .ok_or_else(|| SdkError::new(ErrorCode::Internal, "未签名交易长度异常（短于 96 字节）"))?;

    Ok(UnsignedTransfer {
        unsigned_tx_hex: format!("0x{}", hex::encode(&shell)),
        signing_payload_hex: format!("0x{}", hex::encode(digest)),
        tx_bytes_hex: format!("0x{}", hex::encode(&tx_bytes)),
        sender: p.sender,
        receiver: p.receiver,
        public_key: p.public_key,
        amount: p.amount,
        gas_coin_id: *p.coin.object_id(),
        gas_price: p.gas_price,
        gas_budget: p.gas_budget,
        signature_offset,
    })
}

/// 由参数构造 `TransactionData`（Programmable Transaction Block）。
///
/// 领域说明：Sui 的原生币转账不是「一条指令」，而是一个 PTB：
/// `SplitCoins(coin, [amount])` 先从 gas coin 里切出要转的数额，
/// 再 `TransferObjects([切出的那份], 收款地址)`。
/// 选中的 coin 同时承担「转账源」与「gas 付款」两个角色，故要求其余额
/// ≥ 转账额 + gas 预算（见 [`build_unsigned_transfer`]）。
pub fn build_transaction(p: &TransferParams) -> Result<Transaction, SdkError> {
    let inputs = vec![
        Input::ImmutableOrOwned(p.coin.clone()),
        Input::Pure {
            // `into_inner()` 取出 `[u8; 32]`（`Address` 是 `Copy`，故这里按值取也不会移走），
            // 再 `.to_vec()` 变成 BCS 需要的 `Vec<u8>`。
            value: p.receiver.into_inner().to_vec(),
        },
        Input::Pure {
            value: p.amount.to_le_bytes().to_vec(),
        },
    ];
    let commands = vec![
        Command::SplitCoins(SplitCoins {
            coin: Argument::Input(0),
            amounts: vec![Argument::Input(2)],
        }),
        Command::TransferObjects(TransferObjects {
            objects: vec![Argument::Result(0)],
            address: Argument::Input(1),
        }),
    ];
    Ok(Transaction {
        kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction { inputs, commands }),
        sender: p.sender,
        gas_payment: GasPayment {
            objects: vec![p.coin.clone()],
            owner: p.sender,
            price: p.gas_price,
            budget: p.gas_budget,
        },
        expiration: TransactionExpiration::None,
    })
}

/// 联网版：取出发件人的 SUI coin 与参考 gas 价，再交给 [`assemble_unsigned`]。
///
/// 领域说明——为什么必须联网才能构造：
/// Sui 是**对象模型**链，转账要引用一个具体的 coin 对象（含 object id、
/// version、digest 三元组），这个三元组每次对象变动都会刷新，离线猜不出来。
/// 因此「构造」这步天然依赖链上状态，正是两段式流程存在的理由。
pub async fn build_unsigned_transfer(
    client: &SuiClient,
    sender: Address,
    public_key: [u8; 32],
    receiver: Address,
    amount: u64,
) -> Result<UnsignedTransfer, SdkError> {
    let sender_hex = sender.to_string();

    let coins = client.fetch_sui_coins(&sender_hex).await?;
    // 同一个 coin 既要切出转账额、又要付 gas，故余额必须覆盖两者之和。
    let coin = coins
        .into_iter()
        .find(|c| c.balance >= amount as u128 + DEFAULT_GAS_BUDGET as u128)
        .ok_or_else(|| {
            SdkError::invalid_argument(format!(
                "没有余额充足的 SUI coin（需 ≥ {} + {} MIST）",
                amount, DEFAULT_GAS_BUDGET
            ))
        })?;
    let gas_price = client.fetch_reference_gas_price().await?;

    let coin_addr = Address::from_str(&coin.object_id).map_err(|e| {
        SdkError::new(ErrorCode::Internal, format!("coin 对象地址解析失败: {e}"))
    })?;
    let coin_digest = Digest::from_str(&coin.digest).map_err(|e| {
        SdkError::new(ErrorCode::Internal, format!("coin digest 解析失败: {e}"))
    })?;

    assemble_unsigned(TransferParams {
        sender,
        public_key,
        receiver,
        amount,
        coin: ObjectReference::new(coin_addr, coin.version, coin_digest),
        gas_price,
        gas_budget: DEFAULT_GAS_BUDGET,
    })
}

/// 把已签名的整笔交易（`bcs(SignedTransaction)`）拆成广播所需的两个参数。
///
/// 领域说明：GraphQL 的 `executeTransactionBlock(txBytes, signatures)` 要求
/// `txBytes` 是**纯 `TransactionData`**（无 intent 前缀、无签名），签名另传。
/// 而 agent 手里的「完整交易字节」是两者打包后的 `SignedTransaction`，
/// 故广播前必须在这里拆开。
///
/// 这个函数是那条「广播字节格式」缺陷的唯一防线，
/// `splitting_a_signed_transaction_strips_the_signature` 会守住它。
pub fn split_signed(raw: &[u8]) -> Result<(Vec<u8>, Vec<UserSignature>), SdkError> {
    let signed: SignedTransaction = bcs::from_bytes(raw).map_err(|e| {
        SdkError::invalid_argument(format!("已签名交易不是合法 bcs(SignedTransaction): {e}"))
    })?;
    if signed.signatures.is_empty() {
        return Err(SdkError::invalid_argument(
            "已签名交易没有签名（signatures 为空）",
        ));
    }
    let tx_bytes = bcs::to_bytes(&signed.transaction)
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("交易体重新序列化失败: {e}")))?;
    Ok((tx_bytes, signed.signatures))
}

/// 广播已签名的整笔交易，返回交易 digest。
///
/// 领域说明：走 GraphQL `executeTransactionBlock`。它**同步等待执行结果**
/// （返回里带 `effects.status`），因此这里能直接判断成功与否——
/// 这一点与 ETH / NEAR 那种「进 mempool 就返回」的模型不同。
pub async fn broadcast_raw(client: &SuiClient, raw: &[u8]) -> Result<String, SdkError> {
    let (tx_bytes, signatures) = split_signed(raw)?;
    let tx_base64 = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);
    let sig_base64_list = signatures
        .iter()
        .map(UserSignature::to_base64)
        .collect::<Vec<_>>();
    client.broadcast_tx(&tx_base64, &sig_base64_list).await
}

/// 按 agent 的操作说明把签名写回外壳：从 `signature_offset` 起覆盖 64 字节。
///
/// 抽成公共函数而非让调用方各写一遍，是为了让**生产代码与测试走同一条路径**。
/// 若两处各写一份，布局一变，测试量到的就是旧布局，断言会失真。
///
/// 语法说明：`get_mut(范围)` 返回 `Option<&mut [u8]>`，越界时是 `None` 而不是 panic，
/// 故这里能优雅地转成参数错误。
pub fn splice_signature(shell: &mut [u8], offset: usize, signature: &[u8]) -> Result<(), SdkError> {
    if signature.len() != 64 {
        return Err(SdkError::invalid_argument(format!(
            "ed25519 签名应为 64 字节，实际 {} 字节",
            signature.len()
        )));
    }
    // 先算出终点再做切片——借用可变切片期间不能再读 `shell.len()`，
    // 否则就是「可变借用与不可变借用同时存在」，编译器会报 E0502。
    // `checked_add` 保证偏移大到溢出时得到 None，而不是静默回绕成一个小下标。
    let end = match offset.checked_add(64) {
        Some(e) if e <= shell.len() => e,
        _ => {
            return Err(SdkError::invalid_argument(format!(
                "签名偏移 {offset} 越界（外壳长度 {} 字节）",
                shell.len()
            )))
        }
    };
    shell[offset..end].copy_from_slice(signature);
    Ok(())
}

/// 校验公钥确实对应某个 ed25519 曲线点。
///
/// 领域说明：`VerifyingKey::from_bytes` 会同时校验「长度 32」与
/// 「该点在曲线上」。少了后者，一串非曲线上的 32 字节也能组装出
/// 看起来合法的交易，但节点会以含糊的签名错误拒收，排查成本很高。
pub fn validate_public_key(raw: &[u8]) -> Result<[u8; 32], SdkError> {
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| SdkError::invalid_argument(format!("ed25519 公钥应为 32 字节，实际 {}", raw.len())))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| SdkError::invalid_argument(format!("非法 ed25519 公钥: {e}")))?;
    Ok(arr)
}

/// 单元测试模块：`#[cfg(test)]` 保证只在 `cargo test` 时编译。
///
/// 原则与前面几条链一致：**不拿自己的公式当标准**。
/// 本模块最重要的那条测试用官方公开文档里的真实交易对做外部真值。
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    use sui_sdk_types::ObjectReference;

    // 固定私钥（32 个 0x11）→ 确定性密钥对，测试才可复现。
    const TEST_PRIVKEY: [u8; 32] = [0x11; 32];
    const TEST_AMOUNT: u64 = 1_000_000;
    const TEST_GAS_PRICE: u64 = 1_000;

    // 地址写成**模块级常量**而不是在 `fixed_params()` 里现造，
    // 是为了让「校验 PTB 内容」那条测试能引用**独立字面量**。
    // 若期望值取自 `build_transaction(&fixed_params())`，那么
    // `build_transaction` 自身被改坏时两边同时变，断言就成了恒真的——
    // 这正是变异测试里 M8 / M9 一度存活的原因。
    //
    // 语法说明：`Address::new` 与 `Digest::new` 都是 `const fn`，
    // 故可以在常量上下文里直接调用，编译期就把值算好。
    const TEST_SENDER: Address = Address::new([0xaa; 32]);
    const TEST_RECEIVER: Address = Address::new([0xbb; 32]);
    const TEST_COIN: Address = Address::new([0xcc; 32]);
    const TEST_COIN_DIGEST: Digest = Digest::new([0xdd; 32]);

    // ------------------------------------------------------------------
    // 外部真值：官方《Querying Data with GraphQL RPC》文档里的真实交易对。
    // tx 是 bcs(TransactionData) 的 base64，sig 是 flag||sig||pubkey 的 base64。
    // ------------------------------------------------------------------
    const OFFICIAL_TX_B64: &str = "AAACACAZXApmrHgzTs3FGDyXWka+wmMCy2IwOdKLmTWHb5PnFQEASlCnLAw4qfzLF3unH9or5/L7YpOlReaSEWfoEwhTqpavSxAAAAAAACCUFUCOn8ljIxcG9O+CA1bzqjunqr4DLDSzSoNCkUvu2AEBAQEBAAEAALNQHmLi4jgC5MuwwmiMvZEeV5kuyh+waCS60voE7fpzAa3v/tOFuqDvQ+bjBpKTfjyL+6yIg+5eC3dKReVwghH/rksQAAAAAAAgxtZtKhXTr1zeFAo1JzEqVKn9J1H74ddbCJNVZGo2I1izUB5i4uI4AuTLsMJojL2RHleZLsofsGgkutL6BO36c+gDAAAAAAAAQEIPAAAAAAAA";
    const OFFICIAL_SIG_B64: &str = "AB4ZihXxUMSs9Ju5Cstuuf/hvbTvvycuRk2TMuagLYNJgQuAeXmKyJF9DAXUtL8spIsHrDQgemn4NmojcNl8HQ3JFqhnaTC8gMX4fy/rGgqgL6CDcbikawUUjC4zlkflwg==";

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&TEST_PRIVKEY);
        // 先派生公钥再交出 `sk`：`SigningKey` 不是 `Copy`，
        // 写成 `(sk, VerifyingKey::from(&sk))` 会因「移动后又借用」而编译失败（E0382）。
        let vk = VerifyingKey::from(&sk);
        (sk, vk)
    }

    fn fixed_params() -> TransferParams {
        let (_, vk) = test_keypair();
        TransferParams {
            sender: TEST_SENDER,
            public_key: vk.to_bytes(),
            receiver: TEST_RECEIVER,
            amount: TEST_AMOUNT,
            coin: ObjectReference::new(TEST_COIN, 7, TEST_COIN_DIGEST),
            gas_price: TEST_GAS_PRICE,
            gas_budget: DEFAULT_GAS_BUDGET,
        }
    }

    fn decode_prefixed(raw: &str) -> Vec<u8> {
        hex::decode(raw.trim_start_matches("0x")).unwrap()
    }

    /// **对拍（外部真值）**：官方真实交易的签名，必须能在我们算出的摘要上验过。
    ///
    /// 这条测试是整套无私钥流程的地基。它的判别力来自：官方签名是**第三方实现**
    /// 产生的，我们只提供摘要。若摘要公式错了（最常见的错法就是漏掉 blake2b、
    /// 直接签 intent 消息原文），验签必然失败。
    ///
    /// 反过来，若只做「自己签自己验」，那对任意 32 字节都成立，抓不到这个缺陷。
    #[test]
    fn signing_digest_is_the_blake2b_of_the_intent_message() {
        let tx_bytes = base64::engine::general_purpose::STANDARD
            .decode(OFFICIAL_TX_B64)
            .unwrap();
        let sig_full = base64::engine::general_purpose::STANDARD
            .decode(OFFICIAL_SIG_B64)
            .unwrap();
        assert_eq!(sig_full.len(), USER_SIGNATURE_LEN);
        let (flag, rest) = sig_full.split_at(1);
        let (signature, public_key) = rest.split_at(64);
        assert_eq!(flag[0], SignatureScheme::Ed25519 as u8);

        // 反序列化成官方类型，再用本模块的摘要函数算出待签摘要。
        let tx: Transaction = bcs::from_bytes(&tx_bytes).expect("官方 tx_bytes 应能反序列化");
        let digest = signing_digest(&tx).unwrap();

        // 反例：不加 blake2b、直接签 intent 消息原文 —— 必须验不过。
        let raw_message = intent_message(&tx).unwrap();
        assert_ne!(
            digest.to_vec(),
            raw_message,
            "摘要不应等于 intent 消息原文（漏掉 blake2b 时两者会相等）"
        );

        let vk = VerifyingKey::from_bytes(&<[u8; 32]>::try_from(public_key).unwrap()).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(signature.try_into().unwrap());
        assert!(
            vk.verify(&digest, &sig).is_ok(),
            "官方签名必须能在我们算出的摘要上验过——否则摘要公式有误"
        );
    }

    /// `intent` 前缀必须是 `[0, 0, 0]`，且紧随其后的是 `bcs(TransactionData)`。
    ///
    /// 领域说明：这三个字节是域名分隔。写错（比如用 PersonalMessage 的 `[3,0,0]`）
    /// 时本地签名验签一切正常，只有节点会拒——故必须专门钉住。
    #[test]
    fn intent_prefix_is_three_zero_bytes() {
        let tx = build_transaction(&fixed_params()).unwrap();
        let msg = intent_message(&tx).unwrap();
        let body = bcs::to_bytes(&tx).unwrap();
        assert_eq!(&msg[..3], &[0u8, 0u8, 0u8], "交易 intent 前缀应为 [0,0,0]");
        assert_eq!(&msg[3..], body.as_slice(), "intent 之后应紧跟 bcs(TransactionData)");
    }

    /// 待签摘要必须是 32 字节（blake2b-256 的输出长度）。
    #[test]
    fn signing_digest_is_32_bytes() {
        let unsigned = assemble_unsigned(fixed_params()).unwrap();
        let payload = decode_prefixed(&unsigned.signing_payload_hex);
        assert_eq!(payload.len(), 32, "待签摘要应为 32 字节");
    }

    /// 外壳布局：末尾 32 字节是公钥、其前 64 字节是占位签名（全零）。
    ///
    /// 这两条断言支撑给 agent 的「按偏移覆盖 64 字节」操作说明。
    /// **不硬编码偏移值**——偏移由 `assemble_unsigned` 算出并由这里验证，
    /// 上游若调整布局，测试会立刻变红。
    #[test]
    fn placeholder_signature_sits_before_the_trailing_public_key() {
        let unsigned = assemble_unsigned(fixed_params()).unwrap();
        let shell = decode_prefixed(&unsigned.unsigned_tx_hex);

        assert!(shell.ends_with(&unsigned.public_key), "外壳末尾应是 32 字节公钥");
        assert_eq!(
            unsigned.signature_offset + 64 + 32,
            shell.len(),
            "签名偏移应恰好落在「公钥 + 签名」的起点"
        );
        assert_eq!(
            &shell[unsigned.signature_offset..unsigned.signature_offset + 64],
            &[0u8; 64],
            "占位签名应是 64 字节全零"
        );
    }

    /// **端到端对拍**：模拟 agent 的完整操作（签摘要 → 按偏移覆盖），
    /// 结果必须能反序列化回官方类型，且签名与官方编码逐字节一致。
    ///
    /// 一次覆盖了：摘要正确性、偏移正确性、`UserSignature` 布局、
    /// 以及「签完能验过」这最后一环。
    #[test]
    fn splicing_a_signature_reproduces_the_official_user_signature() {
        let (sk, vk) = test_keypair();
        let unsigned = assemble_unsigned(fixed_params()).unwrap();

        let mut shell = decode_prefixed(&unsigned.unsigned_tx_hex);
        let digest = decode_prefixed(&unsigned.signing_payload_hex);

        // --- agent 侧操作 1：对 32 字节摘要做 ed25519 签名 ---
        let signature = sk.sign(&digest).to_bytes();

        // --- agent 侧操作 2：按偏移覆盖 64 字节 ---
        splice_signature(&mut shell, unsigned.signature_offset, &signature).unwrap();

        // --- SDK 侧：反序列化回官方类型 ---
        let signed: SignedTransaction = bcs::from_bytes(&shell).expect("拼接结果应能反序列化");
        assert_eq!(signed.signatures.len(), 1);

        let expected_bytes = {
            let mut v = vec![SignatureScheme::Ed25519 as u8];
            v.extend_from_slice(&signature);
            v.extend_from_slice(&vk.to_bytes());
            v
        };
        assert_eq!(
            signed.signatures[0].to_bytes(),
            expected_bytes,
            "UserSignature 应等于 flag || sig || pubkey"
        );
        assert_eq!(signed.transaction.sender, unsigned.sender);

        // 最后一环：签名确实能在声明的摘要上验过。
        let sig = ed25519_dalek::Signature::from_slice(&signature).unwrap();
        assert!(vk.verify(&digest, &sig).is_ok());
    }

    /// 广播前拆分：`txBytes` 必须是**纯** `TransactionData`（无 intent 前缀、无签名）。
    ///
    /// 这是那条广播格式缺陷的守护测试。判别力来自两点断言缺一不可：
    /// `tx_bytes` 里不能带 3 字节 intent 前缀（前缀是**签名时**才加的），
    /// 也不能带签名。只断言「长度等于 bcs(TransactionData)」是不够的——
    /// 若实现误把 intent 前缀拼进去，长度也对不上，故再补一条前缀校验。
    #[test]
    fn splitting_a_signed_transaction_strips_the_signature() {
        let unsigned = assemble_unsigned(fixed_params()).unwrap();
        let shell = decode_prefixed(&unsigned.unsigned_tx_hex);
        let tx_bytes = decode_prefixed(&unsigned.tx_bytes_hex);

        let (split_tx, sigs) = split_signed(&shell).unwrap();
        assert_eq!(split_tx, tx_bytes, "拆出的 txBytes 应等于 bcs(TransactionData)");
        assert_eq!(sigs.len(), 1);

        let body = bcs::to_bytes(&build_transaction(&fixed_params()).unwrap()).unwrap();
        assert_eq!(split_tx, body, "txBytes 应与交易体字节完全一致");
        // 关键：txBytes 不含 intent 前缀。
        assert_ne!(
            split_tx.len(),
            body.len() + 3,
            "txBytes 不应含有 3 字节 intent 前缀"
        );
        // 也不含签名。
        assert!(
            split_tx.len() < shell.len(),
            "txBytes 应比外壳短（外壳额外带签名）"
        );
    }

    /// 交易体的**内容**必须与入参逐项对应，而不只是「能反序列化」。
    ///
    /// 判别力说明：期望值全部取自本模块的**常量字面量**，
    /// **不**调用 `build_transaction(&fixed_params())`——
    /// 那样做的话，`build_transaction` 一旦被改坏（收款方写成付款方、
    /// gas 单价与上限写反），期望值会跟着一起错，断言反而还是绿的。
    /// 变异测试的 M8 / M9 就是靠这条测试才被杀死的。
    #[test]
    fn ptb_carries_the_requested_receiver_amount_and_gas() {
        let unsigned = assemble_unsigned(fixed_params()).unwrap();
        let shell = decode_prefixed(&unsigned.unsigned_tx_hex);
        let signed: SignedTransaction = bcs::from_bytes(&shell).expect("外壳应能反序列化");

        assert_eq!(signed.transaction.sender, TEST_SENDER, "付款方应与入参一致");
        assert_eq!(
            signed.transaction.gas_payment.price, TEST_GAS_PRICE,
            "gas 单价应与入参一致"
        );
        assert_eq!(
            signed.transaction.gas_payment.budget, DEFAULT_GAS_BUDGET,
            "gas 上限应为默认预算"
        );

        // 取出 PTB，逐项核对 inputs 与 commands。
        let TransactionKind::ProgrammableTransaction(ptb) = &signed.transaction.kind else {
            panic!("交易种类应是 ProgrammableTransaction")
        };
        assert_eq!(ptb.inputs.len(), 3, "PTB 应有 3 个输入");
        assert!(
            matches!(&ptb.inputs[0], Input::ImmutableOrOwned(r) if *r.object_id() == TEST_COIN),
            "第一个输入应是选中的 gas coin"
        );
        assert_eq!(
            ptb.inputs[1],
            Input::Pure {
                value: TEST_RECEIVER.into_inner().to_vec()
            },
            "第二个输入应是收款地址（写成付款地址时这里会红）"
        );
        assert_eq!(
            ptb.inputs[2],
            Input::Pure {
                value: TEST_AMOUNT.to_le_bytes().to_vec()
            },
            "第三个输入应是要转的 MIST 数额（小端）"
        );

        assert_eq!(ptb.commands.len(), 2, "PTB 应有 2 条指令");
        assert!(
            matches!(&ptb.commands[0], Command::SplitCoins(s) if s.coin == Argument::Input(0)),
            "第一条指令应是从 gas coin 切分出转账额"
        );
        assert!(
            matches!(&ptb.commands[1], Command::TransferObjects(t)
                if t.objects == vec![Argument::Result(0)] && t.address == Argument::Input(1)),
            "第二条指令应把切出的那份转给收款地址"
        );
    }

    /// 没有签名的「已签名交易」必须被拒绝，而不是被当成合法交易广播出去。
    #[test]
    fn empty_signature_list_is_rejected() {
        let tx = build_transaction(&fixed_params()).unwrap();
        let bare = bcs::to_bytes(&SignedTransaction {
            transaction: tx,
            signatures: vec![],
        })
        .unwrap();
        let err = split_signed(&bare).unwrap_err();
        assert!(matches!(err.code, ErrorCode::InvalidArgument));
    }

    /// 公钥必须做**密码学**校验，而不只是查长度。
    ///
    /// `0x02` 重复 32 次这一串：长度合法（32）、y 坐标小于域素数 p，
    /// 但对应的 x² 不是二次剩余——即它不在曲线上。
    #[test]
    fn non_curve_public_key_is_rejected() {
        let err = validate_public_key(&[0x02u8; 32]).unwrap_err();
        assert!(matches!(err.code, ErrorCode::InvalidArgument));
    }

    /// 长度不对的公钥必须被拒绝。
    #[test]
    fn wrong_length_public_key_is_rejected() {
        assert!(validate_public_key(&[0u8; 31]).is_err());
        assert!(validate_public_key(&[0u8; 33]).is_err());
    }
}
