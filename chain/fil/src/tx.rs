//! FIL 的「无私钥两段式」模块：SDK 组装消息 → agent 签名 → SDK 重组并广播。
//!
//! # 为什么 FIL 能做得这么简单
//!
//! Filecoin 的签名模型是「一条 message 一个签名」，与 ETH 同属**账户模型**，
//! 不像 BTC 那样每个输入各签一次。所以这里只有一个待签对象，
//! 走到 [`crate::adapter::FilClient::submit_tx`] 时也只需要一个签名。
//!
//! 但 FIL 有一个极易写错的地方：**待签的不是消息字节，也不是消息 CID，
//! 而是 `blake2b-256(消息CID的字节)`**。链条是：
//!
//! ```text
//! Message ──DAG-CBOR──> 字节 ──blake2b-256──> 摘要
//!         └─> 包成 CIDv1(dag-cbor, blake2b-256) ──> CID 字节
//!                                                    ──blake2b-256──> 待签摘要
//! ```
//!
//! 两次 blake2b-256，中间夹一层 CID。少算一层或者多算一层都**不会报错**，
//! 只会产出一个永远验不过签的签名——节点返回的是 `invalid signature`，
//! 不会告诉你是哪一层错了。故这里把三层产物（CBOR 字节 / CID / 摘要）
//! 全部显式暴露，便于对拍。
//!
//! # 线上字节顺序与结构体字段顺序不一致
//!
//! `fvm_shared::Message` 的字段声明顺序是
//! `version, from, to, sequence, value, method_num, params, gas_limit, gas_fee_cap, gas_premium`，
//! 但它的 `Serialize` 实现写成
//! `version, **to, from**, sequence, value, gas_limit, gas_fee_cap, gas_premium, method_num, params`。
//!
//! **`to` 在 `from` 前面，且 gas 三元组挪到了 method/params 之前。**
//! 手写编码器按结构体顺序来写会得到一份"看着很像、哈希完全不同"的字节。
//! 本模块不自己编码，一律走 `fvm_ipld_encoding::to_vec`，正是为了躲开这个坑；
//! 测试则用一份**独立手写**的 Python 编码器对拍，确认我们调用的方式确实产出规范字节。
//!
//! # 编码约定（agent 侧）
//! - 待签对象是 **32 字节摘要**（已经是 blake2b-256 的结果），**不要再哈希一次**；
//! - 签名用 **secp256k1 可恢复签名**，输出 **65 字节** `r(32) || s(32) || v(1)`；
//! - `v` 取值 **0..=3**（k256 / Lotus 原生约定），**不**加 27。
//!   这也是 FVM 的 `Signature::new_secp256k1` 接受的格式。

use std::str::FromStr;

use base64::Engine as _;
use cid::Cid;
use fvm_ipld_encoding::{RawBytes, from_slice, to_vec};
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
use fvm_shared::message::Message;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use multihash::Multihash;
// `Serialize` / `Deserialize`：上下文里没有任何私密材料，往返 JSON 是安全的。
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use allchain_core::{ErrorCode, SdkError, hexutil};
use chain_rpcutil::Http;

use crate::address;

/// 可恢复签名的长度：`r(32) || s(32) || recovery_id(1)`。
///
/// 领域说明：**不**接受 64 字节的 `r||s`。Filecoin 的地址是公钥的哈希，
/// 节点靠 recovery id 反推公钥才能找到账户——少了那一字节，
/// 验签方只能逐个尝试 4 种可能，而 FVM 的验签实现不做这种尝试，
/// 会直接返回 `invalid signature`。
pub const SIGNATURE_LEN: usize = 65;

/// recovery_id 的取值上界（含）。
///
/// secp256k1 的恢复标识理论取值是 0..=3：低两位区分 y 的奇偶与是否超出
/// 曲线阶，因此**不是** 0/1 两种。有些库（如以太坊的 EIP-155）会加 27，
/// Filecoin 不加。
pub const MAX_RECOVERY_ID: u8 = 3;

/// 消息 CID 的 multihash 摘要长度（blake2b-256）。
const DIGEST_LEN: usize = 32;

/// 未签名转账的构造结果。
#[derive(Debug, Clone)]
pub struct UnsignedTransfer {
    /// 付款地址（f1/f0/f2/f3/f4 皆可，由调用方给出）。
    pub from: Address,
    /// 收款地址。
    pub to: Address,
    /// 转账金额（attoFIL）。
    pub amount_atto: u128,
    /// 发送方 nonce。
    pub nonce: u64,
    /// gas 是否来自节点估算；`false` 表示用的是保守默认值。
    pub gas_estimated: bool,
    /// 待签消息体（gas 已填充）。
    pub message: Message,
    /// 消息 CID（`bafy...` 字符串形式）。
    pub cid: String,
    /// **真正要签的 32 字节摘要**。
    pub signing_digest: [u8; 32],
}

/// 广播阶段重组 `SignedMessage` 所需的全部参数，由构造阶段下发、调用方原样回传。
///
/// 为什么要存 `from` / `to` / 金额 / gas 而不只存消息字节：
/// 广播时要**先验签再广播**，验签的目标是从签名里恢复出公钥、推出地址、
/// 再与 `from` 比对。若上下文里没有 `from`，就只能验「签名格式对不对」，
/// 验不出「这笔钱是不是从你想的账户出去的」。
///
/// 为什么还存了 `unsigned_tx_hex`：它是一条**自检锚点**。
/// 若上下文在 agent 手里被改过（比如金额被加大），
/// 重新算出的 CID 就与记录的不同，这里会立刻失败。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitContext {
    /// 网络名（`mainnet` / `calibration` / `custom` …）。
    /// 用于拦住「主网构造、测试网广播」——两者地址前缀不同（f 与 t），
    /// 但**同一份字节在两条链上都能验签通过**，只能靠这个字段兜。
    pub network: String,
    /// 未签名 message 的 DAG-CBOR 十六进制。
    pub message_hex: String,
    /// 构造阶段算出的消息 CID 字符串，用于自检。
    pub cid: String,
    /// 构造阶段算出的待签摘要（十六进制，带 `0x`）。
    pub signing_digest: String,
    /// 付款地址（字符串形式，验签时的比对基准）。
    pub from: String,
    /// 收款地址。
    pub to: String,
    /// 转账金额（attoFIL，十进制字符串）。
    pub quantity_atto: String,
    /// nonce。
    pub nonce: u64,
    /// gas 上限。
    pub gas_limit: u64,
    /// 费率上限（attoFIL）。
    pub gas_fee_cap: String,
    /// 小费（attoFIL）。
    pub gas_premium: String,
}

/// 计算消息的 CID：`CBOR → blake2b-256 → CIDv1(dag-cbor)`。
///
/// 领域说明：`0x71` 是 **dag-cbor** 的 codec，`0xb220` 是 **blake2b-256**
/// 的 multihash code。这两个常量在 Filecoin 里是硬约定——写错任何一个，
/// 算出的 CID 在链上都不存在，而本地一切「看起来正常」。
///
/// 语法说明：`Multihash::<64>` 中的 `64` 是该 multihash 能容纳的**最大字节数**。
/// blake2b-256 的 multihash 只占 34 字节（2 字节头 + 32 字节摘要），
/// 取 64 是留出余量；这是一个**编译期常量泛型参数**，不是运行期容量。
pub fn message_cid(message: &Message) -> Result<Cid, SdkError> {
    let encoded = to_vec(message)
        .map_err(|e| SdkError::new(ErrorCode::ParseError, format!("DAG-CBOR 编码消息失败: {e}")))?;
    let digest = blake2b_256(&encoded);
    let multihash = Multihash::<64>::wrap(0xb220, &digest).map_err(|e| {
        SdkError::new(ErrorCode::ParseError, format!("构造 multihash 失败: {e}"))
    })?;
    Ok(Cid::new_v1(0x71, multihash))
}

/// **真正要签的摘要**：`blake2b-256(CID 的字节)`。
///
/// 注意入参是 CID 的**字节**而不是 CID 的**字符串**：
/// CID 字符串是 base32 编码后的文本，对它取哈希会得到一个完全不同的值。
/// 这是手搓 Filecoin 签名时最常见的错误之一。
pub fn signing_digest(message: &Message) -> Result<[u8; 32], SdkError> {
    let cid = message_cid(message)?;
    Ok(blake2b_256(&cid.to_bytes()))
}

/// blake2b-256（32 字节输出）。
///
/// 与 `adapter.rs` 里的同名函数保持一致：都用可变输出长度的 `Blake2bVar`
/// 而非固定长度的 `Blake2b`，因为 Filecoin 的地址派生用的是 blake2b-160，
/// 同一套 API 用起来不容易串。
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = blake2::Blake2bVar::new(DIGEST_LEN).expect("blake2b-256 长度合法");
    hasher.update(data);
    let mut out = [0u8; DIGEST_LEN];
    hasher
        .finalize_variable(&mut out)
        .expect("输出缓冲长度匹配");
    out
}

/// 把未签名 message 序列化成十六进制字符串。
pub fn encode_message(message: &Message) -> Result<String, SdkError> {
    let encoded = to_vec(message)
        .map_err(|e| SdkError::new(ErrorCode::ParseError, format!("DAG-CBOR 编码消息失败: {e}")))?;
    Ok(hex::encode(encoded))
}

/// 由十六进制还原 message。
///
/// 领域说明：这一步之所以可行，是因为 DAG-CBOR 编码是**确定性的**
/// ——同样十个字段永远编出同样的字节。所以消息体可以当成
/// 「不透明的二进制串」在 SDK 与 agent 之间往返。
pub fn decode_message(raw: &str) -> Result<Message, SdkError> {
    let body = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
    let bytes =
        hexutil::decode_hex(body).map_err(|e| SdkError::invalid_argument(format!("消息体不是合法十六进制: {e}")))?;
    from_slice(&bytes)
        .map_err(|e| SdkError::new(ErrorCode::ParseError, format!("DAG-CBOR 解码消息失败: {e}")))
}

/// 由上下文重建 message，并自检它的 CID 与记录一致。
///
/// 领域说明：这是「上下文是否被篡改」的唯一一道闸。
/// 上下文会经过 agent 的手、可能被存进数据库、可能跨进程传输。
/// 若任何字段被改动，CID 就会变，这里立刻失败——
/// 而不是等广播后才发现「链上的钱数和自己以为的不一样」。
pub fn rebuild_message(context: &SubmitContext) -> Result<Message, SdkError> {
    let message = decode_message(&context.message_hex)?;
    let actual = message_cid(&message)?.to_string();
    if actual != context.cid {
        return Err(SdkError::invalid_argument(format!(
            "上下文自检失败：消息体算出的 CID({actual})与记录的 CID({})不一致",
            context.cid
        )));
    }
    Ok(message)
}

/// 把消息体与链上下文打包成可回传的上下文。
pub fn build_context(network: &str, message: &Message) -> Result<SubmitContext, SdkError> {
    let digest = signing_digest(message)?;
    Ok(SubmitContext {
        network: network.to_string(),
        message_hex: encode_message(message)?,
        cid: message_cid(message)?.to_string(),
        signing_digest: hexutil::encode_hex_prefixed(&digest),
        from: message.from.to_string(),
        to: message.to.to_string(),
        quantity_atto: message.value.atto().to_string(),
        nonce: message.sequence,
        gas_limit: message.gas_limit,
        gas_fee_cap: message.gas_fee_cap.atto().to_string(),
        gas_premium: message.gas_premium.atto().to_string(),
    })
}

/// 解析 agent 给的 65 字节签名，顺带校验 recovery id 的取值。
///
/// 领域说明：为什么必须显式校验 `v <= 3`——
/// 以太坊生态的签名库普遍在 recovery id 上加 27（EIP-155 之前是 +27，
/// 之后是 + chain_id * 2 + 35）。若 agent 用了这类库，
/// `v` 会是 27/28 或更大的值。此时 `from_slice` 不会报错、
/// 签名本身也是有效的，但恢复出的公钥是**错的**，
/// 于是验签失败，而错误信息看不出根因。这里提前拦下并说清原因。
pub fn parse_signature(raw: &str) -> Result<[u8; SIGNATURE_LEN], SdkError> {
    let body = raw.trim();
    let bare = body.strip_prefix("0x").unwrap_or(body);
    let bytes = hexutil::decode_hex(bare)
        .map_err(|e| SdkError::invalid_argument(format!("FIL 签名不是合法十六进制: {e}")))?;
    if bytes.len() != SIGNATURE_LEN {
        return Err(SdkError::invalid_argument(format!(
            "FIL 签名需为 {SIGNATURE_LEN} 字节（r||s||v），实际 {} 字节",
            bytes.len()
        )));
    }
    let recovery_id = bytes[SIGNATURE_LEN - 1];
    if recovery_id > MAX_RECOVERY_ID {
        return Err(SdkError::invalid_argument(format!(
            "FIL 签名的 recovery id 需为 0..={MAX_RECOVERY_ID}（Filecoin 不加 27），收到 {recovery_id}；\
             若你的签名库来自以太坊生态，请把 v 减 27"
        )));
    }
    let mut out = [0u8; SIGNATURE_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// 由签名与摘要恢复出**未压缩公钥**（65 字节）。
///
/// 领域说明：这正是 Filecoin 节点做的事——账户地址是公钥的哈希，
/// 交易里不带公钥，节点只能靠 recovery id 把它反推出来。
/// 所以「能恢复出公钥」本身就是签名有效的证明，无需额外比对。
///
/// 语法说明：`recover_from_prehash` 收的是**预哈希**（32 字节摘要），
/// 它内部不会再做一次哈希。对应的 `recover_from_msg` 才会自己算哈希，
/// 用错一个会得到一对「都跑得通、但结果无关」的函数。
pub fn recover_pubkey(
    digest: &[u8; DIGEST_LEN],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<Vec<u8>, SdkError> {
    let sig = Signature::from_slice(&signature[..64])
        .map_err(|e| SdkError::invalid_argument(format!("解析签名的 r||s 失败: {e}")))?;
    let recovery_id = RecoveryId::from_byte(signature[SIGNATURE_LEN - 1]).ok_or_else(|| {
        SdkError::invalid_argument(format!(
            "非法的 recovery id: {}（需为 0..={MAX_RECOVERY_ID}）",
            signature[SIGNATURE_LEN - 1]
        ))
    })?;
    let verifying_key = VerifyingKey::recover_from_prehash(digest, &sig, recovery_id)
        .map_err(|e| SdkError::invalid_argument(format!("由签名恢复公钥失败: {e}")))?;
    Ok(verifying_key.to_encoded_point(false).as_bytes().to_vec())
}

/// 验签：恢复公钥 → 派生地址 → 与上下文里的 `from` 比对。
///
/// 领域说明：这是**端到端**的正确性证明。
/// 只检查「签名格式合法」说明不了任何事——真正的风险是
/// 「签名有效，但签的是另一个账户」：此时交易结构完好，
/// 广播后节点会扣掉**别人**账户的钱（或直接从错误的 nonce 上失败）。
/// 恢复公钥并比对发送方，才能确认「这笔交易确实由 from 本人授权」。
pub fn verify_signature(context: &SubmitContext, signature: &[u8; SIGNATURE_LEN]) -> Result<String, SdkError> {
    let digest = decode_digest(&context.signing_digest)?;
    let pubkey = recover_pubkey(&digest, signature)?;
    let recovered = Address::new_secp256k1(&pubkey)
        .map_err(|e| SdkError::invalid_argument(format!("由恢复出的公钥派生地址失败: {e}")))?;
    let expected = Address::from_str(context.from.trim()).map_err(|e| {
        SdkError::invalid_argument(format!("上下文里的 from({}) 不是合法 FIL 地址: {e}", context.from))
    })?;
    if recovered != expected {
        return Err(SdkError::invalid_argument(format!(
            "签名验证失败：签名恢复出的地址是 {recovered}，与上下文里的 from({expected}) 不一致"
        )));
    }
    Ok(recovered.to_string())
}

/// 解析上下文里的摘要字段（带或不带 `0x` 前缀）。
fn decode_digest(raw: &str) -> Result<[u8; DIGEST_LEN], SdkError> {
    let body = raw.trim();
    let bare = body.strip_prefix("0x").unwrap_or(body);
    let bytes = hexutil::decode_hex(bare)
        .map_err(|e| SdkError::invalid_argument(format!("上下文里的待签摘要非法: {e}")))?;
    // 先取长度再 `try_into`：后者会**移动** `bytes`，
    // 之后就再也不能读 `bytes.len()` 了（借用检查器会拒绝）。
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| SdkError::invalid_argument(format!("待签摘要需为 {DIGEST_LEN} 字节，实际 {len} 字节")))
}

/// 组装 Lotus 接受的 `SignedMessage` JSON。
///
/// 领域说明：`Type` 字段是签名算法标识，**1 = secp256k1**，
/// 2 = BLS。填错时节点会按另一种算法验签，返回 `invalid signature`，
/// 同样不会指出是这里的问题。
pub fn signed_message_json(message: &Message, signature: &[u8; SIGNATURE_LEN]) -> Value {
    json!({
        "Message": message_to_lotus_json(message),
        "Signature": {
            "Type": 1,
            // Lotus 的签名字段是 **base64**（标准字符集、带填充），
            // 不是十六进制——这是 REST/JSON 层的约定，与链上字节无关。
            "Data": base64::engine::general_purpose::STANDARD.encode(signature),
        },
    })
}

/// 构造 Lotus JSON-RPC 接受的 Message JSON 形态。
pub fn message_to_lotus_json(message: &Message) -> Value {
    json!({
        "Version": message.version,
        "To": message.to.to_string(),
        "From": message.from.to_string(),
        "Nonce": message.sequence,
        "Value": message.value.to_string(),
        "GasLimit": message.gas_limit,
        "GasFeeCap": message.gas_fee_cap.to_string(),
        "GasPremium": message.gas_premium.to_string(),
        "Method": message.method_num,
        "Params": base64::engine::general_purpose::STANDARD.encode(message.params.bytes()),
    })
}

/// 构造未签名转账：取 nonce → 估 gas → 算 CID 与待签摘要 → 打包上下文。
///
/// 全程**不接触私钥**。`from` 由调用方直接给出（不再像一体式那样由私钥派生），
/// 因此这里会**校验**它是不是一个合法 Filecoin 地址，但无法证明调用方拥有它
/// ——这个证明推迟到广播阶段，由 [`verify_signature`] 用签名完成。
///
/// 不接收 `network`：网络名只属于上下文，由调用方在
/// [`build_context`] 时传入，避免同一个信息在两处各存一份而走偏。
pub async fn assemble_unsigned(
    http: &Http,
    from: &str,
    to: &str,
    amount_atto: u128,
) -> Result<UnsignedTransfer, SdkError> {
    let from_addr = Address::from_str(from.trim())
        .map_err(|e| SdkError::invalid_argument(format!("非法 FIL 付款地址 {from}: {e}")))?;
    let to_addr = Address::from_str(to.trim())
        .map_err(|e| SdkError::invalid_argument(format!("非法 FIL 收款地址 {to}: {e}")))?;

    let nonce = crate::adapter::get_nonce(http, &from_addr.to_string()).await?;

    // gas 先留 0，交给节点估算；估算失败时 `estimate_gas` 内部会退保守默认值。
    let mut message = build_unsigned_message(from_addr, to_addr, amount_atto, nonce);
    let gas_estimated = crate::adapter::estimate_gas(http, &mut message).await;

    let cid = message_cid(&message)?.to_string();
    let digest = signing_digest(&message)?;

    Ok(UnsignedTransfer {
        from: from_addr,
        to: to_addr,
        amount_atto,
        nonce,
        gas_estimated,
        message,
        cid,
        signing_digest: digest,
    })
}

/// 由收发双方、金额、nonce 组装一条 gas 全零的模板消息。
///
/// 单独暴露出来有两个理由：一是让 `assemble_unsigned` 的循环体保持可读；
/// 二是测试要拿它去和**独立的 Python 编码器**对拍——
/// 若它被埋在异步流程里，就只能连着网络一起测。
///
/// 领域说明：`method_num = 0` 表示这是一笔**普通转账**（Send），
/// 不是合约调用；`params` 为空。`version = 0` 是当前唯一的消息版本。
pub fn build_unsigned_message(
    from: Address,
    to: Address,
    amount_atto: u128,
    nonce: u64,
) -> Message {
    Message {
        version: 0,
        from,
        to,
        sequence: nonce,
        value: TokenAmount::from_atto(amount_atto),
        method_num: 0,
        params: RawBytes::new(Vec::new()),
        gas_limit: 0,
        gas_fee_cap: TokenAmount::from_atto(0u128),
        gas_premium: TokenAmount::from_atto(0u128),
    }
}

/// 由 65 字节未压缩公钥派生 f1 地址，供测试与错误提示复用。
///
/// 抽这一层是为了让 tx.rs 不必知道地址编码的细节（base32 / checksum），
/// 那些知识归 `crate::address` 所有。
pub fn address_from_pubkey(pubkey: &[u8]) -> Result<String, SdkError> {
    address::f1_from_pubkey(&hex::encode(pubkey), true)
}

// `#[cfg(test)]`：整个模块只在 `cargo test` 时参与编译，正式构建会被剔除。
#[cfg(test)]
mod tests {
    use super::*;

    // ---- 外部真值：Python 独立实现的 DAG-CBOR + CID ----
    //
    // 来源：`/tmp/gen_fil_vector.py`，用 hashlib 的 blake2b 与**手写**的
    // DAG-CBOR 编码器算出，不参考本工程的任何代码。
    // 用它能同时锚定：f1 地址派生、消息字节顺序（to 在 from 前）、
    // bignum 编码、CID 前缀、以及两次 blake2b-256 的层次。

    const VECTOR_FROM: &str = "f1wcuzrs736zqzbbjjdgl2wvyyufuk4pefbymzf2i";
    const VECTOR_TO: &str = "f1zq74sjmud64dhfowxkybc3sbw3abpcxbckglw6i";
    const VECTOR_SEQUENCE: u64 = 42;
    const VECTOR_VALUE: u128 = 1_000_000_000_000_000_000;
    const VECTOR_GAS_LIMIT: u64 = 2_000_000;
    const VECTOR_GAS_FEE_CAP: u128 = 100_000_000_000;
    const VECTOR_GAS_PREMIUM: u128 = 99_000;
    const VECTOR_CBOR: &str = "8a005501cc3fc925941fb83395d6bab0116e41b6c0178ae15501b0a998cbfbf6619085291997ab5718a168ae3c85182a49000de0b6b3a76400001a001e84804600174876e80044000182b80040";
    // CID 前缀 `0171a0e402 20 ...` 里藏着两个易错点，这里一并记录：
    //   - `01` 是 CIDv1 版本号，`71` 是 dag-cbor 的 codec（裸字节，不是 varint）；
    //   - `a0e402` 才是 blake2b-256 的 multihash code 0xb220 —— multihash 用
    //     **varint(LEB128)** 编码，0xb220 展开成三字节，而不是直观的 `b220`。
    //     生成这个向量的 Python 脚本第一版正是写死成 `b220` 而算错，
    //     靠与本 crate 的 `cid` 实现对拍才暴露出来。
    const VECTOR_CID_BYTES: &str =
        "0171a0e402205fb2e1d912bb1501e96109c42505e46d14099601f34b3ef2534ad24aad3d0bcb";
    const VECTOR_SIGNING_DIGEST: &str =
        "cf14e6ffb921badf1bb6247919083bc1ef3c567f38ffb56acbd33f251fe77ccd";

    // ---- 本地固定私钥（公钥即上面向量的输入） ----

    /// secp256k1 私钥 = 1，公开常量，不含任何真实资产。
    const TEST_PRIVKEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    /// 私钥 = 2，用于造一个「签名人不对」的反例。
    const OTHER_PRIVKEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    fn test_key(hex_priv: &str) -> k256::ecdsa::SigningKey {
        k256::ecdsa::SigningKey::from_slice(&hexutil::decode_hex(hex_priv).unwrap()).unwrap()
    }

    /// 「agent 侧」的签名动作：拿 32 字节摘要，用私钥签出 65 字节恢复式签名。
    fn agent_sign(digest: &[u8; 32], hex_priv: &str) -> [u8; SIGNATURE_LEN] {
        let key = test_key(hex_priv);
        let (sig, recid) = key.sign_prehash_recoverable(digest).unwrap();
        let mut out = [0u8; SIGNATURE_LEN];
        out[..64].copy_from_slice(sig.to_bytes().as_slice());
        out[64] = recid.to_byte();
        out
    }

    fn vector_message() -> Message {
        Message {
            version: 0,
            from: Address::from_str(VECTOR_FROM).unwrap(),
            to: Address::from_str(VECTOR_TO).unwrap(),
            sequence: VECTOR_SEQUENCE,
            value: TokenAmount::from_atto(VECTOR_VALUE),
            method_num: 0,
            params: RawBytes::new(Vec::new()),
            gas_limit: VECTOR_GAS_LIMIT,
            gas_fee_cap: TokenAmount::from_atto(VECTOR_GAS_FEE_CAP),
            gas_premium: TokenAmount::from_atto(VECTOR_GAS_PREMIUM),
        }
    }

    // ---- 与外部真值对拍 ----

    /// 消息字节必须与独立实现**逐字节一致**。
    ///
    /// 这条测试锁死的是「`to_vec` 的调用方式与字段填充顺序」。
    /// 若哪天有人把 `Message` 的构造改成先填 `from` 再填 `to`，
    /// 字节不会变（结构体字段顺序不影响序列化），但如果有人
    /// 手写了编码器、或换了序列化库，这条会立刻红。
    #[test]
    fn message_bytes_match_the_independent_encoder() {
        let encoded = to_vec(&vector_message()).unwrap();
        assert_eq!(hex::encode(&encoded), VECTOR_CBOR);
    }

    /// CID 字节必须与独立实现一致。
    ///
    /// 领域说明：CID 的前 4 字节是 `01 71 b2 20`（version / dag-cbor /
    /// blake2b-256 / 32 字节），后 32 字节是 `blake2b-256(消息字节)`。
    /// 这四项任一写错，产出的 CID 在链上都查不到。
    #[test]
    fn cid_bytes_match_the_independent_encoder() {
        let cid = message_cid(&vector_message()).unwrap();
        assert_eq!(hex::encode(cid.to_bytes()), VECTOR_CID_BYTES);
    }

    /// **待签摘要**必须与独立实现一致——这是本模块最容易错的一层。
    ///
    /// 常见错误有三种，且都**不报错**：
    ///   1. 少算一层：直接对消息字节取哈希；
    ///   2. 多算一层：对 CID 字符串而不是 CID 字节取哈希；
    ///   3. 用错哈希：sha256 而非 blake2b-256。
    ///
    /// 三者都会产出「长度也是 32 字节」的值，只有外部真值能分辨。
    #[test]
    fn signing_digest_matches_the_independent_encoder() {
        let digest = signing_digest(&vector_message()).unwrap();
        assert_eq!(hex::encode(digest), VECTOR_SIGNING_DIGEST);
        // 反证：对**消息字节**直接取哈希会得到另一个值，
        // 少了这条，「少算一层」的写法也能通过。
        assert_ne!(hex::encode(blake2b_256(&to_vec(&vector_message()).unwrap())), VECTOR_SIGNING_DIGEST);
    }

    /// f1 地址派生与独立实现一致。
    ///
    /// 这条顺带覆盖了「protocol byte 是数值 0x01 而非 ASCII '1'」
    /// 这个经典混淆点——两者的 base32 结果完全不同。
    #[test]
    fn address_derivation_matches_the_independent_encoder() {
        let key = test_key(TEST_PRIVKEY);
        let pubkey = key.verifying_key().to_encoded_point(false);
        assert_eq!(address_from_pubkey(pubkey.as_bytes()).unwrap(), VECTOR_FROM);

        let other = test_key(OTHER_PRIVKEY);
        let other_pubkey = other.verifying_key().to_encoded_point(false);
        assert_eq!(address_from_pubkey(other_pubkey.as_bytes()).unwrap(), VECTOR_TO);
    }

    // ---- 端到端：签名 → 恢复 → 比对 ----

    /// 用正确私钥签出的签名，必须能恢复出 `from` 那个地址。
    #[test]
    fn a_valid_signature_recovers_the_from_address() {
        let message = vector_message();
        let digest = signing_digest(&message).unwrap();
        let signature = agent_sign(&digest, TEST_PRIVKEY);

        let context = build_context("mainnet", &message).unwrap();
        let recovered = verify_signature(&context, &signature).unwrap();
        assert_eq!(recovered, VECTOR_FROM);
        // 上下文里的摘要必须是外部真值那一份。
        assert_eq!(context.signing_digest, format!("0x{VECTOR_SIGNING_DIGEST}"));
    }

    /// 用**别的私钥**签出的签名必须被拒，且错误信息指出是地址不匹配。
    ///
    /// 领域说明：这是两段式最关键的安全性质。
    /// 若验签只检查「签名格式合法」，那么任何人拿自己的私钥签一下
    /// 都能构造出一笔「看似有效」的交易，只是广播后失败；
    /// 更糟的是若 SDK 未校验就把 from 写进上下文，
    /// 就会出现「用 A 的签名花 B 的钱」的语义错乱。
    #[test]
    fn a_signature_from_the_wrong_key_is_rejected() {
        let message = vector_message();
        let digest = signing_digest(&message).unwrap();
        let signature = agent_sign(&digest, OTHER_PRIVKEY);

        let context = build_context("mainnet", &message).unwrap();
        let err = verify_signature(&context, &signature).unwrap_err();
        assert!(
            err.to_string().contains("签名验证失败"),
            "错误信息应指出验签失败，实际: {err}"
        );
    }

    /// 改掉上下文里的消息体，CID 自检必须失败。
    ///
    /// 领域说明：agent 可能把上下文存进数据库再取出来，
    /// 中途任何字段被改动都会改变 CID。若不自检，
    /// 签名的摘要与消息体就不再对应，节点会以 `invalid signature` 拒收，
    /// 而排查时看不出是上下文被改了。
    #[test]
    fn tampering_with_the_context_breaks_the_cid_self_check() {
        let message = vector_message();
        let mut context = build_context("mainnet", &message).unwrap();

        // 把 nonce 从 42 改成 43：消息体变了，但记录的 CID 还是旧的。
        let mut tampered = message.clone();
        tampered.sequence = VECTOR_SEQUENCE + 1;
        context.message_hex = encode_message(&tampered).unwrap();

        let err = rebuild_message(&context).unwrap_err();
        assert!(
            err.to_string().contains("上下文自检失败"),
            "篡改后的上下文必须被自检拦下，实际: {err}"
        );
    }

    /// 上下文必须能经 JSON 往返而不丢字段——它会被 agent 存下来再回传。
    #[test]
    fn submit_context_survives_a_json_roundtrip() {
        let message = vector_message();
        let context = build_context("mainnet", &message).unwrap();

        let json = serde_json::to_string(&context).unwrap();
        let back: SubmitContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.network, context.network);
        assert_eq!(back.cid, context.cid);
        assert_eq!(back.signing_digest, context.signing_digest);
        assert_eq!(back.from, context.from);
        assert_eq!(back.gas_limit, context.gas_limit);
        // 往返后仍应能重建出同一条消息。
        assert_eq!(
            hex::encode(to_vec(&rebuild_message(&back).unwrap()).unwrap()),
            context.message_hex
        );
    }

    // ---- 失败路径 ----

    /// recovery id 加了 27（以太坊习惯）必须被明确拒绝并给出原因。
    #[test]
    fn an_ethereum_style_recovery_id_is_rejected() {
        let digest = signing_digest(&vector_message()).unwrap();
        let mut signature = agent_sign(&digest, TEST_PRIVKEY);
        signature[64] += 27;

        let err = parse_signature(&hex::encode(signature)).unwrap_err();
        assert!(
            err.to_string().contains("recovery id"),
            "错误信息应点明 recovery id 的问题，实际: {err}"
        );
    }

    /// 畸形签名（长度不对、乱码）必须被拒绝。
    #[test]
    fn malformed_signatures_are_rejected() {
        assert!(parse_signature("").is_err());
        assert!(parse_signature("0x").is_err());
        assert!(parse_signature(&"ab".repeat(64)).is_err()); // 64 字节：少了 v
        assert!(parse_signature(&"ab".repeat(66)).is_err()); // 66 字节
        assert!(parse_signature("zz").is_err());
    }

    /// 摘要字段长度不对（被截断）必须被拒绝，而不是静默补零。
    #[test]
    fn a_truncated_digest_is_rejected() {
        let mut context = build_context("mainnet", &vector_message()).unwrap();
        context.signing_digest = "0x0011".to_string();
        let signature = agent_sign(&signing_digest(&vector_message()).unwrap(), TEST_PRIVKEY);
        assert!(verify_signature(&context, &signature).is_err());
    }

    // ---- 纯函数 ----

    /// 消息体编码与解码必须互为逆运算。
    #[test]
    fn message_encoding_roundtrips() {
        let message = vector_message();
        let encoded = encode_message(&message).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(decoded, message);
        // 带 0x 前缀应等价。
        assert_eq!(decode_message(&format!("0x{encoded}")).unwrap(), message);
        // 乱码必须被拒。
        assert!(decode_message("zzzz").is_err());
    }

    /// 上下文必须记录**构造时的网络**，供广播阶段做跨网校验。
    #[test]
    fn context_records_the_network_it_was_built_for() {
        let context = build_context("calibration", &vector_message()).unwrap();
        assert_eq!(context.network, "calibration");
        assert_eq!(context.nonce, VECTOR_SEQUENCE);
        assert_eq!(context.gas_limit, VECTOR_GAS_LIMIT);
        assert_eq!(context.quantity_atto, VECTOR_VALUE.to_string());
    }

    /// `SignedMessage` 的 JSON 形态：签名是 base64、Type 是 1。
    ///
    /// 领域说明：`Type` 写错成 2 会让节点按 BLS 算法验签。
    /// 这类错误在广播前无从发现，只能在测试里钉住。
    #[test]
    fn signed_message_json_uses_base64_and_type_one() {
        let message = vector_message();
        let digest = signing_digest(&message).unwrap();
        let signature = agent_sign(&digest, TEST_PRIVKEY);

        let value = signed_message_json(&message, &signature);
        assert_eq!(value["Signature"]["Type"], 1);
        assert_eq!(
            value["Signature"]["Data"],
            base64::engine::general_purpose::STANDARD.encode(signature)
        );
        assert_eq!(value["Message"]["Nonce"], VECTOR_SEQUENCE);
        assert_eq!(value["Message"]["From"], VECTOR_FROM);
        assert_eq!(value["Message"]["To"], VECTOR_TO);
        // Method = 0 表示普通转账。
        assert_eq!(value["Message"]["Method"], 0);
    }

    /// 私钥从未进入上下文：上下文只含公钥能推出的信息。
    ///
    /// 这是一条**契约测试**——若哪天有人把私钥塞进上下文，这条会红。
    #[test]
    fn context_never_carries_the_private_key() {
        let context = build_context("mainnet", &vector_message()).unwrap();
        let json = serde_json::to_string(&context).unwrap();
        for secret in [TEST_PRIVKEY, OTHER_PRIVKEY] {
            assert!(
                !json.to_ascii_lowercase().contains(secret),
                "上下文里出现了私钥字节"
            );
        }
    }
}
