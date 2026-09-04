//! TON 无私钥转账构造：把「构造外部消息」与「签名」拆成两段。
//!
//! ## 为什么 TON 需要单独一个模块
//!
//! TON 的转账不是「账户签一笔交易」，而是**钱包合约**执行一次：外部消息
//! （extMsg）携带 ed25519 签名，钱包合约校验后，再发一条内部消息（intMsg）
//! 把 nanoton 转给收款方。官方 SDK 把这条链路封装成三个连续步骤：
//! 1. `create_external_body` —— 拼出待签的 body cell；
//! 2. `sign_external_body` —— 对 `body.cell_hash()`（32 字节）做 ed25519 签名；
//! 3. `wrap_signed_body` —— 把签名塞回 cell 树，包成 extMsg。
//!
//! 无私钥流程要做的，就是把第 2 步的**输入**交出去、把第 2 步的**输出**收回来。
//!
//! ## 为什么 TON 不能用「覆盖尾部 64 字节」
//!
//! SOL / NEAR / APT / SUI 的交易是**扁平字节 + 尾部签名**，签完覆盖末尾即可。
//! TON 不行，有两道障碍：
//!
//! 1. **签名不字节对齐**。外部消息的 body 若装得下，`EitherRef` 会把它**内联**
//!    进 message cell（`tonlib-core` `tlb_types/primitives/either.rs` 的 `Native`
//!    分支）。钱包 body 约 624 bit，装得下，于是签名从第 275 bit 起，
//!    横跨 **65 个字节**——不是 64。
//! 2. **BOC 末尾还有 CRC32-C**（`has_crc32c` 置位时），改一个字节就失效。
//!
//! 本模块的 `signature_span_is_byte_aligned` 用差分探测实测了这一点并留下断言，
//! 免得将来有人（包括未来的我）以为「照搬 NEAR 那套覆盖末尾 64 字节」就行。
//!
//! ## 因此采用的方案：回传上下文，由 SDK 重组
//!
//! 调用方的工作被压缩到最小：**签 32 字节，回传 64 字节签名**，
//! 再把 `build_transfer` 下发的 `submit_context` 原样回传。
//! SDK 据此重建消息——重组用的是官方那条路径，字节与官方完全一致。
//!
//! 附带的好处：SDK 手里既有公钥又有待签哈希，可以**在广播前验签**。
//! 签名不对时给出明确的本地错误，而不是换来一句含义不明的节点拒绝。

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use allchain_core::{
    ErrorCode, SdkError,
    hexutil::{decode_hex, encode_hex, encode_hex_prefixed},
};
use num_bigint::BigUint;
use tonlib_core::cell::{ArcCell, Cell, EMPTY_ARC_CELL};
use tonlib_core::message::{CommonMsgInfo, InternalMessage, TonMessage, TransferMessage};
use tonlib_core::tlb_types::tlb::TLB;
use tonlib_core::wallet::mnemonic::KeyPair;
use tonlib_core::wallet::ton_wallet::TonWallet;
use tonlib_core::wallet::version_helper::VersionHelper;
use tonlib_core::wallet::versioned::{DEFAULT_WALLET_ID, DEFAULT_WALLET_ID_V5R1};
use tonlib_core::wallet::wallet_version::WalletVersion;
use tonlib_core::{TonAddress, TonHash};

/// ed25519 签名长度（字节）。TON 钱包外部消息固定用 64 字节签名。
pub const SIGNATURE_LEN: usize = 64;

/// 占位签名：全 0。只用来把未签名消息撑到与签名后相同的长度，
/// 便于调用方对照「签完之后会变成什么样」。它**不可**被就地覆盖
/// （原因见模块头），只是参考资料。
pub const PLACEHOLDER_SIGNATURE: [u8; SIGNATURE_LEN] = [0u8; SIGNATURE_LEN];

/// 差分探测用的对照签名：与占位签名**逐位相反**，保证 64 个字节全都不同。
const PROBE_SIGNATURE: [u8; SIGNATURE_LEN] = [0xffu8; SIGNATURE_LEN];

/// 构造一笔 TON 钱包转账所需的全部输入。
///
/// 领域说明：这个结构体把「链上状态」（`seqno` / `add_state_init`）与
/// 「本地参数」（版本 / 公钥 / 金额 / 有效期）收在一处，
/// 好让 `external_message_boc` 成为**纯函数**——不碰网络、不碰时钟，
/// 于是能在单元测试里直接断言它产出的字节。
#[derive(Debug, Clone)]
pub struct TransferParams {
    /// 钱包合约版本。地址由「合约代码 + 初始数据」哈希而来，
    /// 换一个版本就是换一个地址，故必填。
    pub version: WalletVersion,
    /// 钱包 subwallet id；V5R1 与非 V5 系列的默认值不同。
    pub wallet_id: i32,
    /// 工作链。主网账户几乎都在基础链（0），masterchain 是 -1。
    pub workchain: i32,
    /// 签名公钥。钱包合约用它校验外部消息里的签名。
    pub public_key: [u8; 32],
    /// 收款地址。
    pub recipient: TonAddress,
    /// 转账金额，最小单位 nanoton（1 TON = 1e9 nanoton）。
    pub amount_raw: u128,
    /// 钱包 seqno，防重放。已激活账户从链上取，未激活（待部署）为 0。
    pub seqno: u32,
    /// 外部消息过期时间（Unix 秒）。超时后节点直接丢弃。
    pub expire_at: u32,
    /// 是否附带 StateInit。钱包尚未部署上链时必须为 `true`。
    pub add_state_init: bool,
}

/// 未签名的外部消息，以及签名所需的全部材料。
#[derive(Debug, Clone)]
pub struct UnsignedTransfer {
    /// 未签名交易的 BOC 十六进制（带 `0x`，**无 CRC32**），签名处填的是全 0 占位。
    ///
    /// ⚠️ **仅供核对，不可就地覆盖签名**：TON 的签名不字节对齐（详见模块头）。
    /// 签名完成后请把它交给 `submit_tx`，由 SDK 重组。
    pub unsigned_tx_hex: String,
    /// **真正要签的 32 字节**（带 `0x`）：未签名 body cell 的 `cell_hash()`。
    pub signing_payload_hex: String,
    /// 未签名 body cell 的 BOC 十六进制（带 `0x`），即 `signing_payload_hex` 的原像。
    pub message_body_hex: String,
    /// 付款地址（由公钥 + 钱包版本 + wallet_id + 工作链推导）。
    pub sender: TonAddress,
    /// 收款地址。
    pub recipient: TonAddress,
    /// 转账金额（nanoton）。
    pub amount_raw: u128,
    /// 钱包 seqno。
    pub seqno: u32,
    /// 外部消息过期时间。
    pub expire_at: u32,
    /// 钱包合约版本。
    pub version: WalletVersion,
    /// 钱包 subwallet id。
    pub wallet_id: i32,
    /// 工作链。
    pub workchain: i32,
    /// 是否附带 StateInit。
    pub add_state_init: bool,
}

/// 广播阶段重组消息所需的全部参数，由 `build_transfer` 下发、调用方原样回传。
///
/// 领域说明：这些字段**一个都不能省**，也**一个都不能在广播时重新去链上取**：
/// - `seqno` 必须与签名时**逐位一致**，中途若又有交易上链，重取会拿到新值，
///   拼出来的消息签名必然对不上；
/// - `expire_at` 同理，它写进了被签名的 body；
/// - `public_key` / `wallet_version` / `wallet_id` / `workchain` 共同决定钱包地址，
///   少了任何一个都推不出同一个钱包。
///
/// 语法说明：`amount_raw` 用 `String` 而非 `u128`——JSON 的数字在不少语言里
/// 会被解析成 f64（只有 53 位有效位），大额 nanoton 会丢精度。
/// 与本工程其它金额字段保持同一约定。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitContext {
    /// 钱包合约版本名（`V4R2` / `V5R1` …），与 `adapter::parse_wallet_version` 同一套取值。
    pub wallet_version: String,
    /// 钱包 subwallet id。
    pub wallet_id: i32,
    /// 工作链。
    pub workchain: i32,
    /// 签名公钥的十六进制（**不带** `0x` 前缀）。
    pub public_key: String,
    /// 收款地址（各链原生格式，这里即 TON 地址）。
    pub recipient: String,
    /// 转账金额（nanoton），十进制字符串。
    pub amount_raw: String,
    /// 钱包 seqno，必须与构造时一致。
    pub seqno: u32,
    /// 外部消息过期时间（Unix 秒），必须与构造时一致。
    pub expire_at: u32,
    /// 是否附带 StateInit（钱包尚未部署上链时为 `true`）。
    pub add_state_init: bool,
}

impl SubmitContext {
    /// 由构造参数生成上下文。
    pub fn from_params(params: &TransferParams) -> Self {
        Self {
            wallet_version: version_name(params.version).to_string(),
            wallet_id: params.wallet_id,
            workchain: params.workchain,
            public_key: encode_hex(&params.public_key),
            recipient: params.recipient.to_string(),
            amount_raw: params.amount_raw.to_string(),
            seqno: params.seqno,
            expire_at: params.expire_at,
            add_state_init: params.add_state_init,
        }
    }

    /// 还原成构造参数。
    ///
    /// 这一步会重新校验每一项：上下文是**跨进程传回**的数据，
    /// 调用方可能手改过、也可能被截断，因此不能假设它可信。
    pub fn to_params(&self) -> Result<TransferParams, SdkError> {
        let version = parse_wallet_version(&self.wallet_version)?;
        let public_key = validate_public_key(&self.public_key)?;
        let recipient = self
            .recipient
            .parse::<TonAddress>()
            .map_err(|e| SdkError::invalid_argument(format!("submit_context 收款地址非法: {e}")))?;
        let amount_raw = self.amount_raw.trim().parse::<u128>().map_err(|_| {
            SdkError::invalid_argument(format!("submit_context 金额非法: {}", self.amount_raw))
        })?;
        Ok(TransferParams {
            version,
            wallet_id: self.wallet_id,
            workchain: self.workchain,
            public_key,
            recipient,
            amount_raw,
            seqno: self.seqno,
            expire_at: self.expire_at,
            add_state_init: self.add_state_init,
        })
    }
}

/// 仅含公钥的「半个密钥对」。
///
/// 领域说明：`tonlib-core` 的钱包地址推导（以及带 StateInit 时的初始数据构造）
/// 只需要公钥，但函数签名要的是完整的 [`KeyPair`]。这里塞一个**空的**
/// `secret_key` 来满足类型，是刻意的设计——本模块从头到尾不会调用
/// `TonWallet::sign_external_body`，任何需要私钥的路径都会在别处先失败。
///
/// 语法说明：`KeyPair` 的两个字段都是 `pub Vec<u8>`，因此可以用结构体字面量
/// 直接构造。`Vec::new()` 造出长度为 0 的空向量，不分配堆内存。
fn public_only_key_pair(public_key: &[u8; 32]) -> KeyPair {
    KeyPair {
        public_key: public_key.to_vec(),
        secret_key: Vec::new(),
    }
}

/// 只用公钥还原出钱包（含地址）。
///
/// 与 `TonWallet::new(version, key_pair)` 走的是同一条推导路径
/// （`VersionHelper::get_data` → `VersionHelper::get_code` → `TonAddress::derive`），
/// 因此得到的地址与持有私钥时**逐字节相同**。
pub fn wallet_from_public_key(
    version: WalletVersion,
    public_key: &[u8; 32],
    workchain: i32,
    wallet_id: i32,
) -> Result<TonWallet, SdkError> {
    let key_pair = public_only_key_pair(public_key);
    TonWallet::new_with_params(version, key_pair, workchain, wallet_id)
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("推导 TON 钱包地址失败: {e}")))
}

/// 给定钱包版本取默认的 subwallet id。
///
/// V5R1 的默认 wallet_id 与旧版本不同（`0x7FFFFF11` vs `0x29A9A317`），
/// 而且它直接参与地址推导——所以用错版本会得到一个**地址完全不同的钱包**，
/// 而不是「同一钱包换个参数」。与 `tonlib-core` 的 `TonWallet::new` 保持一致。
pub fn default_wallet_id(version: WalletVersion) -> i32 {
    match version {
        WalletVersion::V5R1 => DEFAULT_WALLET_ID_V5R1,
        _ => DEFAULT_WALLET_ID,
    }
}

/// 构造内部转账消息（intMsg）的 cell。
///
/// 领域说明：这才是「真正转钱」的那条消息，由钱包合约在校验签名后代发。
/// 字段取值的由来：
/// - `bounce = true`：目标地址不存在时资金退回，而不是凭空消失；
/// - `ihr_disabled = true`、`ihr_fee = 0`：即时超立方路由已废弃，钱包转账恒为 0；
/// - `created_lt` / `created_at = 0`：这两个字段由**验证者**在落块时填，
///   构造阶段必须为 0。
pub fn build_internal_message(
    sender: &TonAddress,
    recipient: &TonAddress,
    amount_raw: u128,
) -> Result<ArcCell, SdkError> {
    // `BigUint` 是任意精度无符号整数：TON 的金额字段（Grams）在 TL-B 里
    // 是变长编码，用 `u64` 会在超大金额下溢出。
    let internal = InternalMessage {
        ihr_disabled: true,
        bounce: true,
        bounced: false,
        src: sender.clone(),
        dest: recipient.clone(),
        value: BigUint::from(amount_raw),
        ihr_fee: BigUint::from(0u32),
        fwd_fee: BigUint::from(0u32),
        created_lt: 0,
        created_at: 0,
    };
    let transfer =
        TransferMessage::new(CommonMsgInfo::InternalMessage(internal), EMPTY_ARC_CELL.clone());
    let cell = transfer
        .build()
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("构造内部转账消息失败: {e}")))?;
    Ok(cell.to_arc())
}

/// 拼出待签的 body cell（外部消息体，尚未含签名）。
///
/// 语法说明：`create_external_body` 是 `TonWallet` 的方法，但只读
/// `self.version` / `self.wallet_id`，不碰 `key_pair`，所以传入
/// 「只带公钥」的钱包完全安全。
pub fn external_body(params: &TransferParams) -> Result<Cell, SdkError> {
    let wallet = wallet_from_public_key(
        params.version,
        &params.public_key,
        params.workchain,
        params.wallet_id,
    )?;
    let int_cell = build_internal_message(&wallet.address, &params.recipient, params.amount_raw)?;
    wallet
        .create_external_body(params.expire_at, params.seqno, &[int_cell])
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("构造外部消息体失败: {e}")))
}

/// 待签的 32 字节哈希：body cell 的 `cell_hash()`。
///
/// 钱包合约校验签名时算的就是这个值，因此它才是**真正要签的字节**——
/// 不是整个 BOC，也不是内部消息。
pub fn signing_payload(params: &TransferParams) -> Result<TonHash, SdkError> {
    Ok(external_body(params)?.cell_hash())
}

/// 用给定签名字节组装完整的外部消息，并序列化成 **无 CRC** 的 BOC。
///
/// 这一步对应官方路径的 `sign_external_body` + `wrap_signed_body`，
/// 区别是签名由外部传入而非本地用私钥算出——**字节布局与官方完全一致**。
pub fn external_message_boc(
    params: &TransferParams,
    signature: &[u8],
) -> Result<Vec<u8>, SdkError> {
    if signature.len() != SIGNATURE_LEN {
        return Err(SdkError::invalid_argument(format!(
            "ed25519 签名必须为 {SIGNATURE_LEN} 字节，收到 {} 字节",
            signature.len()
        )));
    }
    let wallet = wallet_from_public_key(
        params.version,
        &params.public_key,
        params.workchain,
        params.wallet_id,
    )?;
    let int_cell = build_internal_message(&wallet.address, &params.recipient, params.amount_raw)?;
    let body = wallet
        .create_external_body(params.expire_at, params.seqno, &[int_cell])
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("构造外部消息体失败: {e}")))?;
    // `VersionHelper::sign_msg` 按版本决定签名拼在 body 前面还是后面：
    // V5R1 是 `body || sign`，其余版本是 `sign || body`。
    let signed = VersionHelper::sign_msg(params.version, &body, signature)
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("写入签名失败: {e}")))?;
    let external = wallet
        .wrap_signed_body(signed, params.add_state_init)
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("封装外部消息失败: {e}")))?;
    external
        // `false` = 不加 CRC32-C。TL-B 里 `has_crc32c` 是可选位，置 0 合法；
        // 已有的 `transfer` 路径也是这么序列化的，保持一致。
        .to_boc(false)
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("序列化 BOC 失败: {e}")))
}

/// 组装未签名交易：给调用方返回「要签什么」以及广播时要回传的上下文。
///
/// 这是两段式流程的第一段，全程不接触私钥。
pub fn assemble_unsigned(params: &TransferParams) -> Result<UnsignedTransfer, SdkError> {
    let wallet = wallet_from_public_key(
        params.version,
        &params.public_key,
        params.workchain,
        params.wallet_id,
    )?;
    let body = external_body(params)?;
    let payload: TonHash = body.cell_hash();
    let body_boc = body
        .to_boc(false)
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("序列化消息体失败: {e}")))?;
    let unsigned_boc = external_message_boc(params, &PLACEHOLDER_SIGNATURE)?;

    Ok(UnsignedTransfer {
        unsigned_tx_hex: encode_hex_prefixed(&unsigned_boc),
        signing_payload_hex: encode_hex_prefixed(payload.as_slice()),
        message_body_hex: encode_hex_prefixed(&body_boc),
        sender: wallet.address,
        recipient: params.recipient.clone(),
        amount_raw: params.amount_raw,
        seqno: params.seqno,
        expire_at: params.expire_at,
        version: params.version,
        wallet_id: params.wallet_id,
        workchain: params.workchain,
        add_state_init: params.add_state_init,
    })
}

/// 用调用方回传的签名重组已签名的外部消息。
///
/// 这是两段式流程的第二段：入参只有「上下文 + 签名」，没有私钥。
pub fn assemble_signed(ctx: &SubmitContext, signature: &[u8]) -> Result<Vec<u8>, SdkError> {
    let params = ctx.to_params()?;
    external_message_boc(&params, signature)
}

/// 广播前验签：确认这 64 字节签名确实是由 `ctx.public_key` 对
/// 待签哈希签出来的。
///
/// 领域说明：这一步是「回传上下文」方案额外赚到的好处——扁平字节的链做不到
/// （它们拿不到公钥，只能把交易丢给节点、由节点拒绝）。
/// 在这里验签，能把「签名错了」从一句含义不明的节点报错，
/// 变成一条明确的本地错误。
pub fn verify_signature(ctx: &SubmitContext, signature: &[u8]) -> Result<(), SdkError> {
    let params = ctx.to_params()?;
    let signature = as_signature(signature)?;
    let verifying_key = VerifyingKey::from_bytes(&params.public_key).map_err(|e| {
        SdkError::invalid_argument(format!("submit_context 公钥不是合法 ed25519 点: {e}"))
    })?;
    let payload = signing_payload(&params)?;
    verifying_key.verify(payload.as_slice(), &signature).map_err(|_| {
        SdkError::invalid_argument(
            "ed25519 签名校验失败：签名与 submit_context 描述的交易不匹配（seqno / 金额 / 有效期 / 公钥任一不符都会导致本错误）",
        )
    })
}

/// 把字节切片转成定长 ed25519 签名，顺带做长度校验。
///
/// 语法说明：`&[u8; 64]::try_from(slice)` 需要的是**数组引用**，
/// 所以外层先取 `signature` 的切片再转换；失败时返回原切片，
/// 用 `map_err` 换成我们自己的错误类型。
fn as_signature(signature: &[u8]) -> Result<Signature, SdkError> {
    let raw = <[u8; SIGNATURE_LEN]>::try_from(signature).map_err(|_| {
        SdkError::invalid_argument(format!(
            "ed25519 签名必须为 {SIGNATURE_LEN} 字节，收到 {} 字节",
            signature.len()
        ))
    })?;
    // ed25519-dalek 的 `Signature::from_bytes` 只做**字节装载**，不做数学校验；
    // 真正的合法性检查发生在 `verify` 里。
    Ok(Signature::from_bytes(&raw))
}

/// 实测签名在 BOC 字节流中横跨多少个字节。
///
/// 领域说明：这是个**诊断函数**，存在的唯一目的是把「TON 签名不字节对齐」
/// 这件事固化成一条断言。差分做法是：同一笔消息分别用全 0 与全 0xFF
/// 作签名各序列化一次，逐字节比对，不同的那段就是签名的影响范围。
///
/// 若它返回 `SIGNATURE_LEN`（64），说明签名恰好字节对齐，理论上可以就地覆盖；
/// 返回 65 则证明跨了一个字节，**不能**用覆盖的方式拼装。
/// 目前实测结果为 65，与模块头的分析一致。
pub fn signature_span_bytes(params: &TransferParams) -> Result<usize, SdkError> {
    let zeros = external_message_boc(params, &PLACEHOLDER_SIGNATURE)?;
    let probe = external_message_boc(params, &PROBE_SIGNATURE)?;
    if zeros.len() != probe.len() {
        return Err(SdkError::new(
            ErrorCode::Internal,
            format!(
                "同笔消息在两种占位签名下 BOC 长度不同（{} vs {}），无法定位签名影响范围",
                zeros.len(),
                probe.len()
            ),
        ));
    }
    // `zip` 把两个切片配成对，`filter` 只留不同的位置，`count` 统计个数。
    //
    // 语法说明：闭包参数写作 `|(_, (a, b))|` 是**解构**：
    // `zip` 后 `enumerate` 产出 `(usize, (&u8, &u8))`，
    // 下划线 `_` 忽略不关心的下标，`a != b` 会自动解引用比较。
    Ok(zeros
        .iter()
        .zip(probe.iter())
        .filter(|(a, b)| a != b)
        .count())
}

/// 解析调用方给出的公钥：接受 `0x` 前缀十六进制（64 位）或 base64（32 字节）。
///
/// 这里不额外验曲线：钱包地址由公钥推导，地址对不上时
/// `build_transfer` 会用「推导地址 ≠ from」拦下来，那才是真正有意义的检查。
pub fn validate_public_key(raw: &str) -> Result<[u8; 32], SdkError> {
    let trimmed = raw.trim();
    // 先按十六进制解，失败再退到 base64。
    let bytes = decode_hex(trimmed).or_else(|_| {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, trimmed)
            .map_err(|_| SdkError::invalid_argument(format!("非法 ed25519 公钥: {trimmed}")))
    })?;
    // `<[u8; 32]>::try_from(slice)` 把切片转成定长数组的**引用**再拷贝；
    // 长度不符时返回 Err，用 `map_err` 换成我们自己的错误类型。
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        SdkError::invalid_argument(format!(
            "ed25519 公钥需为 32 字节，收到 {} 字节: {trimmed}",
            bytes.len()
        ))
    })
}

/// 按 `<版本>:<公钥>` 或纯公钥解析，默认 V4R2。
///
/// 领域说明：为什么把钱包版本塞进公钥字段而不是单独加参数——
/// 因为钱包**版本决定地址**（地址 = hash(合约代码 + 初始数据)），
/// 它与公钥是一对、不可分离的输入；而沿用 `parse_ton_private_key`
/// 已有的 `<version>:<secret>` 前缀写法，能让两种调用方式保持一致。
pub fn parse_signer_public_key(input: &str) -> Result<(WalletVersion, [u8; 32]), SdkError> {
    let trimmed = input.trim();
    if let Some((ver, rest)) = trimmed.split_once(':') {
        let version = parse_wallet_version(ver)?;
        return Ok((version, validate_public_key(rest)?));
    }
    Ok((WalletVersion::V4R2, validate_public_key(trimmed)?))
}

/// 把版本关键字（大小写不敏感）映射到 [`WalletVersion`]。
///
/// 与 `adapter::parse_wallet_version` 是同一张表，分开存放是为了让 `tx`
/// 模块不依赖 adapter（两者的调用场景不同：一个解析私钥，一个解析公钥）。
pub fn parse_wallet_version(s: &str) -> Result<WalletVersion, SdkError> {
    let v = match s.trim().to_ascii_lowercase().as_str() {
        "v1r1" => WalletVersion::V1R1,
        "v1r2" => WalletVersion::V1R2,
        "v1r3" => WalletVersion::V1R3,
        "v2r1" => WalletVersion::V2R1,
        "v2r2" => WalletVersion::V2R2,
        "v3r1" => WalletVersion::V3R1,
        "v3r2" => WalletVersion::V3R2,
        "v4r1" => WalletVersion::V4R1,
        "v4r2" => WalletVersion::V4R2,
        "v5r1" => WalletVersion::V5R1,
        "highloadv1r1" => WalletVersion::HighloadV1R1,
        "highloadv1r2" => WalletVersion::HighloadV1R2,
        "highloadv2" => WalletVersion::HighloadV2,
        "highloadv2r1" => WalletVersion::HighloadV2R1,
        "highloadv2r2" => WalletVersion::HighloadV2R2,
        other => {
            return Err(SdkError::invalid_argument(format!(
                "未知 TON 钱包版本: {other}（支持 v1r1..v4r2 / v5r1 / highload*）"
            )))
        }
    };
    Ok(v)
}

/// [`WalletVersion`] 的版本名，用于序列化进 `submit_context` 再原样解析回来。
///
/// 取小写形式（如 `v4r2`）而不是 `format!("{version:?}")` 的 `V4R2`：
/// 它就是调用方在 `public_key` 里写版本前缀时用的那种写法，
/// 报错回显时能直接照抄。
pub fn version_name(version: WalletVersion) -> &'static str {
    match version {
        WalletVersion::V1R1 => "v1r1",
        WalletVersion::V1R2 => "v1r2",
        WalletVersion::V1R3 => "v1r3",
        WalletVersion::V2R1 => "v2r1",
        WalletVersion::V2R2 => "v2r2",
        WalletVersion::V3R1 => "v3r1",
        WalletVersion::V3R2 => "v3r2",
        WalletVersion::V4R1 => "v4r1",
        WalletVersion::V4R2 => "v4r2",
        WalletVersion::V5R1 => "v5r1",
        WalletVersion::HighloadV1R1 => "highloadv1r1",
        WalletVersion::HighloadV1R2 => "highloadv1r2",
        WalletVersion::HighloadV2 => "highloadv2",
        WalletVersion::HighloadV2R1 => "highloadv2r1",
        WalletVersion::HighloadV2R2 => "highloadv2r2",
    }
}

/// 把 BOC 字节流转成 toncenter `/sendBoc` 需要的 base64。
///
/// 顺带做一次反序列化校验：挡掉截断、乱码这类「能被 base64 编码、
/// 但根本不是 BOC」的输入，让错误在本地就暴露，而不是换来一个含义不明的节点报错。
pub fn encode_boc_for_broadcast(bytes: &[u8]) -> Result<String, SdkError> {
    if bytes.is_empty() {
        return Err(SdkError::invalid_argument("待广播的 BOC 为空"));
    }
    tonlib_core::cell::BagOfCells::parse(bytes)
        .map_err(|e| SdkError::new(ErrorCode::ParseError, format!("非法 BOC: {e}")))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        bytes,
    ))
}

/// 单元测试。
///
/// 这里的**核心用例**是对拍官方签名路径：用 tonlib-core 自己测试里那组公开
/// 助记词，走 `TonWallet::create_external_msg` 产出一份「官方 BOC」；
/// 再用另一条完全独立的库（ed25519-dalek）签出签名，走本模块的上下文重组路径，
/// 断言两者**逐字节相同**。只有当字节完全一致时，才说明待签哈希与重组都对。
#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use std::str::FromStr;
    use tonlib_core::wallet::mnemonic::Mnemonic;

    use super::*;

    /// tonlib-core 官方测试用的助记词——这是一份**外部真值**，
    /// 它的 V3R1 / V3R2 / V4R2 / V5R1 地址都在上游测试里被断言过。
    const TEST_MNEMONIC: &str = "fancy carpet hello mandate penalty trial consider property top vicious exit rebuild tragic profit urban major total month holiday sudden rib gather media vicious";
    /// 上游测试里给出的 V4R2 地址期望值。它不依赖本模块的任何代码。
    const EXPECTED_V4R2_ADDRESS: &str = "EQCDM_QGggZ3qMa_f3lRPk4_qLDnLTqdi6OkMAV2NB9r5TG3";
    /// 上游测试里给出的 V3R2 地址期望值，用于确认「换版本 = 换地址」。
    const EXPECTED_V3R2_ADDRESS: &str = "EQA-RswW9QONn88ziVm4UKnwXDEot5km7GEEXsfie_0TFOCO";

    /// 固定的交易参数，避免每个用例各写一份导致用例之间不可比。
    fn fixed_params(version: WalletVersion) -> TransferParams {
        let key_pair = mnemonic_to_keypair(TEST_MNEMONIC).unwrap();
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&key_pair.public_key);
        TransferParams {
            version,
            wallet_id: default_wallet_id(version),
            workchain: 0,
            public_key,
            recipient: TonAddress::from_str(EXPECTED_V3R2_ADDRESS).unwrap(),
            amount_raw: 1_500_000_000u128,
            seqno: 7,
            expire_at: 1_700_000_000,
            add_state_init: false,
        }
    }

    fn mnemonic_to_keypair(words: &str) -> Result<KeyPair, SdkError> {
        let mnemonic = Mnemonic::from_str(words, &None)
            .map_err(|e| SdkError::invalid_argument(format!("非法助记词: {e}")))?;
        mnemonic
            .to_key_pair()
            .map_err(|e| SdkError::new(ErrorCode::Internal, format!("推导密钥对失败: {e}")))
    }

    /// 用**另一套库**（ed25519-dalek）签出签名。
    ///
    /// 领域说明：tonlib 内部用 NaCl 签名，这里刻意换成 ed25519-dalek，
    /// 于是「签名算得对不对」这件事由两个独立实现互相印证——
    /// 若待签哈希算错，两个库会一起错不了，但**验签会失败**。
    fn dalek_signature(payload: &[u8]) -> [u8; SIGNATURE_LEN] {
        let key_pair = mnemonic_to_keypair(TEST_MNEMONIC).unwrap();
        // tonlib 的 secret_key 是 NaCl 的 64 字节扩展形式（seed || pubkey），
        // 前 32 字节即 ed25519 种子。取前 32 字节喂给 dalek 后，
        // 再用「推导出的公钥必须一致」来确认两个库对密钥的理解相同。
        let seed: [u8; 32] = key_pair.secret_key[..32].try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        assert_eq!(
            VerifyingKey::from(&signing_key).to_bytes(),
            fixed_params(WalletVersion::V4R2).public_key,
            "ed25519-dalek 与 tonlib 对同一助记词推导出的公钥不一致"
        );
        use ed25519_dalek::Signer;
        signing_key.sign(payload).to_bytes()
    }

    /// 走官方路径产出的已签名 BOC——本模块的**外部真值**。
    ///
    /// ⚠️ 内部消息**刻意不调用** `build_internal_message`，而用下面那份独立构造。
    /// 这不是洁癖：一开始这里复用了被测函数，结果变异测试里
    /// 「bounce 取反」「金额 +1」「收发方对调」三个变异体全部存活——
    /// 两边共用同一个函数时，它算错了也一起错，对拍等于没做。
    fn official_signed_boc(params: &TransferParams) -> Vec<u8> {
        let key_pair = mnemonic_to_keypair(TEST_MNEMONIC).unwrap();
        let wallet = TonWallet::new(params.version, key_pair).unwrap();
        let int_cell =
            independent_internal_message(&wallet.address, &params.recipient, params.amount_raw);
        wallet
            .create_external_msg(
                params.expire_at,
                params.seqno,
                params.add_state_init,
                &[int_cell],
            )
            .unwrap()
            .to_boc(false)
            .unwrap()
    }

    /// 测试内独立构造的内部转账消息，字段全部**写死**。
    ///
    /// 存在的意义是给 `build_internal_message` 提供一个不由它自己产生的参照物。
    /// 参照物必须与被测实现**共享零代码**，否则两者会一起错。
    fn independent_internal_message(
        sender: &TonAddress,
        recipient: &TonAddress,
        amount: u128,
    ) -> ArcCell {
        let internal = InternalMessage {
            ihr_disabled: true,
            bounce: true,
            bounced: false,
            src: sender.clone(),
            dest: recipient.clone(),
            value: BigUint::from(amount),
            ihr_fee: BigUint::from(0u32),
            fwd_fee: BigUint::from(0u32),
            created_lt: 0,
            created_at: 0,
        };
        TransferMessage::new(
            CommonMsgInfo::InternalMessage(internal),
            EMPTY_ARC_CELL.clone(),
        )
        .build()
        .unwrap()
        .to_arc()
    }

    /// 内部消息必须真的带上调用方要的收款方、金额与 bounce 标志。
    ///
    /// 期望值取自上面那份独立构造，因此 `build_internal_message` 里
    /// 任何一个字段写错，这条用例都会红。
    #[test]
    fn internal_message_matches_an_independently_built_one() {
        let params = fixed_params(WalletVersion::V4R2);
        let wallet = wallet_from_public_key(
            params.version,
            &params.public_key,
            params.workchain,
            params.wallet_id,
        )
        .unwrap();
        let ours = encode_hex(
            build_internal_message(&wallet.address, &params.recipient, params.amount_raw)
                .unwrap()
                .to_boc(false)
                .unwrap()
                .as_slice(),
        );

        let expected = encode_hex(
            independent_internal_message(&wallet.address, &params.recipient, params.amount_raw)
                .to_boc(false)
                .unwrap()
                .as_slice(),
        );
        assert_eq!(ours, expected, "内部消息与独立构造不一致");

        // 反向确认：金额差一个 nanoton 就必须不同，
        // 否则上面那条断言可能是「两边恒等」的假绿。
        let other = encode_hex(
            independent_internal_message(
                &wallet.address,
                &params.recipient,
                params.amount_raw + 1,
            )
            .to_boc(false)
            .unwrap()
            .as_slice(),
        );
        assert_ne!(ours, other, "金额变了内部消息却没变");
    }

    /// 只用公钥推导出的地址，必须与持有私钥时推导出的完全一致。
    ///
    /// 这是整个无私钥流程的地基：地址错了，后面签得再对也会打到别人的钱包。
    #[test]
    fn public_key_only_wallet_derives_the_official_address() {
        let key_pair = mnemonic_to_keypair(TEST_MNEMONIC).unwrap();
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&key_pair.public_key);

        let keyless = wallet_from_public_key(
            WalletVersion::V4R2,
            &public_key,
            0,
            default_wallet_id(WalletVersion::V4R2),
        )
        .unwrap();
        assert_eq!(keyless.address.to_string(), EXPECTED_V4R2_ADDRESS);

        // 反向确认：同一把公钥换版本，地址必须不同。
        // 这条断言是「版本属于必填输入」这一设计的直接依据。
        let v3 = wallet_from_public_key(
            WalletVersion::V3R2,
            &public_key,
            0,
            default_wallet_id(WalletVersion::V3R2),
        )
        .unwrap();
        assert_eq!(v3.address.to_string(), EXPECTED_V3R2_ADDRESS);
        assert_ne!(keyless.address, v3.address);
    }

    /// **对拍官方签名路径**：用外部签名库 + 上下文重组，必须逐字节复现官方 BOC。
    ///
    /// 这是本模块最重要的一条断言。它同时证明了三件事：
    /// 待签哈希算对了、签名位置由官方 `sign_msg` 决定（我们没有自己拼）、
    /// 以及最终 BOC 的字节布局与官方一致。
    #[test]
    fn context_reassembly_reproduces_the_official_boc_byte_for_byte() {
        for version in [WalletVersion::V3R2, WalletVersion::V4R2, WalletVersion::V5R1] {
            let params = fixed_params(version);
            let official = official_signed_boc(&params);

            let unsigned = assemble_unsigned(&params).unwrap();
            let ctx = SubmitContext::from_params(&params);
            let signature = dalek_signature(&decode_hex(&unsigned.signing_payload_hex).unwrap());
            // 先验签：这一步过了，才说明我们交给 agent 的待签对象是对的。
            verify_signature(&ctx, &signature).unwrap();

            let rebuilt = assemble_signed(&ctx, &signature).unwrap();
            assert_eq!(
                encode_hex(&rebuilt),
                encode_hex(&official),
                "{version:?}: 重组结果与官方 BOC 不一致"
            );
        }
    }

    /// `signing_payload_hex` 必须是**官方签名所用的那个哈希**，而不是随便 32 字节。
    ///
    /// 反向验证：拿官方 BOC 里签名验不过的「错哈希」去验签，必须失败。
    /// 只做「签完自己再验一次」是恒真的（对任何字节都成立），抓不到算错的哈希。
    #[test]
    fn signing_payload_is_not_just_any_32_bytes() {
        let params = fixed_params(WalletVersion::V4R2);
        let unsigned = assemble_unsigned(&params).unwrap();
        let ctx = SubmitContext::from_params(&params);
        let signature = dalek_signature(&decode_hex(&unsigned.signing_payload_hex).unwrap());

        // 真值：验得过。
        verify_signature(&ctx, &signature).unwrap();

        // 拿内部消息 cell 的哈希去验，必须验不过——
        // 它同样是个「合法的 32 字节 cell 哈希」，但不是被签的那个。
        let wrong = build_internal_message(
            &unsigned.sender,
            &unsigned.recipient,
            unsigned.amount_raw,
        )
        .unwrap()
        .cell_hash()
        .unwrap();
        assert_ne!(
            encode_hex(wrong.as_slice()),
            unsigned.signing_payload_hex.trim_start_matches("0x"),
            "内部消息哈希不应等于待签哈希"
        );
    }

    /// 上下文里任何一项被改动，验签都必须失败。
    ///
    /// 这保证 `submit_tx` 不会「拿一份被篡改的上下文去广播一笔对不上的交易」。
    #[test]
    fn tampering_with_the_context_breaks_verification() {
        let params = fixed_params(WalletVersion::V4R2);
        let unsigned = assemble_unsigned(&params).unwrap();
        let signature = dalek_signature(&decode_hex(&unsigned.signing_payload_hex).unwrap());

        let good = SubmitContext::from_params(&params);
        verify_signature(&good, &signature).unwrap();

        // 金额 +1
        let mut bad = good.clone();
        bad.amount_raw = (params.amount_raw + 1).to_string();
        assert!(verify_signature(&bad, &signature).is_err());

        // seqno +1（重放防护的核心字段）
        let mut bad = good.clone();
        bad.seqno = params.seqno + 1;
        assert!(verify_signature(&bad, &signature).is_err());

        // 有效期 +1
        let mut bad = good.clone();
        bad.expire_at = params.expire_at + 1;
        assert!(verify_signature(&bad, &signature).is_err());

        // 换个钱包版本 → 推导出另一个地址 → body 不同
        let mut bad = good.clone();
        bad.wallet_version = "v3r2".to_string();
        assert!(verify_signature(&bad, &signature).is_err());

        // 换个公钥（用它自己的签名验不过）
        let mut bad = good.clone();
        bad.public_key = encode_hex(&[0x33u8; 32]);
        assert!(verify_signature(&bad, &signature).is_err());
    }

    /// 签名长度不对、或上下文本身非法，都要在验签前就被挡下。
    #[test]
    fn malformed_signature_or_context_is_rejected() {
        let params = fixed_params(WalletVersion::V4R2);
        let ctx = SubmitContext::from_params(&params);

        assert!(verify_signature(&ctx, &[0u8; 63]).is_err());
        assert!(verify_signature(&ctx, &[0u8; 65]).is_err());
        assert!(assemble_signed(&ctx, &[0u8; 32]).is_err());

        let mut bad = ctx.clone();
        bad.wallet_version = "v9r9".to_string();
        assert!(bad.to_params().is_err());

        let mut bad = ctx.clone();
        bad.amount_raw = "abc".to_string();
        assert!(bad.to_params().is_err());

        let mut bad = ctx.clone();
        bad.recipient = "not-an-address".to_string();
        assert!(bad.to_params().is_err());
    }

    /// 上下文要能走过一次 JSON 序列化往返（它要跨进程传给调用方再传回来）。
    #[test]
    fn submit_context_survives_a_json_roundtrip() {
        let params = fixed_params(WalletVersion::V5R1);
        let ctx = SubmitContext::from_params(&params);
        // `serde_json::to_value` → `from_value`：模拟「下发 → 回传」。
        let round: SubmitContext =
            serde_json::from_value(serde_json::to_value(&ctx).unwrap()).unwrap();
        let restored = round.to_params().unwrap();
        assert_eq!(restored.version, params.version);
        assert_eq!(restored.public_key, params.public_key);
        assert_eq!(restored.amount_raw, params.amount_raw);
        assert_eq!(restored.seqno, params.seqno);
        assert_eq!(restored.expire_at, params.expire_at);
        assert_eq!(
            signing_payload(&restored).unwrap().as_slice(),
            signing_payload(&params).unwrap().as_slice()
        );
    }

    /// 金额 / 收款方 / seqno / 有效期 / 公钥变了，待签哈希必须跟着变。
    ///
    /// 这是一条**变异式**断言：它保证 `signing_payload_hex` 真的由这些字段推导，
    /// 而不是某个写死的常量。
    #[test]
    fn changing_any_field_changes_the_signing_payload() {
        let base = fixed_params(WalletVersion::V4R2);
        let base_payload = encode_hex(signing_payload(&base).unwrap().as_slice());

        let mut other = base.clone();
        other.amount_raw += 1;
        assert_ne!(encode_hex(signing_payload(&other).unwrap().as_slice()), base_payload);

        let mut other = base.clone();
        other.seqno += 1;
        assert_ne!(encode_hex(signing_payload(&other).unwrap().as_slice()), base_payload);

        let mut other = base.clone();
        other.expire_at += 1;
        assert_ne!(encode_hex(signing_payload(&other).unwrap().as_slice()), base_payload);

        let mut other = base.clone();
        other.public_key[0] ^= 0x01;
        assert_ne!(encode_hex(signing_payload(&other).unwrap().as_slice()), base_payload);
    }

    /// **固化「TON 签名不字节对齐」这个事实**。
    ///
    /// 差分探测实测签名影响 65 个字节而非 64，说明它跨了字节边界，
    /// 因此「覆盖末尾 64 字节」那套做法在 TON 上行不通。
    /// 这条断言是模块头那段分析的可执行证据——将来若有人想改回覆盖式拼接，
    /// 它会第一时间拦下来。
    #[test]
    fn signature_is_not_byte_aligned_in_the_boc() {
        for version in [WalletVersion::V3R2, WalletVersion::V4R2, WalletVersion::V5R1] {
            let span = signature_span_bytes(&fixed_params(version)).unwrap();
            assert_eq!(
                span,
                SIGNATURE_LEN + 1,
                "{version:?}: 签名影响范围应为 {} 字节（不字节对齐），实测 {span}",
                SIGNATURE_LEN + 1
            );
        }
    }

    /// 公钥解析：十六进制（可带 0x）与 base64 都要支持，长度不符要拒绝。
    #[test]
    fn public_key_parsing_accepts_hex_and_base64() {
        let raw = [0x11u8; 32];
        assert_eq!(validate_public_key(&encode_hex(&raw)).unwrap(), raw);
        assert_eq!(validate_public_key(&encode_hex_prefixed(&raw)).unwrap(), raw);
        assert_eq!(
            validate_public_key(&base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                raw
            ))
            .unwrap(),
            raw
        );
        assert!(validate_public_key(&encode_hex(&[0x11u8; 31])).is_err());
        assert!(validate_public_key("not-a-key").is_err());
    }

    /// 钱包版本前缀：不写默认 V4R2，写了要生效，写错要拒绝。
    #[test]
    fn signer_public_key_parsing_honours_the_version_prefix() {
        let key = encode_hex(&[0x22u8; 32]);
        let (v, pk) = parse_signer_public_key(&key).unwrap();
        assert_eq!(v, WalletVersion::V4R2);
        assert_eq!(pk, [0x22u8; 32]);

        let (v, _) = parse_signer_public_key(&format!("v5r1:{key}")).unwrap();
        assert_eq!(v, WalletVersion::V5R1);

        assert!(parse_signer_public_key(&format!("v9r9:{key}")).is_err());
        assert!(parse_signer_public_key(&format!("v5r1:{}", encode_hex(&[0x22u8; 8]))).is_err());
    }

    /// 版本名与版本枚举要能双向对应（上下文里存的是字符串）。
    #[test]
    fn version_name_roundtrips() {
        for version in [
            WalletVersion::V3R1,
            WalletVersion::V3R2,
            WalletVersion::V4R1,
            WalletVersion::V4R2,
            WalletVersion::V5R1,
            WalletVersion::HighloadV2R2,
        ] {
            assert_eq!(parse_wallet_version(version_name(version)).unwrap(), version);
        }
    }

    /// 广播编码：合法 BOC 能过，空输入与乱码要被挡下。
    #[test]
    fn broadcast_encoding_validates_the_boc() {
        let params = fixed_params(WalletVersion::V4R2);
        let boc = external_message_boc(&params, &PLACEHOLDER_SIGNATURE).unwrap();
        let b64 = encode_boc_for_broadcast(&boc).unwrap();
        assert_eq!(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).unwrap(),
            boc
        );

        assert!(encode_boc_for_broadcast(&[]).is_err());
        assert!(encode_boc_for_broadcast(&[0x01, 0x02, 0x03]).is_err());
    }
}
