//! Arweave 两段式（无私钥）转账的**纯计算层**。
//!
//! 只做三件事：构造未签名交易、算待签摘要、验签。
//! 不碰网络（联网取 `last_tx` / 手续费在 `adapter.rs`），也不碰私钥。
//!
//! 拆出这一层的理由与 FIL / CKB 的 `tx.rs` 一致：把「字节 → 待签摘要」这段
//! 与网络解耦，才能被单元测试直接打到，否则每个用例都得先起一个网关。
//!
//! # AR 签名链路上四个反直觉的事实
//!
//! 1. **待签对象不是交易字节，而是 48 字节的 deep hash**。
//!    AR 的交易在链上的形态是 JSON，**没有**规范的二进制编码，
//!    所以协议规定：先把交易的若干字段按固定顺序组织成一棵「deep hash 树」，
//!    用 **SHA-384**（不是 SHA-256）逐级级联哈希，得到 48 字节摘要。
//!    - 每个叶子打上 `blob{len}` 前缀标签，每个列表打上 `list{len}` 前缀标签；
//!    - `format = 2` 的交易有 9 个子节点，顺序是
//!      `format / owner / target / quantity / reward / last_tx / tags / data_size / data_root`。
//!
//! 2. **签名是在这 48 字节之上再哈希一次的 RSA-PSS**。
//!    `signature = RSA-PSS-Sign(sha256(deep_hash))`——这里换回 **SHA-256**，
//!    盐长取「模数字节数 - 2 - 32」，即 PSS 允许的**最大**盐长。
//!    这条不是照抄文档，而是从一笔**真实主网交易**上反推出来的（见本文件测试）：
//!    把该交易的签名做一次裸 RSA 运算展开成 EM，数出 salt 恰好 222 字节
//!    = 256 - 2 - 32，与 arweave-rs 的 `sign`（`salt_len: None`）完全吻合。
//!    验签侧则**自动探测**盐长（`salt_len: None`），因此不会拒收别的实现。
//!
//! 3. **交易 ID 由签名决定**：`id = base64url(sha256(signature))`。
//!    所以签名落地之前交易**没有** ID——这也是 `submit_tx` 必须在填完签名
//!    之后才算 ID 的原因，构造阶段返回的 `id` 一律是空串。
//!
//! 4. **`owner` 字段必须写 RSA 模数 n，而地址是 `base64url(sha256(n))`**。
//!    地址对模数是**单向**的，无法反推，所以 AR 的两段式**必须**由调用方
//!    显式提供 `public_key`（即模数 n 的 base64url）——
//!    这与 EVM / BTC 那种「签名里能恢复公钥」的链完全不同。

use arweave_rs::crypto::base64::Base64;
use arweave_rs::crypto::hash::{deep_hash, ToItems};
use arweave_rs::currency::Currency;
use arweave_rs::transaction::tags::Tag;
use arweave_rs::transaction::Tx;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::OsRng;
// `PublicKey` 是 **trait**：`RsaPublicKey` 的 `verify` 方法定义在 trait 上，
// 不把 trait 引入作用域就调不到它——这是 Rust 里「方法来自 trait」的固定规矩。
use rsa::{BigUint, PaddingScheme, PublicKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
// `FromStr` 是 trait：`Currency::from_str` / `Base64::from_str` / `Tx::from_str`
// 都定义在它上面，不引入作用域就调不到。
use std::str::FromStr;

use allchain_core::{ErrorCode, SdkError, hexutil};

/// deep hash 的输出长度（字节）。
///
/// 之所以是 48：deep hash 用 **SHA-384**，不是更常见的 SHA-256。
/// 这个数字出现在两处：本模块的数组类型，以及调用方对 `signing_payload_hex`
/// 长度的预期——把它定成常量，避免散落的字面量彼此漂移。
pub const DEEP_HASH_LEN: usize = 48;

/// 交易格式版本。
///
/// AR 有两代交易格式：
/// - `1`：旧格式，deep hash 只有 6 个子节点（没有 `format` / `data_size` / `data_root`）；
/// - `2`：现行格式，9 个子节点，所有现代网关都用它。
///
/// 本模块**只**支持 `2`。构造时写死，重建上下文时若发现别的值直接报错，
/// 而不是「照着算出一个结果」——因为格式错了算出的摘要毫无意义，
/// 却会安静地通过后续所有检查，最后在广播时才被节点拒绝。
pub const TX_FORMAT: u8 = 2;

/// RSA 公钥指数 e = 65537（`0x010001`）。
///
/// Arweave 的 JWK 里 `e` 恒为 `AQAB`（base64url 的 `0x010001`）。
/// 模数 n 由调用方提供，e 则是协议固定的，故在这里写死。
const PUBLIC_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

/// SHA-256 输出长度（字节）。PSS 盐长公式里要用到它。
const SHA256_LEN: usize = 32;

/// PSS 编码里除盐以外的固定开销：`0x01` 分隔符 1 字节 + 尾部 `0xbc` 1 字节。
const PSS_FIXED_OVERHEAD: usize = 2;

/// 一笔交易只可能有一个待签对象，因此签名数组长度恒为 1。
pub const SIGNATURE_COUNT: usize = 1;

/// 交易的 tag（键值对），两段各字段都是 **base64url** 字符串。
///
/// 为什么单独定义这个类型：arweave-rs 的 `Tag<Base64>` 只能在内存里用，
/// 它**没有**实现 `Serialize`，装不进要回传给调用方的 JSON 上下文里。
/// 因此这里用一份「字符串形态」的镜像，专门用于序列化。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArTag {
    /// tag 名（base64url 编码后的原始字节）。
    pub name: String,
    /// tag 值（base64url 编码后的原始字节）。
    pub value: String,
}

/// 广播阶段需要回传的上下文。
///
/// 为什么必须回传而不是让调用方自己拼交易：
/// AR 的交易体是 **JSON**，字段顺序、`quantity` / `reward` 的十进制字符串化、
/// tag 的 base64url 编码都得与构造时**逐字节一致**，否则 deep hash 就变了，
/// 验签必然失败。让调用方照着文档重抄一遍，是在给自己埋静默错误的坑。
///
/// 本结构体的字段命名与 [`crate::tx::SubmitContext`] 之外的链无关，
/// 各链各有一份同名类型，互不干扰。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitContext {
    /// 构造时的网络名，用于跨网护栏。
    ///
    /// 为什么需要它：AR 主网与测试网的交易字节、签名算法完全一样
    /// （不像 FIL 那样地址前缀不同），唯一区别是网关地址与 `arweave.net`
    /// 上是否真的存在这笔 `last_tx`。链本身不做网络校验，
    /// 所以「在测试网构造、去主网广播」这类误用只能由 SDK 在广播前拦住。
    pub network: String,
    /// 交易格式版本。
    pub format: u8,
    /// 付款方的 RSA 模数 n（base64url）——交易里的 `owner` 字段。
    pub owner: String,
    /// 收款地址（base64url，43 字符）。
    pub target: String,
    /// 转账金额，winston 十进制字符串。
    pub quantity: String,
    /// 矿工手续费，winston 十进制字符串。
    pub reward: String,
    /// 锚点交易（base64url），防止重放。
    pub last_tx: String,
    /// 数据区字节数；纯转账恒为 0。
    pub data_size: u64,
    /// 数据根（base64url）；纯转账恒为空串。
    pub data_root: String,
    /// 交易 tag 列表。
    pub tags: Vec<ArTag>,
    /// 构造阶段算出的 48 字节待签摘要（`0x` + 十六进制）。
    ///
    /// 它**冗余**于上面的字段（可以重算），保留下来的唯一目的是**自检**：
    /// 广播时重算一遍并与之比对，不一致就说明上下文被改过，
    /// 这时继续广播只会得到一笔无效交易。
    pub signing_digest: String,
    /// 付款地址（= `base64url(sha256(owner_bytes))`），仅用于回显与日志。
    pub from: String,
    /// 收款地址，仅用于回显。
    pub to: String,
}

/// 未签名交易 + 它对应的待签摘要。
///
/// 把两者绑在一个结构体里返回，是为了杜绝「拿了交易却忘了重算摘要」
/// 这种调用错误——调用方不需要记得它们是两回事。
#[derive(Debug)]
pub struct UnsignedTx {
    /// 未签名交易本体（`id` 与 `signature` 均为空，因为二者都依赖签名）。
    pub tx: Tx,
    /// 真正要签的 48 字节 deep hash。
    pub signing_digest: [u8; DEEP_HASH_LEN],
}

/// 从上下文重建出的交易。
///
/// 与 [`UnsignedTx`] 结构相同但语义不同：这里的摘要是**重算**出来的，
/// 且已与上下文里记录的值比对过一致。
#[derive(Debug)]
pub struct RebuiltTx {
    /// 重建出的未签名交易。
    pub tx: Tx,
    /// 重算出的待签摘要。
    pub signing_digest: [u8; DEEP_HASH_LEN],
}

/// 构造一笔**纯转账**的未签名交易。
///
/// 「纯转账」的含义：`data` 为空、`data_size = 0`、`data_root` 为空。
/// AR 的转账本质上就是一笔带 `target` + `quantity` 的数据交易，
/// 只是数据区为空——这也是为什么它同样要付存储费。
///
/// 参数里的字节切片都是**已解码**的原始字节（不是 base64url 字符串）：
/// 解码在调用方做，是为了让「输入格式非法」与「构造失败」两类错误分开报错。
///
/// 语法说明：`&[u8]` 是字节切片引用，调用方既能传 `Vec<u8>` 也能传 `&[u8; N]`，
/// 都不发生所有权转移；函数内部再用 `.to_vec()` 各自复制一份进 `Tx`。
#[allow(clippy::too_many_arguments)]
pub fn new_unsigned_tx(
    owner: &[u8],
    target: &[u8],
    quantity: u128,
    reward: u64,
    last_tx: &[u8],
    tags: Vec<Tag<Base64>>,
) -> Tx {
    // 结构体字面量里 `chunks` / `proofs` 也必须写出来：
    // `Tx` 没有实现 `Default` 之外的构造捷径，且这两个字段标了 `#[serde(skip)]`
    // ——它们只服务于大文件的分片上传，纯转账恒为空，也不参与序列化。
    Tx {
        format: TX_FORMAT,
        // `id` 与 `signature` 都依赖签名结果，构造阶段只能是空。
        id: Base64::empty(),
        last_tx: Base64(last_tx.to_vec()),
        owner: Base64(owner.to_vec()),
        tags,
        target: Base64(target.to_vec()),
        // `Currency::from(u128)`：AR 的金额类型是「AR + winston」两段式大数，
        // 由 arweave-rs 负责把它渲染成十进制字符串（进 deep hash 的就是这个串）。
        quantity: Currency::from(quantity),
        data_root: Base64::empty(),
        data: Base64::empty(),
        data_size: 0,
        reward,
        signature: Base64::empty(),
        chunks: vec![],
        proofs: vec![],
    }
}

/// 计算交易的 deep hash（48 字节），即**真正要签的对象**。
///
/// 领域说明：这一步绝不自己实现。deep hash 的级联规则（标签怎么写、
/// 子节点怎么拼）由 arweave-rs 的 `ToItems` + `deep_hash` 给出，
/// 与 arweave-js 对齐；手写一份几乎必然在边界情况上分叉，
/// 而分叉的表现是「签名永远验不过」，排查成本极高。
///
/// 语法说明：`to_deep_hash_item()` 是 **trait 方法**，来自 `ToItems<'a, Tx>`，
/// 所以本文件顶部必须 `use arweave_rs::crypto::hash::ToItems`，否则编译不过。
pub fn signing_digest(tx: &Tx) -> Result<[u8; DEEP_HASH_LEN], SdkError> {
    let item = tx.to_deep_hash_item().map_err(|e| {
        SdkError::new(
            ErrorCode::Internal,
            format!("构造 AR deep hash 输入失败: {e}"),
        )
    })?;
    // arweave-rs 的 `to_deep_hash_item` 对 `format` 不是 1 / 2 的情况是
    // `unreachable!()`（会 panic）。本模块只在两处调用它，且两处都保证了
    // `format == TX_FORMAT`：一处是刚构造出来的，一处是重建后校验过的。
    Ok(deep_hash(item))
}

/// 把交易序列化成网关接受的 JSON 字符串。
///
/// `Tx` 的 `Serialize` 是 arweave-rs **手写**的（在 `transaction/parser.rs`），
/// 不是 `derive` 出来的——因为字段顺序必须固定、`Base64` 要渲染成 base64url、
/// `quantity` 要走 `Currency::to_string()`。所以这里直接 `to_string` 即可，
/// **不要**自己拼 JSON。
pub fn tx_json(tx: &Tx) -> Result<String, SdkError> {
    serde_json::to_string(tx).map_err(|e| {
        SdkError::new(ErrorCode::Internal, format!("序列化 AR 交易失败: {e}"))
    })
}

/// 交易 JSON 的十六进制形态（`0x` + hex）。
///
/// 为什么是「JSON 的 hex」而不是某种二进制：AR 根本没有规范二进制编码，
/// 链上存的就是 JSON。这里 hex 化只是为了塞进统一的
/// `BuildTransferView::unsigned_tx_hex` 字段，保持跨链字段语义一致
/// （「未签名交易的原始字节」），调用方无需解析它。
pub fn tx_json_hex(tx: &Tx) -> Result<String, SdkError> {
    let json = tx_json(tx)?;
    Ok(hexutil::encode_hex_prefixed(json.as_bytes()))
}

/// 由签名推导交易 ID：`base64url(sha256(signature))`。
///
/// 领域说明：AR 的 txid **不是**交易内容的哈希，而是**签名的哈希**。
/// 这是个少见的设计——它意味着同一笔内容、同一个密钥签两次，
/// 因为 PSS 盐是随机的，会得到两个**不同**的 ID。
/// 后果是：AR 交易无法在签名前预知 ID，也无法「重放同一笔交易」。
pub fn tx_id(signature: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(signature))
}

/// RSA 模数（原始字节）→ Arweave 地址：`base64url(sha256(n))`。
///
/// 与 `adapter.rs` 里的 `derive_address` 是同一个算法，差别只在
/// 输入已是解码后的字节、且不做「地址是否合法」的复核。
pub fn modulus_address(modulus: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(modulus))
}

/// PSS 盐长：`模数字节数 - 2 - 32`。
///
/// 领域说明：这是 PSS 允许的**最大**盐长（OpenSSL 里叫 `RSA_PSS_SALTLEN_MAX`）。
/// arweave-rs 的 `sign` 传 `salt_len: None`，而 rsa crate 对 `None` 的解释正是
/// `size - 2 - digest_size`，与本函数一致——写成显式公式是为了在
/// extra 字段里如实告诉调用方「该用多长的盐」，否则 agent 很容易按
/// 「盐长 = 摘要长度（32）」的常规做法签出一个网络拒收的签名。
///
/// 语法说明：`saturating_sub` 与 `-` 的区别在于前者在不够减时返回 0 而不是
/// panic（debug 模式下 `-` 溢出会 panic）。这里的输入来自外部提供的模数长度，
/// 用饱和减法挡住「模数只有 20 字节」这类畸形输入是必要的。
pub fn pss_salt_len(modulus_len: usize) -> usize {
    modulus_len.saturating_sub(SHA256_LEN + PSS_FIXED_OVERHEAD)
}

/// 校验一个 RSA-PSS 签名是否由 `modulus` 对应的私钥签出。
///
/// 参数：
/// - `modulus`：RSA 模数 n 的**原始大端字节**（即交易里的 `owner` 解码后）；
/// - `digest`：48 字节 deep hash，即当时的待签对象；
/// - `signature`：原始签名字节，长度必须**恰好**等于模数字节数。
///
/// 为什么不用 arweave-rs 现成的 `crypto::verify::verify`：那份实现内部有
/// 两处 `.unwrap()`（JWK 解析、DER 解码），遇到畸形模数会 **panic**。
/// 在长驻的 HTTP / MCP 服务里 panic 是不可接受的，所以这里自己构造公钥，
/// 把每一步的失败都翻译成 `SdkError`。
///
/// 语法说明：`RsaPublicKey::new(n, e)` 里的 `BigUint` 是大整数类型，
/// `from_bytes_be` 按**大端**解释字节序——RSA 模数在 JWK / DER 里都是大端，
/// 用 `from_bytes_le` 会得到一个完全不同的数，验签必然失败且不报错。
pub fn verify_signature(
    modulus: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<(), SdkError> {
    if modulus.is_empty() {
        return Err(SdkError::invalid_argument("AR 公钥模数为空"));
    }
    let n = BigUint::from_bytes_be(modulus);
    let e = BigUint::from_bytes_be(&PUBLIC_EXPONENT);
    let key = RsaPublicKey::new(n, e).map_err(|err| {
        SdkError::invalid_argument(format!("非法 AR RSA 公钥（模数 {} 字节）: {err}", modulus.len()))
    })?;

    // 关键一步：**再哈希一次**。
    // 待签对象是 48 字节的 deep hash，但 RSA-PSS 签的是 `sha256(deep_hash)`
    // 的 32 字节结果。少了这一次哈希，验签会失败，且错误信息只是
    // 「invalid signature」,完全看不出是漏哈希还是签错了。
    let hashed = Sha256::digest(digest);
    let padding = PaddingScheme::PSS {
        // 验签用不到随机数，但 `PaddingScheme::PSS` 的字段是必填的，
        // 只能塞一个真的 RNG 进去。`OsRng` 直接读操作系统熵源，无需播种。
        salt_rng: Box::new(OsRng),
        digest: Box::new(Sha256::new()),
        // `None` = 自动探测盐长。这是**故意**的宽松：Arweave 网络接受
        // 最大盐长的签名（真实主网交易就是这么签的），但别的实现可能用
        // 别的盐长；验签侧不该替网络做这个决定。
        salt_len: None,
    };
    key.verify(padding, &hashed, signature).map_err(|_| {
        SdkError::invalid_argument(format!(
            "AR 签名校验失败：签名长度 {} 字节，模数长度 {} 字节（两者必须相等），\
             或该签名并非由该公钥对应的私钥签出",
            signature.len(),
            modulus.len()
        ))
    })
}

/// 把签名写进交易，并同步算出交易 ID。
///
/// 顺序不能反：ID 依赖签名，所以必须先填 `signature` 再算 `id`。
///
/// 语法说明：`&mut Tx` 是**可变借用**——`Tx` 没有实现 `Clone`，
/// 只能就地修改，不能「复制一份改完再返回」。
pub fn attach_signature(tx: &mut Tx, signature: Vec<u8>) {
    tx.id = Base64(Sha256::digest(&signature).to_vec());
    tx.signature = Base64(signature);
}

/// 解析调用方传来的签名（十六进制或 base64url）。
///
/// AR 生态里签名通常以 base64url 出现（交易 JSON 里就是），
/// 但本 SDK 的 `SubmitRequest` 惯例用 hex，故两者都收。
pub fn parse_signature(raw: &str, encoding: &str) -> Result<Vec<u8>, SdkError> {
    match encoding {
        "hex" => hexutil::decode_hex(raw),
        "base64" | "base64url" => decode_base64url(raw),
        other => Err(SdkError::invalid_argument(format!(
            "AR 签名编码只支持 hex / base64url，收到 {other}"
        ))),
    }
}

/// 宽松解码 base64url：容忍末尾 `=` 填充与空白。
///
/// 为什么容忍填充：AR 自己的字段一律不填充，但调用方很可能从别的库
/// 拿到带填充的字符串。剥掉 `=` 再解比报错友好得多，且不会引入歧义
/// ——`URL_SAFE_NO_PAD` 本身就是「不填充」语义。
pub fn decode_base64url(raw: &str) -> Result<Vec<u8>, SdkError> {
    let trimmed = raw.trim().trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(trimmed).map_err(|e| {
        SdkError::invalid_argument(format!("非法 base64url 字符串: {e}; 原文: {raw}"))
    })
}

/// 把上下文里的 tag 列表还原成 arweave-rs 的 `Tag<Base64>`。
fn tags_from_context(tags: &[ArTag]) -> Result<Vec<Tag<Base64>>, SdkError> {
    tags.iter()
        .map(|t| {
            Ok(Tag {
                name: Base64(decode_base64url(&t.name)?),
                value: Base64(decode_base64url(&t.value)?),
            })
        })
        // `.collect::<Result<Vec<_>, _>>()` 是 Rust 的固定套路：
        // 把「一堆 Result」收集成「一个装着所有成功值的 Result」，
        // 只要有一个 Err 就整体变 Err，`?` 在调用侧照常工作。
        .collect::<Result<Vec<Tag<Base64>>, SdkError>>()
}

/// 由未签名交易组装回传上下文。
///
/// 语法说明：`impl Into<String>` 让调用方传 `String` 或 `&str` 都行；
/// 传 `&str` 时内部分配一次，传 `String` 则零拷贝接管。
pub fn build_context(
    network: impl Into<String>,
    tx: &Tx,
    signing_digest: &[u8; DEEP_HASH_LEN],
    from: impl Into<String>,
    to: impl Into<String>,
) -> SubmitContext {
    SubmitContext {
        network: network.into(),
        format: tx.format,
        owner: tx.owner.to_string(),
        target: tx.target.to_string(),
        quantity: tx.quantity.to_string(),
        reward: tx.reward.to_string(),
        last_tx: tx.last_tx.to_string(),
        data_size: tx.data_size,
        data_root: tx.data_root.to_string(),
        tags: tx
            .tags
            .iter()
            .map(|t| ArTag {
                name: t.name.to_string(),
                value: t.value.to_string(),
            })
            .collect(),
        signing_digest: hexutil::encode_hex_prefixed(signing_digest),
        from: from.into(),
        to: to.into(),
    }
}

/// 从上下文重建交易，并**重算**待签摘要与记录值比对。
///
/// 这道自检是防篡改的最后一道闸：上下文由调用方原样回传，
/// 理论上不该变；但若被中间环节改动（或调用方手抖改了金额），
/// 重算出的摘要就会与记录值不符，此时继续验签只会得到一个
/// 「签名无效」的模糊错误。在这里拦下来，错误信息能精确指向问题。
pub fn rebuild_tx(ctx: &SubmitContext) -> Result<RebuiltTx, SdkError> {
    if ctx.format != TX_FORMAT {
        return Err(SdkError::invalid_argument(format!(
            "AR 只支持 format = {TX_FORMAT} 的交易，上下文里是 {}",
            ctx.format
        )));
    }
    let owner = decode_base64url(&ctx.owner)?;
    let target = decode_base64url(&ctx.target)?;
    let last_tx = decode_base64url(&ctx.last_tx)?;
    let data_root = if ctx.data_root.is_empty() {
        Vec::new()
    } else {
        decode_base64url(&ctx.data_root)?
    };
    // `Currency::from_str` 接受十进制字符串；AR 上链时 `quantity` 就是这么表示的。
    let quantity = arweave_rs::currency::Currency::from_str(&ctx.quantity).map_err(|e| {
        SdkError::invalid_argument(format!("上下文里的 quantity 非法: {e}"))
    })?;
    let reward = ctx.reward.trim().parse::<u64>().map_err(|e| {
        SdkError::invalid_argument(format!("上下文里的 reward 非法: {e}"))
    })?;

    let tx = Tx {
        format: ctx.format,
        id: Base64::empty(),
        last_tx: Base64(last_tx),
        owner: Base64(owner),
        tags: tags_from_context(&ctx.tags)?,
        target: Base64(target),
        quantity,
        data_root: Base64(data_root),
        data: Base64::empty(),
        data_size: ctx.data_size,
        reward,
        signature: Base64::empty(),
        chunks: vec![],
        proofs: vec![],
    };

    let digest = signing_digest(&tx)?;
    let recorded = hexutil::decode_hex(&ctx.signing_digest).map_err(|e| {
        SdkError::invalid_argument(format!("上下文里的 signing_digest 非法: {e}"))
    })?;
    // 用 `!=` 直接比字节切片，不比字符串：避免 `0x` 前缀 / 大小写差异造成的误判。
    if recorded != digest {
        return Err(SdkError::invalid_argument(format!(
            "上下文自洽性校验失败：重算出的待签摘要是 0x{}，上下文里记录的是 0x{}，\
             说明上下文在构造后被改动过",
            hexutil::encode_hex(&digest),
            hexutil::encode_hex(&recorded)
        )));
    }
    Ok(RebuiltTx {
        tx,
        signing_digest: digest,
    })
}

/// 单元测试。
///
/// 期望值全部来自**外部真值**：一笔真实存在于 Arweave 主网的交易
/// （arweave-rs 仓库 `res/sample_tx.json`，txid
/// `t3K1b8IhvtGWxAGsipZE5NafmEGrtj3OAcYikJ0edeU`，
/// 可用 `GET https://arweave.net/tx/{id}` 取回，HTTP 200）。
///
/// 用真实链上数据而非「自造往返」的意义：本工程在 CKB 上已经踩过
/// 「自往返永远通过」的坑（bech32 变体写错时自测全绿，只有与官方实现对拍才暴露）。
/// 这里同样的道理——若只测「我们算的摘要能被我们验过」，
/// 任何一致性的错误都会被漏掉。
#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// 主网真实交易的 `owner`（RSA-2048 模数的 base64url，342 字符 → 256 字节）。
    const MAINNET_TX_OWNER: &str = "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhU\
        ixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNh\
        PuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf\
        39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA\
        2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w";

    /// 主网真实交易的收款地址（43 字符）。
    const MAINNET_TX_TARGET: &str = "PAgdonEn9f5xd-UbYdCX40Sj28eltQVnxz6bbUijeVY";

    /// 主网真实交易的锚点（`last_tx`）。
    const MAINNET_TX_LAST_TX: &str =
        "ddvXNxatQmS3LeKi_x1RJn6g9G0esUaTEgT40a6f_WYyawZaSK3w8WC2czAuLgmT";

    /// 主网真实交易的签名（342 字符 base64url → 256 字节）。
    const MAINNET_TX_SIGNATURE: &str = "EJQN0DpfPBm1aUo1qk6dCkrY_zKHMJBQx3v36UOzmodF39RvBI2rqx_gTgLzszNkHIWnf-zwzXCz\
        6xF5wzlrHWkosgfSwfZOhm3aVE5KLGvqVqSlMTlIzkIcR6KKFRe9m7HyOxJHvXykAD8X1X_6RExn\
        XAZX4B9mwR10lqCG2wkRMJxchVisOZph-O5OfgteC1lb5YFx0BNAtmVgtUlY7dQdV1vVYq2_sDJP\
        kYpHK5YIMIjoRsqdGP31gOFXTmzuIHYhRyii-clx2uxrv0pjfnv9tl9WPViHu3FGLlW9tH5z3mXd\
        t7PQx-o8MGK_MXz10LLlqsPdos2rI3D3MgPUqQ";

    /// 主网真实交易的 txid。
    const MAINNET_TX_ID: &str = "t3K1b8IhvtGWxAGsipZE5NafmEGrtj3OAcYikJ0edeU";

    /// 该交易的 deep hash 期望值，取自 arweave-rs 自带的 `test_deep_hash`。
    ///
    /// 这是**独立来源**：arweave-rs 的测试常量与它自己的实现是同一份代码，
    /// 但对我们而言它是外部真值；再加上「这笔交易真的在主网上」，
    /// 就构成了「摘要算法 → 签名 → 上链成功」的完整证据链。
    const MAINNET_TX_DEEP_HASH: &str = "4a0f4afff8cd2fe56bc3454cd7f922bac51fb2a348364eb313b20184b7e783d592cb06636ae7\
        d7c7b5ab34ffcd37cb75";

    /// 由 `owner` 派生的地址（= arweave-rs 测试里那个测试钱包的地址）。
    const MAINNET_TX_FROM: &str = "ggHWyKn0I_CTtsyyt2OR85sPYz9OvKLd9DYIvRQ2ET4";

    /// 复刻主网那笔交易的形态：带一个 `test=test` 的 tag。
    fn mainnet_tx() -> Tx {
        let tags = vec![Tag {
            name: Base64::from_utf8_str("test").unwrap(),
            value: Base64::from_utf8_str("test").unwrap(),
        }];
        new_unsigned_tx(
            &decode_base64url(MAINNET_TX_OWNER).unwrap(),
            &decode_base64url(MAINNET_TX_TARGET).unwrap(),
            100_000,
            600_912,
            &decode_base64url(MAINNET_TX_LAST_TX).unwrap(),
            tags,
        )
    }

    /// 由主网签名字节重建出完整交易（填了 signature 与 id）。
    fn signed_mainnet_tx() -> Tx {
        let mut tx = mainnet_tx();
        attach_signature(&mut tx, decode_base64url(MAINNET_TX_SIGNATURE).unwrap());
        tx
    }

    #[test]
    fn deep_hash_matches_the_on_chain_transaction() {
        let digest = signing_digest(&mainnet_tx()).unwrap();
        assert_eq!(hexutil::encode_hex(&digest), MAINNET_TX_DEEP_HASH);
        assert_eq!(digest.len(), DEEP_HASH_LEN);
    }

    /// **决定性的一条**：真实主网交易的签名必须能通过我们的验签。
    ///
    /// 这一条同时钉住了三件事——deep hash 算法、签名前的 sha256、
    /// 以及盐长的自动探测——任一步错了都会在这里红。
    #[test]
    fn the_real_mainnet_signature_verifies() {
        let tx = signed_mainnet_tx();
        let digest = signing_digest(&tx).unwrap();
        let modulus = decode_base64url(MAINNET_TX_OWNER).unwrap();
        let signature = decode_base64url(MAINNET_TX_SIGNATURE).unwrap();
        verify_signature(&modulus, &digest, &signature).unwrap();
    }

    /// 反证：同一份签名换个摘要必须失败。
    ///
    /// 没有这条反证，上面的 `verify_signature` 有可能恒真
    /// （比如实现里把错误吞掉、永远返回 Ok），测试照样全绿。
    #[test]
    fn a_tampered_digest_fails_verification() {
        let modulus = decode_base64url(MAINNET_TX_OWNER).unwrap();
        let signature = decode_base64url(MAINNET_TX_SIGNATURE).unwrap();
        let mut digest = signing_digest(&mainnet_tx()).unwrap();
        // 只翻转一个 bit：deep hash 的雪崩效应该让验签立刻失败。
        digest[0] ^= 0x01;
        assert!(verify_signature(&modulus, &digest, &signature).is_err());
    }

    /// 反证：换成另一个模数（另一个人）也必须失败，
    /// 证明验签真的绑定了身份，而不只是「格式合法」。
    #[test]
    fn a_signature_from_another_key_fails_verification() {
        let digest = signing_digest(&mainnet_tx()).unwrap();
        let signature = decode_base64url(MAINNET_TX_SIGNATURE).unwrap();
        // 造一份等长但内容不同的模数：模拟「拿着别人的签名冒充自己」。
        let other_modulus = {
            let mut m = decode_base64url(MAINNET_TX_OWNER).unwrap();
            m[0] ^= 0xff;
            m
        };
        assert!(verify_signature(&other_modulus, &digest, &signature).is_err());
    }

    /// 反证：长度不等于模数的签名必须被拒。
    #[test]
    fn a_short_signature_fails_verification() {
        let digest = signing_digest(&mainnet_tx()).unwrap();
        let signature = decode_base64url(MAINNET_TX_SIGNATURE).unwrap();
        let modulus = decode_base64url(MAINNET_TX_OWNER).unwrap();
        assert!(verify_signature(&modulus, &digest, &signature[..255]).is_err());
    }

    /// 交易 ID = base64url(sha256(签名))，与主网记录一致。
    #[test]
    fn tx_id_is_the_sha256_of_the_signature() {
        let signature = decode_base64url(MAINNET_TX_SIGNATURE).unwrap();
        assert_eq!(tx_id(&signature), MAINNET_TX_ID);
        assert_eq!(signed_mainnet_tx().id.to_string(), MAINNET_TX_ID);
    }

    /// 地址由模数派生，与 arweave-rs 测试钱包地址一致。
    #[test]
    fn address_derives_from_the_modulus() {
        let modulus = decode_base64url(MAINNET_TX_OWNER).unwrap();
        assert_eq!(modulus_address(&modulus), MAINNET_TX_FROM);
    }

    /// 上下文走一圈回来必须能重建出同一笔交易、同一个摘要。
    #[test]
    fn context_roundtrip_rebuilds_the_same_tx() {
        let tx = mainnet_tx();
        let digest = signing_digest(&tx).unwrap();
        let ctx = build_context("mainnet", &tx, &digest, MAINNET_TX_FROM, MAINNET_TX_TARGET);

        let rebuilt = rebuild_tx(&ctx).unwrap();
        assert_eq!(rebuilt.signing_digest, digest);
        assert_eq!(tx_json(&rebuilt.tx).unwrap(), tx_json(&tx).unwrap());
        // 回填的 from / to 也要原样带回来。
        assert_eq!(ctx.from, MAINNET_TX_FROM);
        assert_eq!(ctx.to, MAINNET_TX_TARGET);
    }

    /// 篡改上下文里的金额必须被自检拦住，且错误信息指出是摘要不一致。
    #[test]
    fn tampering_with_the_context_amount_is_rejected() {
        let tx = mainnet_tx();
        let digest = signing_digest(&tx).unwrap();
        let mut ctx = build_context("mainnet", &tx, &digest, MAINNET_TX_FROM, MAINNET_TX_TARGET);
        ctx.quantity = "200000".to_string();
        let err = rebuild_tx(&ctx).unwrap_err();
        assert!(err.message.contains("上下文自洽性校验失败"), "{}", err.message);
    }

    /// 不接受非现行 format。
    #[test]
    fn non_current_format_is_rejected() {
        let tx = mainnet_tx();
        let digest = signing_digest(&tx).unwrap();
        let mut ctx = build_context("mainnet", &tx, &digest, MAINNET_TX_FROM, MAINNET_TX_TARGET);
        ctx.format = 1;
        let err = rebuild_tx(&ctx).unwrap_err();
        assert!(err.message.contains("format"), "{}", err.message);
    }

    /// 未签名交易序列化出的 JSON 必须与主网返回的字段完全一致。
    ///
    /// 这条把「我们构造交易的方式」钉在真实链上数据上：
    /// 字段顺序、空 `id` / 空 `signature`、十进制 quantity 都得对。
    #[test]
    fn unsigned_json_matches_the_on_chain_shape() {
        let json = tx_json(&mainnet_tx()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["format"], 2);
        assert_eq!(value["id"], "");
        assert_eq!(value["signature"], "");
        assert_eq!(value["owner"], MAINNET_TX_OWNER);
        assert_eq!(value["target"], MAINNET_TX_TARGET);
        assert_eq!(value["last_tx"], MAINNET_TX_LAST_TX);
        assert_eq!(value["quantity"], "100000");
        assert_eq!(value["reward"], "600912");
        assert_eq!(value["data_size"], "0");
        assert_eq!(value["data_root"], "");
        // tag 的 name/value 是「test」的 base64url。
        assert_eq!(value["tags"][0]["name"], "dGVzdA");
        assert_eq!(value["tags"][0]["value"], "dGVzdA");
    }

    /// 签名编码：hex 与 base64url 解出来必须是同一段字节。
    #[test]
    fn signature_parsing_accepts_hex_and_base64url() {
        let bytes = decode_base64url(MAINNET_TX_SIGNATURE).unwrap();
        let as_hex = hexutil::encode_hex(&bytes);
        assert_eq!(parse_signature(&as_hex, "hex").unwrap(), bytes);
        assert_eq!(parse_signature(MAINNET_TX_SIGNATURE, "base64url").unwrap(), bytes);
        // 带填充的 base64url 也要能解。
        let padded = format!("{MAINNET_TX_SIGNATURE}==");
        assert_eq!(parse_signature(&padded, "base64").unwrap(), bytes);
        assert!(parse_signature(&as_hex, "utf7").is_err());
    }

    /// 盐长公式：256 字节模数 → 222 字节盐，
    /// 与从真实主网签名里反推出的数值一致。
    #[test]
    fn pss_salt_len_follows_the_max_salt_rule() {
        assert_eq!(pss_salt_len(256), 222);
        // 4096 位（512 字节）模数 → 478 字节盐。
        assert_eq!(pss_salt_len(512), 478);
        // 畸形短模数不能 panic。
        assert_eq!(pss_salt_len(10), 0);
    }

    /// 空模数必须被拒，且不能因为 `BigUint::from_bytes_be` 而 panic。
    #[test]
    fn empty_modulus_is_rejected() {
        let digest = signing_digest(&mainnet_tx()).unwrap();
        let signature = decode_base64url(MAINNET_TX_SIGNATURE).unwrap();
        let err = verify_signature(&[], &digest, &signature).unwrap_err();
        assert!(err.message.contains("模数为空"), "{}", err.message);
    }

    /// 上下文里不能出现私钥：字段名层面做一次扫描。
    ///
    /// 这条防的是「将来有人往上下文里塞了私钥却没被察觉」——
    /// 两段式的全部意义就是私钥不进 SDK，这里把它固化成一条断言。
    #[test]
    fn context_never_carries_a_private_key() {
        let tx = mainnet_tx();
        let digest = signing_digest(&tx).unwrap();
        let ctx = build_context("mainnet", &tx, &digest, MAINNET_TX_FROM, MAINNET_TX_TARGET);
        let value = serde_json::to_value(&ctx).unwrap();
        let names: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for forbidden in ["private", "priv", "secret", "jwk", "d"] {
            assert!(
                !names.contains(&forbidden),
                "上下文出现了疑似私钥字段: {forbidden}"
            );
        }
    }

    /// `Tx::from_str` 能解析我们自己序列化的 JSON（往返自洽）。
    ///
    /// 注意这条**只是**自洽性检查，不能替代上面的外部真值测试：
    /// 它只能抓住「我们写的 JSON 读不回来」，抓不住「我们写错了」。
    #[test]
    fn serialized_json_parses_back_into_a_tx() {
        let tx = signed_mainnet_tx();
        let json = tx_json(&tx).unwrap();
        let parsed = Tx::from_str(&json).unwrap();
        assert_eq!(parsed.id.to_string(), MAINNET_TX_ID);
        assert_eq!(parsed.quantity.to_string(), "100000");
        assert_eq!(parsed.reward, 600_912);
    }
}
