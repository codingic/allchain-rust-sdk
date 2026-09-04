//! 交易的「无私钥」构造与广播：只组装、只广播，全程不接触私钥。
//!
//! ## 与 NEAR 那侧的关键差别：待签对象不是 32 字节摘要
//! Aptos 的签名消息是
//!
//! ```text
//! sha3_256("APTOS::RawTransaction") || bcs(RawTransaction)
//! ```
//!
//! 即**一个域名分隔前缀 + 交易体原文**，长度随 payload 变化（通常上百字节），
//! ed25519 直接对它签名。对比一下：
//! - NEAR：签 `sha256(borsh(Transaction))` —— **32 字节摘要**；
//! - SOL：签 `Message::serialize()` —— 消息体原文，**无前缀**；
//! - APT：签 `前缀(32B) + 交易体原文` —— **有前缀的原文**。
//!
//! 三种形态各不相同，这正是 SDK 必须显式回传 `signing_payload_hex`、
//! 而不能让调用方自己从 `unsigned_tx_hex` 推导的原因。
//!
//! ## 为什么必须显式给 public_key
//! Aptos 的地址是 `sha3_256(ed25519_pubkey || 0x00)`，**哈希不可逆**，
//! 拿不到公钥就组装不出 authenticator。而 REST 的账户接口只回
//! `authentication_key`（同样是哈希），也不给公钥。
//! 因此本链的无私钥流程**要求调用方显式提供 public_key**——没有回退路径，
//! 与其猜错不如明确报错。

use std::time::{SystemTime, UNIX_EPOCH};

use allchain_core::{ErrorCode, SdkError};
// aptos-sdk 里有**两组同名**的 ed25519 类型，这是本文件最容易踩的坑，
// 故两组的路径都写全，绝不用简短名互相指代：
// - `crypto::*` —— 密码学原语。`Ed25519PublicKey` 内部包 `ed25519_dalek::VerifyingKey`，
//   构造时会校验「长度 32 **且**该点确实在曲线上」；
// - `transaction::authenticator::*` —— BCS 线上类型，就是 `pub [u8; 32]` / `pub [u8; 64]`
//   的元组结构体，只校验长度、不做密码学检查。
// 两组**不可互换**：把 `crypto::Ed25519PublicKey` 塞进 `TransactionAuthenticator`
// 会直接编译不过（E0308）。我们的用法是「前者校验、后者序列化」，见
// [`placeholder_authenticator`]。
use aptos_sdk::transaction::{
    EntryFunction, RawTransaction, SignedTransaction, TransactionAuthenticator,
};
use aptos_sdk::types::{AccountAddress, ChainId};
use chain_rpcutil::Http;
use serde_json::Value;

/// 构造一笔未签名转账所需的全部输入。
///
/// 为什么收成一个结构体而不是九个参数：clippy 的 `too_many_arguments`
/// 在超过 7 个参数时报警，而这九项**缺一不可**——
/// 收成结构体的额外好处是调用方必须逐字段命名，不会把 `chain_id`
/// 与 `gas_unit_price` 这类同为 u64 的字段填反。
pub struct TransferParams {
    /// 付款地址（32 字节）。
    pub sender: AccountAddress,
    /// 付款账户的 ed25519 公钥（32 字节），会被写进 authenticator。
    pub public_key: Vec<u8>,
    /// 收款地址。
    pub receiver: AccountAddress,
    /// 金额（最小单位 octa）。
    pub amount: u64,
    /// 付款账户的序列号（防重放 + 定序），从链上读取。
    pub sequence_number: u64,
    /// 链 ID（防跨链重放），从账本信息读取。
    pub chain_id: u8,
    /// gas 单价（octa / gas unit）。
    pub gas_unit_price: u64,
    /// gas 上限。
    pub max_gas_amount: u64,
    /// 交易过期时间（Unix 秒）；过期后节点直接拒收。
    pub expiration_timestamp_secs: u64,
}

/// 未签名转账：交给 agent 的「待签信封」。
// `Debug` 是给 `Result::unwrap_err()` 用的——它对 `Ok` 一侧的值也有约束，
// 少了这个派生，想断言「这个输入应该报错」的测试反而写不出来。
#[derive(Debug, Clone)]
pub struct UnsignedTransfer {
    /// 带**占位签名**的完整交易字节（BCS，带 `0x` 前缀）。
    pub unsigned_tx_hex: String,
    /// 真正要签的消息（带 `0x` 前缀）：`sha3_256("APTOS::RawTransaction") || bcs(RawTransaction)`。
    pub signing_payload_hex: String,
    /// 付款地址。
    pub sender: AccountAddress,
    /// 收款地址。
    pub receiver: AccountAddress,
    /// 写进 authenticator 的公钥。
    pub public_key: Vec<u8>,
    /// 序列号。
    pub sequence_number: u64,
    /// 链 ID。
    pub chain_id: u8,
    /// gas 单价。
    pub gas_unit_price: u64,
    /// gas 上限。
    pub max_gas_amount: u64,
    /// 过期时间（Unix 秒）。
    pub expiration_timestamp_secs: u64,
    /// 转账金额（octa）。
    pub amount: u64,
}

/// 占位签名：64 字节全零。
///
/// 它只用来把 authenticator 的**长度与布局**占住，好让 agent 之后
/// 「覆盖最后 64 字节」即可。全零不是合法签名，但这不影响序列化。
const PLACEHOLDER_SIGNATURE: [u8; 64] = [0u8; 64];

/// 构造「占位 authenticator」：形状与真实签名完全一致，只是签名字段全零。
///
/// 领域说明：Aptos 的交易是 `RawTransaction` + `Authenticator` **两层**结构，
/// authenticator 里同时带公钥与签名，两个字段都得占住位，
/// 否则外壳的字节长度会与最终交易不一致，agent 按「覆盖最后 64 字节」
/// 操作时就会错位——而且错位后反序列化可能仍然成功，只是验签失败，
/// 属于排查成本很高的静默缺陷。
///
/// 抽成函数而非在调用处内联，是为了让**生产代码与测试走同一条构造路径**：
/// 测试要拿它的序列化长度去切「交易体」，若两处各写一遍，
/// 一旦布局变了，测试量到的是旧布局，断言就会失真。
///
/// 语法说明：`?` 在 `Result` 上等价于「出错就提前 `return Err`」，
/// 这里两次 `?` 的错误类型都是 `SdkError`，故可直接连用而无需 `map_err`。
fn placeholder_authenticator(public_key: &[u8]) -> Result<TransactionAuthenticator, SdkError> {
    // 第一道关：严格的密码学校验（长度 + 点在曲线上）。返回值被丢弃，
    // 这一行的意义全在它的副作用——用 `_` 绑定表明我们只要校验结果。
    // 少了它，一个非曲线上的 32 字节也能组装出「看起来合法」的交易，
    // 但链上会拒签，且错误信息与本 SDK 无关。
    let _validated = aptos_sdk::crypto::Ed25519PublicKey::from_bytes(public_key)
        .map_err(|e| SdkError::invalid_argument(format!("非法 ed25519 公钥: {e}")))?;

    Ok(TransactionAuthenticator::Ed25519 {
        // 第二道关：转成 BCS 线上类型。这里的 `try_from_bytes` 只查长度，
        // 但长度必然已由上面那道关保证，故此处理论上不会失败。
        public_key: aptos_sdk::transaction::authenticator::Ed25519PublicKey::try_from_bytes(
            public_key,
        )
        .map_err(|e| SdkError::invalid_argument(format!("非法 ed25519 公钥: {e}")))?,
        signature: aptos_sdk::transaction::authenticator::Ed25519Signature::try_from_bytes(
            &PLACEHOLDER_SIGNATURE,
        )
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("构造占位签名失败: {e}")))?,
    })
}

/// 组装未签名转账（**纯函数**：不联网、不签名）。
///
/// 与 NEAR / SOL 那侧同样的分工：联网取元数据的部分单独放在
/// [`build_unsigned_transfer`] 里，这里只管序列化，
/// 于是「字节对不对」可以完全离线验证。
pub fn assemble_unsigned(p: TransferParams) -> Result<UnsignedTransfer, SdkError> {
    // 原生币转账走 `0x1::aptos_account::transfer(to, amount)`。
    let payload = EntryFunction::apt_transfer(p.receiver, p.amount)
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("构造转账 payload 失败: {e}")))?;

    // 未签名交易体。注意 Aptos 的「交易」是 `RawTransaction` + `Authenticator` 两层，
    // 与 ETH 那种「同一份字节里带签名字段」的扁平结构不同。
    let raw = RawTransaction::new(
        p.sender,
        p.sequence_number,
        payload.into(),
        p.max_gas_amount,
        p.gas_unit_price,
        p.expiration_timestamp_secs,
        ChainId::new(p.chain_id),
    );

    // 待签消息：由官方 SDK 生成，内部是 `sha3_256("APTOS::RawTransaction") || bcs(raw)`。
    let signing_message = raw
        .signing_message()
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("计算待签消息失败: {e}")))?;

    // 外壳：装一个占位 authenticator，让整笔交易的字节布局与最终形态一致。
    let placeholder = placeholder_authenticator(&p.public_key)?;
    let shell = SignedTransaction::new(raw, placeholder);
    let shell_bytes = aptos_sdk::aptos_bcs::to_bytes(&shell)
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("序列化未签名交易失败: {e}")))?;

    Ok(UnsignedTransfer {
        unsigned_tx_hex: format!("0x{}", hex::encode(&shell_bytes)),
        signing_payload_hex: format!("0x{}", hex::encode(&signing_message)),
        sender: p.sender,
        receiver: p.receiver,
        public_key: p.public_key,
        sequence_number: p.sequence_number,
        chain_id: p.chain_id,
        gas_unit_price: p.gas_unit_price,
        max_gas_amount: p.max_gas_amount,
        expiration_timestamp_secs: p.expiration_timestamp_secs,
        amount: p.amount,
    })
}

/// 联网版：取链 ID、序列号、gas 估价，然后交给 [`assemble_unsigned`] 组装。
///
/// 领域说明：这三项都是**防重放 / 计费**的必需品，且都只能从节点实时读：
/// - `chain_id`：防止主网签名被拿到测试网重放；
/// - `sequence_number`：Aptos 用它替代 nonce，每个账户单调递增；
/// - `gas_unit_price`：节点按当时的网络拥堵度估价，取不到就退回 100 octa。
///
/// 语法说明：`expiration_from_now_secs` 由调用方给出而不是在这里写死，
/// 是为了让测试能传固定值——把「当前时间」这类不可控输入推到边界，
/// 纯逻辑部分才可复现。
pub async fn build_unsigned_transfer(
    http: &Http,
    sender: AccountAddress,
    public_key: &[u8],
    receiver: AccountAddress,
    amount: u64,
    expiration_from_now_secs: u64,
) -> Result<UnsignedTransfer, SdkError> {
    // 1) 链 ID：GET / 的 `chain_id` 字段。
    let ledger = http.get_value("").await?;
    let chain_id = ledger
        .get("chain_id")
        .and_then(Value::as_u64)
        .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "账本信息缺少 chain_id"))?;
    // 链 ID 在 Aptos 协议里是 u8，超出范围即说明连错了节点。
    let chain_id: u8 = chain_id
        .try_into()
        .map_err(|_| SdkError::new(ErrorCode::ParseError, format!("chain_id 超出 u8 范围: {chain_id}")))?;

    // 2) 序列号：账户不存在（全新）时拿不到，此时按 0 处理——
    //    首笔交易本来就该用 0。
    let sequence_number = http
        .get_value(&format!("/accounts/{sender}"))
        .await
        .ok()
        .and_then(|v| v.get("sequence_number").cloned())
        .and_then(|v| chain_rpcutil::loose_u64(&v).ok())
        .unwrap_or(0);

    // 3) gas 估价：失败回退 100 octa（APT 常规水平）。
    let gas_unit_price = http
        .get_value("estimate_gas_price")
        .await
        .ok()
        .and_then(|g| g.get("gas_estimate").cloned())
        .and_then(|v| chain_rpcutil::loose_u64(&v).ok())
        .unwrap_or(100);

    // 4) 过期时间 = 现在 + 给定秒数。
    //
    // `duration_since(UNIX_EPOCH)` 只有在**系统时间早于 1970 年**时才会失败，
    // 那种机器也不该跑区块链软件，故 `unwrap_or_default()`（取 0）是可接受的兜底。
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    assemble_unsigned(TransferParams {
        sender,
        public_key: public_key.to_vec(),
        receiver,
        amount,
        sequence_number,
        chain_id,
        gas_unit_price,
        // 收款方若尚未注册 CoinStore，这笔交易会顺带创建它，开销比普通转账高，
        // 故 gas 上限放到 500_000（普通转账只需 ~10）。
        max_gas_amount: 500_000,
        expiration_timestamp_secs: now.saturating_add(expiration_from_now_secs),
    })
}

/// 广播**已签名**的交易字节，发完即返回哈希，不等确认。
///
/// 领域说明：走 `submit_transaction`（对应 REST `POST /transactions`），
/// 节点只做**准入校验**（签名、序列号、格式）后放进 mempool 就返回。
/// 它**不保证**交易最终执行成功——执行期的失败（Move 合约 abort、
/// gas 不足、账户未注册等）要等落块后才看得到。要确认请用 `tx(<hash>)` 查询。
pub async fn broadcast_raw(rpc_url: &str, raw: &[u8]) -> Result<String, SdkError> {
    // BCS 反序列化：走官方实现，顺带校验字节完整性。
    let signed: SignedTransaction = aptos_sdk::aptos_bcs::from_bytes(raw)
        .map_err(|e| SdkError::invalid_argument(format!("已签名交易不是合法 BCS: {e}")))?;

    // 全节点客户端按端点即时构造。官方 SDK 的 `AptosConfig::custom` 与
    // `FullnodeClient::new` 各返回一次 Result（前者校验 URL、后者建连接池），
    // 两次都映射到同一个错误文案上。
    let client = aptos_sdk::api::FullnodeClient::new(
        aptos_sdk::config::AptosConfig::custom(rpc_url)
            .map_err(|e| SdkError::new(ErrorCode::RpcError, format!("构造 APT 客户端失败: {e}")))?,
    )
    .map_err(|e| SdkError::new(ErrorCode::RpcError, format!("构造 APT 客户端失败: {e}")))?;

    let pending = client
        .submit_transaction(&signed)
        .await
        .map_err(|e| SdkError::new(ErrorCode::RpcError, format!("广播 APT 交易失败: {e}")))?;

    Ok(pending.data.hash.to_string())
}

/// 单元测试模块：`#[cfg(test)]` 保证只在 `cargo test` 时编译。
///
/// 原则与前面几条链一致：**不拿自己的公式当标准**。
/// 「签一下再验一下」对任意字节都成立，抓不到「待签消息算错了」这类缺陷。
/// 这里的两条硬断言分别对着独立实现的 sha3-256 与官方的 `build_and_sign`。
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_sdk::account::Ed25519Account;
    use aptos_sdk::crypto::Ed25519PrivateKey;
    use aptos_sdk::transaction::TransactionBuilder;
    use sha3::{Digest, Sha3_256};

    // 固定私钥（32 个 0x11）→ 确定性账户，测试才可复现。
    const TEST_PRIVKEY: [u8; 32] = [0x11; 32];
    // 固定输入，避免任何来自时钟或随机数的不确定性。
    const TEST_SEQ: u64 = 7;
    const TEST_CHAIN_ID: u8 = 1;
    const TEST_GAS_PRICE: u64 = 100;
    const TEST_MAX_GAS: u64 = 500_000;
    const TEST_EXPIRATION: u64 = 1_700_000_000;
    const TEST_AMOUNT: u64 = 1_000_000;
    /// 收款地址。写成常量而非散落的字面量，是为了让「与官方路径对拍」那条测试
    /// 用的收款方与生产代码用的是**同一份**输入——否则拼错一位也会让对拍失真。
    const TEST_RECEIVER: &str = "0x22";

    /// 固定输入的参数集。
    ///
    /// 语法说明：把「造参数」和「组装」拆成两个函数，是为了让测试能
    /// **只改动其中一个字段**再组装（见 `non_curve_public_key_is_rejected`）。
    /// 若只有一个 `fixed_unsigned()`，改字段就得复制一整份结构体字面量。
    fn fixed_params() -> TransferParams {
        let account = test_account();
        TransferParams {
            sender: account.address(),
            public_key: account.public_key().to_bytes().to_vec(),
            receiver: AccountAddress::from_hex(TEST_RECEIVER).unwrap(),
            amount: TEST_AMOUNT,
            sequence_number: TEST_SEQ,
            chain_id: TEST_CHAIN_ID,
            gas_unit_price: TEST_GAS_PRICE,
            max_gas_amount: TEST_MAX_GAS,
            expiration_timestamp_secs: TEST_EXPIRATION,
        }
    }

    /// 用固定输入组装一笔未签名转账。
    fn fixed_unsigned() -> UnsignedTransfer {
        assemble_unsigned(fixed_params()).unwrap()
    }

    fn test_account() -> Ed25519Account {
        Ed25519Account::from_private_key(Ed25519PrivateKey::from_bytes(&TEST_PRIVKEY).unwrap())
    }

    fn decode_prefixed(raw: &str) -> Vec<u8> {
        hex::decode(raw.trim_start_matches("0x")).unwrap()
    }

    /// **对拍一**：待签消息必须等于「域名分隔前缀 + 交易体 BCS」，用独立实现算一遍。
    ///
    /// Aptos 的这个前缀（`sha3_256("APTOS::RawTransaction")`）是**防跨协议重放**的关键：
    /// 少了它，同一把 ed25519 密钥在其它协议里签出的字节可能被拿来当 Aptos 交易提交。
    /// 这项校验在链上不会报错、只会让签名验证失败，属于典型的静默缺陷。
    #[test]
    fn signing_message_is_prefixed_bcs_of_the_raw_transaction() {
        let unsigned = fixed_unsigned();
        let payload = decode_prefixed(&unsigned.signing_payload_hex);
        let shell = decode_prefixed(&unsigned.unsigned_tx_hex);

        // 独立重算：sha3 前缀 + 交易体字节。
        //
        // 交易体 = 外壳去掉尾部 authenticator。authenticator 的长度用官方序列化器量出来，
        // 不写死常量——这样即便上游调整布局，测试仍然测的是「前缀对不对」这件事本身。
        let placeholder_auth =
            aptos_sdk::aptos_bcs::to_bytes(&placeholder_authenticator(&unsigned.public_key).unwrap())
                .unwrap();
        let body = &shell[..shell.len() - placeholder_auth.len()];

        let mut expected = Sha3_256::digest(b"APTOS::RawTransaction").to_vec();
        expected.extend_from_slice(body);
        assert_eq!(payload, expected, "待签消息应等于 sha3_256(域名前缀) || bcs(RawTransaction)");
        // 前缀固定 32 字节，后面才是交易体。
        assert!(payload.len() > 32);
    }

    /// **对拍二**：模拟 agent 的完整操作（签待签消息 → 覆盖最后 64 字节），
    /// 结果必须与官方 `TransactionBuilder::build_and_sign` **逐字节相同**。
    ///
    /// 这条测试是整套无私钥流程的验收标准：它一次覆盖了待签消息的正确性、
    /// authenticator 的布局、以及「覆盖最后 64 字节」这条操作说明是否成立。
    #[test]
    fn splicing_a_signature_reproduces_the_official_signed_transaction() {
        let account = test_account();
        let unsigned = fixed_unsigned();

        let mut shell = decode_prefixed(&unsigned.unsigned_tx_hex);
        let payload = decode_prefixed(&unsigned.signing_payload_hex);

        // --- agent 侧操作 1：对整段待签消息做一次 ed25519 签名 ---
        let signature = account.sign_message(&payload);
        let signature_bytes = signature.to_bytes();
        assert_eq!(signature_bytes.len(), 64);

        // --- agent 侧操作 2：覆盖外壳的最后 64 字节 ---
        let tail = shell.len() - 64;
        shell[tail..].copy_from_slice(&signature_bytes);

        // --- SDK 侧：反序列化回官方类型 ---
        let spliced: SignedTransaction = aptos_sdk::aptos_bcs::from_bytes(&shell).unwrap();

        // --- 与官方路径对拍 ---
        let official = TransactionBuilder::new()
            .sender(account.address())
            .sequence_number(TEST_SEQ)
            .payload(
                EntryFunction::apt_transfer(
                    AccountAddress::from_hex(TEST_RECEIVER).unwrap(),
                    TEST_AMOUNT,
                )
                .unwrap()
                .into(),
            )
            .chain_id(ChainId::new(TEST_CHAIN_ID))
            .max_gas_amount(TEST_MAX_GAS)
            .gas_unit_price(TEST_GAS_PRICE)
            .expiration_timestamp_secs(TEST_EXPIRATION)
            .build_and_sign(&account)
            .unwrap();

        assert_eq!(
            aptos_sdk::aptos_bcs::to_bytes(&spliced).unwrap(),
            aptos_sdk::aptos_bcs::to_bytes(&official).unwrap(),
            "拼接出的交易必须与官方签名结果逐字节一致"
        );

        // 最后确认签名本身能验过——覆盖的正是我们声明的那段待签消息。
        assert!(
            account
                .public_key()
                .verify(&payload, &signature)
                .is_ok()
        );
    }

    /// 外壳布局：必须以交易体开头、以 64 字节全零占位签名结尾。
    ///
    /// 这两条断言直接支撑「覆盖最后 64 字节」这条给 agent 的说明，
    /// 且**不硬编码 authenticator 的具体长度**——上游若调整布局，
    /// 只要「签名仍是最后一个字段」这个不变式成立，测试就仍然有效。
    #[test]
    fn placeholder_signature_sits_at_the_tail() {
        let unsigned = fixed_unsigned();
        let shell = decode_prefixed(&unsigned.unsigned_tx_hex);

        assert!(shell.ends_with(&[0u8; 64]), "外壳尾部应是 64 字节全零占位签名");
        // 外壳 = 交易体 + authenticator，故必然以交易体字节开头。
        let raw_bytes = aptos_sdk::aptos_bcs::to_bytes(&RawTransaction::new(
            unsigned.sender,
            TEST_SEQ,
            EntryFunction::apt_transfer(unsigned.receiver, TEST_AMOUNT)
                .unwrap()
                .into(),
            TEST_MAX_GAS,
            TEST_GAS_PRICE,
            TEST_EXPIRATION,
            ChainId::new(TEST_CHAIN_ID),
        ))
        .unwrap();
        assert!(shell.starts_with(&raw_bytes), "外壳应以 bcs(RawTransaction) 开头");
    }

    /// 公钥必须做**密码学**校验，而不只是查长度。
    ///
    /// 领域说明：`0x02` 重复 32 次这一串字节，长度合法（32）、
    /// 且解码出的 y 坐标小于域素数 p，但对应的 x² **不是二次剩余**——
    /// 也就是说它根本不是曲线上的点。若只查长度就放行，
    /// 组装出的交易在链上会被拒签，而报错来自节点、与本 SDK 无关，
    /// 排查时很难想到是公钥没验。
    ///
    /// 语法说明：`assert!(matches!(..))` 比 `assert!(result.is_err())` 更进一步：
    /// 它顺带锁定了错误**种类**是参数类（调用方的锅）而非内部错误（SDK 的锅）。
    #[test]
    fn non_curve_public_key_is_rejected() {
        let mut params = fixed_params();
        params.public_key = vec![0x02u8; 32];
        let err = assemble_unsigned(params).unwrap_err();
        assert!(
            matches!(err.code, ErrorCode::InvalidArgument),
            "不在曲线上的公钥应被判为参数错误，实际为: {err}"
        );
    }

    /// 关键字段必须能在反序列化后原样取出（防重放的两个字段尤其不能错）。
    #[test]
    fn shell_round_trips_through_bcs() {
        let unsigned = fixed_unsigned();
        let signed: SignedTransaction =
            aptos_sdk::aptos_bcs::from_bytes(&decode_prefixed(&unsigned.unsigned_tx_hex))
                .expect("外壳必须能反序列化成 SignedTransaction");

        assert_eq!(signed.raw_txn.sender, unsigned.sender);
        assert_eq!(signed.raw_txn.sequence_number, TEST_SEQ);
        assert_eq!(signed.raw_txn.chain_id, ChainId::new(TEST_CHAIN_ID));
        assert_eq!(signed.raw_txn.expiration_timestamp_secs, TEST_EXPIRATION);
        assert_eq!(signed.raw_txn.gas_unit_price, TEST_GAS_PRICE);
        assert_eq!(signed.raw_txn.max_gas_amount, TEST_MAX_GAS);
    }
}
