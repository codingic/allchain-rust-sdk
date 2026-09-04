//! BTC 的「无私钥两段式」模块：SDK 搭模板 → agent 逐输入签名 → SDK 重组并广播。
//!
//! # 为什么 BTC 不能沿用「一笔交易一个待签对象」的模型
//!
//! 前面几条链（ETH / SOL / NEAR / APT / SUI）都是**账户模型**：
//! 一笔交易只有一个待签哈希，签完得到一个签名，塞回交易体即可。
//! BTC 是 **UTXO 模型**，签名粒度是「每个输入一个」：
//!
//! - 一笔交易有 N 个输入，就要算 N 个 **sighash**、做 N 次签名；
//! - 每个 sighash 覆盖「全部输入 + 全部输出」的组合摘要，
//!   所以**改动任何一个输入都会让其它所有输入的签名失效**；
//! - 两种脚本的 sighash 算法还不一样：P2WPKH 走 **BIP143**（把输入金额也混进哈希），
//!   P2PKH 走**传统算法**（不混金额，因此有「少找零攻击」的历史缺陷）。
//!
//! 因此这里的待签材料是**一个数组**，而不是单个 `signing_payload_hex`。
//! 相应地，广播阶段要收回的也是一个**签名数组**
//! （`SubmitRequest.signatures`，按索引与待签数组一一对应）。
//!
//! # 为什么签名要「原样回传上下文」而不是让调用方自己拼
//!
//! 可以：调用方拿到 `unsigned_tx_hex` 后自己算 sighash、自己填 witness。
//! 但要写对，调用方必须同时搞对三件事——DER 编码、**低 S 归一化**、见证/scriptSig 的
//! 结构差异。这三者任一出错，产出的是**格式合法但语义错误**的交易：
//! 本地签名成功、序列化成功，直到广播才被节点以「non-mandatory-script-verify-flag」
//! 拒掉，而错误信息不会告诉你错在哪一步。
//!
//! 所以这里沿用 TON 那套做法：
//!   1. `assemble_unsigned` 下发 `unsigned_tx_hex` + 逐输入 sighash + 不透明 `SubmitContext`；
//!   2. agent 对每个 sighash 各签一次，产出 **64 字节紧凑签名**（`r || s`）；
//!   3. `assemble_signed` 用上下文重建交易、**逐个验签**后再拼装。
//!
//! 第 3 步的验签是硬要求：拼接前先验，就能把「错序 / 错链 / 被篡改的上下文」
//! 挡在本地，而不是让一笔注定失败的交易上链。
//!
//! # 编码约定（agent 侧）
//! - 待签对象是 **32 字节哈希**（已经是双 SHA256 的结果），**不要再哈希一次**；
//! - 签名用 **secp256k1**，输出 **64 字节紧凑格式** `r(32) || s(32)`，十六进制；
//! - SDK 会做低 S 归一化（BIP62）与 DER 编码，并在末尾补 `0x01`（SIGHASH_ALL）。

use std::str::FromStr;

use anyhow::{Context, Result, bail};
// `encode` 是比特币的字节级序列化（非 JSON）。
use bitcoin::consensus::encode;
// `Hash` trait 提供 `to_byte_array()` 这类定长哈希操作。
use bitcoin::hashes::Hash;
// `Secp256k1` 是椭圆曲线运算上下文；`new()` 带完整预计算表，可签名亦可验签。
use bitcoin::key::Secp256k1;
// `PushBytesBuf` 是「可直接压入脚本的字节缓冲区」，带 520 字节上限检查。
use bitcoin::script::PushBytesBuf;
// 紧凑签名（`r||s`）与底层公钥类型；`bitcoin::ecdsa::Signature` 才是带 sighash 标志的类型。
use bitcoin::secp256k1::ecdsa::Signature as SecpSignature;
use bitcoin::secp256k1::{Message, PublicKey as SecpPublicKey};
// `SighashCache` 会缓存中间结果，逐输入签名时避免重复哈希。
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness, absolute::LockTime, transaction::Version,
};
// `Serialize` / `Deserialize`：上下文里没有任何私密材料，序列化是安全的。
use serde::{Deserialize, Serialize};

use crate::backend::Chain;
use crate::network::NetworkArg;
use crate::transactions::{
    InputInfo, Selected, build_unsigned_transaction, collect_candidates, recommended_fee_rate,
    select_coins,
};
use crate::units::{ScriptKind, format_btc};

/// 紧凑签名的长度：`r(32) || s(32)`。
///
/// 领域说明：多数 secp256k1 高层库（ethers / web3.py / k256）签名输出的都是这 64 字节。
/// **不**接受 DER：DER 是变长的（前导零导致 70~73 字节浮动），
/// 若同时接受两种格式就只能靠「猜长度」区分，猜错的代价是广播一笔无效交易。
/// 与其静默兜底，不如明确拒绝并报错。
pub const COMPACT_SIGNATURE_LEN: usize = 64;

/// 压缩公钥的长度：`02/03 ‖ X(32)`。
const COMPRESSED_PUBLIC_KEY_LEN: usize = 33;

/// 脚本类型名（上下文 JSON 里用的字符串标签）。
pub const SCRIPT_TYPE_P2WPKH: &str = "p2wpkh";
/// 传统 P2PKH 的脚本类型名。
///
/// **定位说明（为什么还留着）**：本 crate 的**构造**路径（`assemble_unsigned`）
/// 只扫 P2WPKH，签名器也只接受 P2WPKH，所以新交易不会再产生 P2PKH 输入。
/// 这里保留该分支，是为了让**广播**阶段（`assemble_signed` / `submit_tx`）仍能处理
/// 改造前已生成、尚未广播的上下文——那些上下文里的输入带着 `script_type = "p2pkh"`，
/// 直接拒绝会让它们永远发不出去。它是兼容路径，不是新交易走的路径。
pub const SCRIPT_TYPE_P2PKH: &str = "p2pkh";

/// 由压缩公钥派生的两个可花费地址。
///
/// 领域说明：同一个公钥在不同脚本类型下会派生出**完全不同**的地址，
/// 它们各自能收到币，但手续费与兼容性不同。两条路径都要扫，
/// 否则「币躺在 P2PKH 地址上」的用户会收到「没有可用 UTXO」的误报。
///
/// ⚠️ 两个地址都由**压缩**公钥派生。未压缩公钥（65 字节）派生的 P2PKH 地址
/// 是另一套（2012 年之前的钱包才用），本模块不支持——若你的币在那类地址上，
/// 请用一体式 `transfer`（传 WIF 私钥）。
#[derive(Debug, Clone)]
pub struct KeyAddresses {
    /// 原生隔离见证地址（`bc1q...`），也是**默认找零地址**。
    pub p2wpkh: Address,
    /// 由压缩公钥派生的传统地址（`1...`）。
    pub p2pkh: Address,
}

/// 单个输入的待签材料。
///
/// 领域说明：字段里带了 `value` 与 `script_type`，是因为 P2WPKH 的 BIP143
/// sighash **需要输入金额**，而金额不在交易字节里——少了它就签不出正确的哈希。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSigning {
    /// 输入下标，与 `SubmitRequest.signatures` 的索引一一对应。
    pub index: usize,
    /// 被引用的前序交易 ID。
    pub txid: String,
    /// 前序交易里的第几个输出。
    pub vout: u32,
    /// 该输入的金额（satoshi）。
    pub value: u64,
    /// 脚本类型：`p2wpkh` / `p2pkh`。
    pub script_type: String,
    /// **真正要签的 32 字节哈希**（十六进制，无 `0x` 前缀）。
    pub sighash: String,
}

/// 广播阶段重组交易所需的全部参数，由 `assemble_unsigned` 下发、调用方原样回传。
///
/// 为什么要存 `value` 与 `script_pubkey`：这两项**不在**交易字节里，
/// 但 P2WPKH 的 BIP143 sighash 计算必须要它们。缺少任何一项都无法重算 sighash，
/// 也就无法验签——这正是「必须回传上下文」而非「只回传交易字节」的根因。
///
/// 为什么还存了 `unsigned_tx_hex`：它是一条**自检锚点**。
/// 重建出的交易若与它不一致，说明上下文在往返途中被改过，直接拒绝而不是带病广播。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitContext {
    /// 网络名（`mainnet` / `testnet` / ...）。用于拦住「主网构造、测试网广播」。
    pub network: String,
    /// 交易版本号。
    pub version: i32,
    /// 绝对时间锁（0 = 立即可入块）。
    pub locktime: u32,
    /// 签名所用公钥（压缩格式，33 字节，十六进制）。
    pub public_key: String,
    /// 输入明细（含 sighash 所需的金额与脚本）。
    pub inputs: Vec<ContextInput>,
    /// 输出明细。
    pub outputs: Vec<ContextOutput>,
    /// 构造阶段的未签名交易字节，用于重建后自检。
    pub unsigned_tx_hex: String,
}

/// 上下文里的单个输入。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextInput {
    pub txid: String,
    pub vout: u32,
    /// nSequence 值（RBF 信号就编码在这里）。
    pub sequence: u32,
    /// 该输入值多少 satoshi——**BIP143 sighash 需要它**。
    pub value: u64,
    /// 锁定脚本 `scriptPubKey` 的十六进制。
    pub script_pubkey: String,
    /// 脚本类型：`p2wpkh` / `p2pkh`。
    pub script_type: String,
}

/// 上下文里的单个输出。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextOutput {
    /// 金额（satoshi）。
    pub value: u64,
    /// 锁定脚本的十六进制。
    pub script_pubkey: String,
}

/// 构造未签名转账的请求参数（**不含任何私钥**）。
#[derive(Debug, Clone)]
pub struct UnsignedRequest {
    /// 签名公钥（压缩格式）。决定了能花哪些 UTXO。
    pub public_key: CompressedPublicKey,
    /// 收款地址（已校验网络）。
    pub to: Address,
    /// 转账金额（satoshi）。
    pub amount_sat: u64,
    /// 费率（sat/vB）。
    pub fee_rate: f64,
    /// 是否启用 RBF。
    pub rbf: bool,
}

/// 未签名转账的构造结果。
#[derive(Debug, Clone)]
pub struct UnsignedTransfer {
    /// 付款地址（`from`，由公钥派生，已与请求校验一致）。
    pub from: String,
    /// 收款地址。
    pub to: String,
    /// 转账金额（satoshi）。
    pub amount_sat: u64,
    /// 将支付的手续费（satoshi）。
    pub fee: u64,
    /// 费率（sat/vB）。
    pub fee_rate: f64,
    /// 找零金额；0 表示已并入手续费。
    pub change: u64,
    /// 找零回到哪个地址。
    pub change_address: String,
    /// vsize 估算值。
    pub vsize_estimate: u64,
    /// 未签名交易的十六进制（scriptSig / witness 均为空）。
    pub unsigned_tx_hex: String,
    /// 逐输入的待签哈希，顺序与 `SubmitContext.inputs` 完全一致。
    pub signing_payloads: Vec<InputSigning>,
    /// 广播阶段要原样回传的上下文。
    pub context: SubmitContext,
    /// 输入明细，供调用方展示与审计。
    pub inputs: Vec<InputInfo>,
}

/// 解析压缩公钥：接受带或不带 `0x` 前缀的十六进制。
///
/// 为什么**只**收压缩格式：P2WPKH 地址与见证字段都以压缩公钥为基础，
/// 未压缩公钥派生出的是另一套地址。此处严格拒绝，避免「地址能算出来、
/// 但见证填不进去」的半吊子状态。
pub fn parse_public_key(raw: &str) -> Result<CompressedPublicKey> {
    let trimmed = raw.trim();
    // `strip_prefix` 返回 `Option<&str>`；`unwrap_or` 在没有前缀时退回原串。
    // 这一步只是「容忍 `0x`」，不做校验——真正的校验交给 `hex::decode` 与下面的检查。
    let body = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(body).with_context(|| format!("公钥不是合法十六进制: {trimmed}"))?;
    // **长度必须自己先查一遍**。
    //
    // 底层 `CompressedPublicKey::from_slice` 走的是 secp256k1 的 `PublicKey::from_slice`，
    // 它会同时接受 **33 字节压缩**与 **65 字节未压缩**两种编码——名字里带
    // "Compressed" 并不表示它只收压缩。少了这一句，「传一枚合法的 65 字节未压缩公钥」
    // 会被静默接受，随后派生出的见证与地址都对不上，直到广播才失败。
    if bytes.len() != COMPRESSED_PUBLIC_KEY_LEN {
        bail!(
            "非法 BTC 压缩公钥（{} 字节）：需为 33 字节压缩格式（02/03 开头）的十六进制",
            bytes.len()
        );
    }
    // 剩下来的校验（点在曲线上）交给 `from_slice`。
    CompressedPublicKey::from_slice(&bytes).with_context(|| {
        format!(
            "非法 BTC 压缩公钥（{} 字节）：需为 33 字节压缩格式（02/03 开头）的十六进制",
            bytes.len()
        )
    })
}

/// 由压缩公钥派生两个可花费地址。
///
/// 语法说明：`CompressedPublicKey::pubkey_hash()` 求的是
/// `hash160(压缩公钥 33 字节)`，与 `Address::p2wpkh` 内部用的是同一个哈希，
/// 因此两个地址共享一次哈希计算（库内部会再算一次，这里代码量不变但语义清晰）。
pub fn key_addresses(public_key: &CompressedPublicKey, network: Network) -> KeyAddresses {
    KeyAddresses {
        p2wpkh: Address::p2wpkh(public_key, network),
        // 注意这里传的是 `pubkey_hash()` 的**结果**，于是 P2PKH 地址也是
        // hash160(**压缩**公钥)，与 2012 年后所有主流钱包一致。
        p2pkh: Address::p2pkh(public_key.pubkey_hash(), network),
    }
}

/// 把脚本类型枚举映射成上下文里用的字符串标签。
///
/// 语法说明：`match self` 对 `Copy` 枚举按值匹配；返回 `&'static str`
/// 是因为所有分支都是字符串字面量，无需分配。
pub fn script_type_name(kind: ScriptKind) -> &'static str {
    match kind {
        ScriptKind::P2wpkh => SCRIPT_TYPE_P2WPKH,
        ScriptKind::P2pkh => SCRIPT_TYPE_P2PKH,
    }
}

/// 把上下文里的字符串标签还原成脚本类型枚举，未知值直接报错。
pub fn parse_script_type(raw: &str) -> Result<ScriptKind> {
    match raw {
        SCRIPT_TYPE_P2WPKH => Ok(ScriptKind::P2wpkh),
        SCRIPT_TYPE_P2PKH => Ok(ScriptKind::P2pkh),
        other => bail!("未知脚本类型: {other}（仅支持 p2wpkh / p2pkh）"),
    }
}

/// 构造未签名转账：拉 UTXO → 选币 → 搭模板 → 逐输入算 sighash → 打包上下文。
///
/// 全程**不接触私钥**。`public_key` 只用于两件事：派生可花费地址（找 UTXO）、
/// 以及放进上下文（广播阶段填进见证 / scriptSig 并验签）。
pub async fn assemble_unsigned(
    chain: &Chain,
    public_key: &CompressedPublicKey,
    req: &UnsignedRequest,
) -> Result<UnsignedTransfer> {
    let network_arg = chain.network();
    let network = network_arg.network();

    // 1) 由公钥派生可花费地址，向索引器问 UTXO。
    let addresses = key_addresses(public_key, network);
    //
    // **只扫 P2WPKH（`bc1q…`）**：签名器只实现 BIP143 那套 sighash，
    // 若这里也把 P2PKH（`1…`）地址上的 UTXO 选进来，构造出的输入会带着
    // `script_type = "p2pkh"`，签名器只能拒绝——这笔交易就永远签不出来。
    // 宁可在这里少选，也不要构造出一笔注定签不了的交易。
    let scan_targets = vec![(addresses.p2wpkh.clone(), ScriptKind::P2wpkh)];
    let candidates = collect_candidates(chain, &scan_targets).await?;
    if candidates.is_empty() {
        // 把地址报出来，用户可拿去区块浏览器核对。
        bail!("地址 {} 上没有可用 UTXO", addresses.p2wpkh);
    }

    // 2) 选币（纯函数）。
    let selection = select_coins(candidates, req.amount_sat, req.fee_rate)?;

    // 3) 搭未签名骨架（纯函数）。
    //
    // 找零固定回到 P2WPKH 地址：与输入同一套脚本，手续费也最低。
    let tx = build_unsigned_transaction(
        &selection,
        &req.to.script_pubkey(),
        &addresses.p2wpkh.script_pubkey(),
        req.amount_sat,
        req.rbf,
    )?;

    // 4) 打包上下文（先建上下文，再算 sighash，保证两者用的是同一批输入描述）。
    let context = build_context(network_arg, &tx, public_key, &selection.selected)?;

    // 5) 逐输入算 sighash。
    //
    // 语法说明：`&context` 是借用而非移动——`context` 后面还要塞进返回值。
    let hashes = sighashes(&tx, &context)?;
    if hashes.len() != selection.selected.len() {
        // 这条断言本不该触发（两边都按输入数展开），留着是为了防止将来
        // 有人给 `sighashes` 加了过滤分支却忘了同步这里。
        bail!(
            "sighash 数量({})与输入数量({})不一致",
            hashes.len(),
            selection.selected.len()
        );
    }
    let signing_payloads = selection
        .selected
        .iter()
        .zip(hashes.iter())
        // `.enumerate()` 放在 `.zip()` 之前：下标取自选币结果的顺序，
        // 与 `context.inputs` 的顺序天然一致。
        .enumerate()
        .map(|(index, (selected, hash))| InputSigning {
            index,
            txid: selected.utxo.txid.clone(),
            vout: selected.utxo.vout,
            value: selected.utxo.value,
            script_type: script_type_name(selected.kind).to_string(),
            sighash: hex::encode(hash),
        })
        .collect();

    let inputs = selection
        .selected
        .iter()
        .map(|s| InputInfo {
            txid: s.utxo.txid.clone(),
            vout: s.utxo.vout,
            value: s.utxo.value,
            confirmed: s.utxo.confirmed,
        })
        .collect();

    Ok(UnsignedTransfer {
        from: addresses.p2wpkh.to_string(),
        to: req.to.to_string(),
        amount_sat: req.amount_sat,
        fee: selection.fee,
        fee_rate: req.fee_rate,
        change: selection.change,
        change_address: addresses.p2wpkh.to_string(),
        vsize_estimate: selection.vsize_estimate,
        unsigned_tx_hex: encode::serialize_hex(&tx),
        signing_payloads,
        context,
        inputs,
    })
}

/// 把一笔未签名交易转成可回传的上下文。
///
/// 领域说明：`value` 与 `script_pubkey` 来自**选币结果**而非交易字节——
/// 它们不在交易里，但 BIP143 sighash 必须要它们。这也是为什么广播阶段
/// 不能只凭 `unsigned_tx_hex` 自己重算。
pub fn build_context(
    network: NetworkArg,
    tx: &Transaction,
    public_key: &CompressedPublicKey,
    selected: &[Selected],
) -> Result<SubmitContext> {
    if tx.input.len() != selected.len() {
        bail!(
            "交易输入数({})与选币结果({})不一致",
            tx.input.len(),
            selected.len()
        );
    }
    // `zip` 把两个等长序列并排迭代；长度已在上面校验过，不会静默丢项。
    let inputs = tx
        .input
        .iter()
        .zip(selected.iter())
        .map(|(txin, s)| ContextInput {
            txid: txin.previous_output.txid.to_string(),
            vout: txin.previous_output.vout,
            // `to_consensus_u32()` 把 `Sequence` 还原成链上字节对应的整数。
            sequence: txin.sequence.to_consensus_u32(),
            value: s.utxo.value,
            script_pubkey: hex::encode(s.script.as_bytes()),
            script_type: script_type_name(s.kind).to_string(),
        })
        .collect();

    let outputs = tx
        .output
        .iter()
        .map(|out| ContextOutput {
            // `to_sat()` 把 `Amount` 新类型拆回 u64。
            value: out.value.to_sat(),
            script_pubkey: hex::encode(out.script_pubkey.as_bytes()),
        })
        .collect();

    Ok(SubmitContext {
        network: network.as_str().to_string(),
        // `Version` 是元组结构体，`.0` 取出内部的 i32。
        version: tx.version.0,
        locktime: tx.lock_time.to_consensus_u32(),
        public_key: hex::encode(public_key.to_bytes()),
        inputs,
        outputs,
        unsigned_tx_hex: encode::serialize_hex(tx),
    })
}

/// 由上下文重建未签名交易，并自检它与上下文里记录的字节**逐字节一致**。
///
/// 领域说明：这条自检是「上下文是否被篡改」的第一道闸。
/// 上下文会经过 agent 手、可能被存进数据库、可能跨进程传输，
/// 若中途任何一个字段被改动（金额、找零、收款脚本……），
/// 重建出的字节就对不上 `unsigned_tx_hex`，这里会立刻失败——
/// 而不是等到广播后才发现「链上交易和自己以为的不是一笔」。
pub fn rebuild_unsigned(ctx: &SubmitContext) -> Result<Transaction> {
    let mut inputs = Vec::with_capacity(ctx.inputs.len());
    for input in &ctx.inputs {
        let txid = Txid::from_str(&input.txid)
            .with_context(|| format!("上下文里的 txid 非法: {}", input.txid))?;
        // 脚本类型在这里顺带校验一次：未知标签会在重建阶段就暴露，
        // 不会带着一个无法签名的输入走到广播。
        parse_script_type(&input.script_type)?;
        inputs.push(TxIn {
            previous_output: OutPoint {
                txid,
                vout: input.vout,
            },
            // 重建的是**未签名**模板：scriptSig 与 witness 恒为空。
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(input.sequence),
            witness: Witness::new(),
        });
    }

    let mut outputs = Vec::with_capacity(ctx.outputs.len());
    for output in &ctx.outputs {
        outputs.push(TxOut {
            value: Amount::from_sat(output.value),
            // `ScriptBuf::from(Vec<u8>)`：由原始字节直接构造脚本，不做任何解析校验
            //（这是刻意的——上下文里的脚本来自构造阶段，本就应当是合法字节）。
            script_pubkey: ScriptBuf::from(
                hex::decode(&output.script_pubkey)
                    .with_context(|| format!("输出脚本不是合法十六进制: {}", output.script_pubkey))?,
            ),
        });
    }

    let tx = Transaction {
        // `Version(i32)`：元组结构体构造，与 `tx.version.0` 的读取互为逆运算。
        version: Version(ctx.version),
        lock_time: LockTime::from_consensus(ctx.locktime),
        input: inputs,
        output: outputs,
    };

    let rebuilt = encode::serialize_hex(&tx);
    if rebuilt != ctx.unsigned_tx_hex {
        bail!(
            "上下文自检失败：重建出的交易与记录的未签名交易不一致（重建 {} 字节，记录 {} 字节）",
            rebuilt.len() / 2,
            ctx.unsigned_tx_hex.len() / 2
        );
    }
    Ok(tx)
}

/// 逐输入计算待签哈希，顺序与 `ctx.inputs` 一致。
///
/// 领域说明：两种脚本的 sighash 算法不同——
/// - `p2wpkh` 走 **BIP143**，把**本输入金额**混进哈希（`p2wpkh_signature_hash`）；
/// - `p2pkh` 走**传统算法**，不混金额（`legacy_signature_hash`）。
///
/// 语法说明：`SighashCache::new(tx)` 持有 `tx` 的不可变借用，
/// 而取哈希的方法需要 `&mut self`，所以 `cache` 必须声明为 `mut`。
/// 返回的 `Vec<[u8; 32]>` 是**自有**数据，不借用 `tx`，
/// 因此调用方拿到返回值后可以安全地修改 `tx`（拼装阶段正是这么做的）。
pub fn sighashes(tx: &Transaction, ctx: &SubmitContext) -> Result<Vec<[u8; 32]>> {
    if tx.input.len() != ctx.inputs.len() {
        bail!(
            "交易输入数({})与上下文输入数({})不一致",
            tx.input.len(),
            ctx.inputs.len()
        );
    }
    let mut cache = SighashCache::new(tx);
    let mut out = Vec::with_capacity(ctx.inputs.len());
    for (index, input) in ctx.inputs.iter().enumerate() {
        let script = ScriptBuf::from(
            hex::decode(&input.script_pubkey)
                .with_context(|| format!("输入 {} 的脚本不是合法十六进制", index))?,
        );
        let sighash = sighash_for_input(
            &mut cache,
            index,
            &script,
            parse_script_type(&input.script_type)?,
            input.value,
        )?;
        out.push(sighash);
    }
    Ok(out)
}

/// 计算**单个**输入的 sighash。
///
/// 单独暴露出来有两个理由：一是让 `sighashes` 的循环体保持一行可读；
/// 二是测试要拿 **BIP143 官方测试向量**对它逐字段对拍——
/// 那条向量是一笔 2 输入的交易，其中只有第 2 个输入是见证输入，
/// 若只能「一次性算全部」，就没法只针对那一个输入比对。
///
/// 语法说明：`cache: &mut SighashCache<&Transaction>` 写成可变引用，
/// 是因为取哈希的方法需要 `&mut self`（它要往内部缓存里写中间结果）。
pub fn sighash_for_input(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    script_pubkey: &ScriptBuf,
    kind: ScriptKind,
    value: u64,
) -> Result<[u8; 32]> {
    // 两种 sighash 的**类型不同**（`bip143::Sighash` vs `LegacySighash`），
    // 所以要在各自的分支里就转成 `[u8; 32]`，否则 match 两边的类型对不上。
    // 这层新类型正是 rust-bitcoin 用来防止「把 SegWit 摘要当传统摘要用」的手段。
    let sighash = match kind {
        ScriptKind::P2wpkh => cache
            .p2wpkh_signature_hash(
                index,
                script_pubkey,
                // **BIP143 的关键设计**：把本输入的金额混进哈希。
                Amount::from_sat(value),
                // `SIGHASH_ALL`：签名覆盖全部输入与全部输出，
                // 即「我认可这笔交易的每一个细节」。
                EcdsaSighashType::All,
            )?
            .to_byte_array(),
        ScriptKind::P2pkh => cache
            .legacy_signature_hash(
                index,
                script_pubkey,
                // 传统算法收的是「1 字节标志」而不是枚举，`to_u32()` 把它取出来。
                EcdsaSighashType::All.to_u32(),
            )?
            .to_byte_array(),
    };
    Ok(sighash)
}

/// 把 agent 给的 64 字节紧凑签名转成比特币链上格式：`DER || SIGHASH_ALL(0x01)`。
///
/// 领域说明——两处必须做对、做错了却不报错的地方：
/// 1. **低 S 归一化（BIP62）**：ECDSA 里 `(r, s)` 与 `(r, n - s)` 都是有效签名，
///    比特币节点只接受 **s ≤ n/2** 的那一个（否则判定为非标准交易直接拒收）。
///    多数链不管这件事，BTC 必须管；
/// 2. **末尾的 sighash 标志字节**：`0x01` 表示 SIGHASH_ALL。少这一个字节，
///    节点会认为签名的哈希类型是非法的。
///
/// 这两步都在 SDK 内完成，正是「让调用方只管签哈希」的价值所在。
pub fn encode_signature(compact: &[u8]) -> Result<Vec<u8>> {
    if compact.len() != COMPACT_SIGNATURE_LEN {
        bail!(
            "BTC 签名需为 {COMPACT_SIGNATURE_LEN} 字节紧凑格式（r||s 的十六进制），实际 {} 字节；\
             若你的签名库输出 DER（0x30 开头），请先转成 r||s",
            compact.len()
        );
    }
    // 注意 `mut`：`normalize_s()` 是**就地修改**（返回 `()`），不是返回新值的函数式写法。
    let mut signature = SecpSignature::from_compact(compact).context("解析紧凑签名失败")?;
    // 把 s 换成 `min(s, n - s)`，即低 S 归一化。
    // 已经是低 S 时它什么也不做，所以无条件调用是安全的。
    signature.normalize_s();
    // `serialize_der()` 返回 `ArrayVec`（栈上定长缓冲），`.to_vec()` 转成可增长的 `Vec`。
    let mut out = signature.serialize_der().to_vec();
    // 追加 SIGHASH_ALL 标志字节。
    out.push(EcdsaSighashType::All.to_u32() as u8);
    Ok(out)
}

/// 用上下文重建交易、**逐个验签**，再拼装出可广播的已签名交易。
///
/// 领域说明：验签放在拼装**之前**是刻意的。若不验，一个错序的签名数组
/// 会拼出一笔「结构完好但签名对不上」的交易——本地一切正常，
/// 广播后才被节点拒，而返回的错误（non-mandatory-script-verify-flag）
/// 不会告诉你是哪个输入错了。先验签则能在本地精确指出第几个输入不对。
///
/// 语法说明：`signatures: &[Vec<u8>]` 是**字节切片的切片**——
/// 外层借用数组本身，内层每项各自持有已解码的签名字节。
pub fn assemble_signed(ctx: &SubmitContext, signatures: &[Vec<u8>]) -> Result<Transaction> {
    if signatures.len() != ctx.inputs.len() {
        bail!(
            "签名数量({})与输入数量({})不一致：BTC 每个输入都要单独签一次",
            signatures.len(),
            ctx.inputs.len()
        );
    }
    let public_key = parse_public_key(&ctx.public_key)?;
    // `CompressedPublicKey` 是元组结构体，`.0` 取出内部的 `secp256k1::PublicKey`。
    let secp_key: SecpPublicKey = public_key.0;

    // 重建并自检；这一步会拦下被篡改的上下文。
    let mut tx = rebuild_unsigned(ctx)?;
    // 一次性算出全部 sighash，随后结束对 `tx` 的借用，才能往里写见证。
    let hashes = sighashes(&tx, ctx)?;
    let secp = Secp256k1::new();

    for (index, raw) in signatures.iter().enumerate() {
        let der = encode_signature(raw)?;
        // 验签：用重建出的 sighash + 上下文里的公钥。任何一个对不上就地失败。
        verify_signature(&secp, &hashes[index], &der, &secp_key)?;

        let bitcoin_sig =
            bitcoin::ecdsa::Signature::from_slice(&der).with_context(|| format!("输入 {index} 的 DER 签名非法"))?;
        match parse_script_type(&ctx.inputs[index].script_type)? {
            // 见证两项：`[DER 签名 + 标志字节, 压缩公钥]`。
            // 见证**不计入 txid**，所以补签名不改变交易 ID（SegWit 修复的延展性问题）。
            ScriptKind::P2wpkh => {
                tx.input[index].witness = Witness::p2wpkh(&bitcoin_sig, &secp_key);
            }
            // scriptSig 两项：`[DER 签名 + 标志字节, 公钥]`。
            ScriptKind::P2pkh => {
                tx.input[index].script_sig = build_script_sig(&der, &public_key)?;
            }
        }
    }
    Ok(tx)
}

/// 用给定公钥验签单个输入的签名。
///
/// 领域说明：这是**端到端**的正确性证明——只比对字节无法说明签名有效，
/// 走一遍椭圆曲线验签才能证明「这个签名确实由对应私钥对这段 sighash 签出」。
pub fn verify_signature(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    sighash: &[u8; 32],
    der_with_flag: &[u8],
    public_key: &SecpPublicKey,
) -> Result<()> {
    let signature = bitcoin::ecdsa::Signature::from_slice(der_with_flag)
        .context("签名不是合法的 DER + sighash 标志格式")?;
    if signature.sighash_type != EcdsaSighashType::All {
        bail!(
            "只接受 SIGHASH_ALL 签名，收到 {:?}",
            signature.sighash_type
        );
    }
    // `Message::from_digest` 要求 32 字节；sighash 本身就是摘要，
    // 这里**不再**做一次双 SHA256（BTC 的 sighash 已经是 dSHA256 的结果）。
    let message = Message::from_digest(*sighash);
    secp.verify_ecdsa(&message, &signature.signature, public_key)
        .context("签名验证失败：签名与 sighash 或公钥不匹配")
}

/// 构造 P2PKH 的 scriptSig：先压签名、再压公钥。
///
/// 领域说明：比特币脚本是**栈式**执行的，先压入的先出栈，
/// 而 `OP_CHECKSIG` 期望栈顶是公钥、其下是签名。
/// 因此顺序必须是「签名在前，公钥在后」，写反了脚本会直接失败。
pub fn build_script_sig(der_with_flag: &[u8], public_key: &CompressedPublicKey) -> Result<ScriptBuf> {
    let mut sig_bytes = PushBytesBuf::new();
    sig_bytes
        // `extend_from_slice` 返回 `Result`：超过 520 字节会报错而非静默截断。
        .extend_from_slice(der_with_flag)
        .context("签名长度超出脚本推送上限")?;
    let mut pubkey_bytes = PushBytesBuf::new();
    pubkey_bytes
        // 直接用调用方给的**压缩**公钥（33 字节），与 P2PKH 地址的派生方式一致。
        .extend_from_slice(&public_key.to_bytes())
        .context("公钥长度超出脚本推送上限")?;
    Ok(ScriptBuf::builder()
        .push_slice(sig_bytes)
        .push_slice(pubkey_bytes)
        // `into_script()` 把建造者转成不可变的 `ScriptBuf`。
        .into_script())
}

/// 序列化已签名交易，返回 `(原始交易十六进制, txid)`。
///
/// 领域说明：txid 是**非见证部分**的双 SHA256，所以 P2WPKH 填好见证后
/// txid 不变；而 P2PKH 的签名在 scriptSig 里、参与 txid 计算，
/// 因此 P2PKH 交易签名前后 txid **会变**（这就是交易延展性问题）。
pub fn finalize(tx: &Transaction) -> (String, String) {
    (
        encode::serialize_hex(tx),
        tx.compute_txid().to_string(),
    )
}

/// 取当前数据源的推荐费率（sat/vB）。
///
/// 抽出来是为了让适配器不必知道「费率从哪儿来」——
/// 一体式与两段式路径都应当用同一个推荐值，签名结果才可能一致。
pub async fn current_fee_rate(chain: &Chain) -> f64 {
    recommended_fee_rate(chain).await
}

/// 把 satoshi 格式化为 BTC 字符串，供错误信息使用。
pub fn format_amount(sat: u64) -> String {
    format_btc(sat)
}

// `#[cfg(test)]`：整个模块只在 `cargo test` 时参与编译，正式构建会被剔除。
#[cfg(test)]
mod tests {
    use super::*;
    // 双 SHA256（比特币的哈希原语），供「手写 preimage」的独立对拍使用。
    use bitcoin::consensus::encode;
    use bitcoin::hashes::sha256d;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::Transaction;

    use crate::backend::UtxoView;
    use crate::transactions::select_coins;

    // ---- 外部真值：BIP143 官方测试向量 ----
    //
    // 来源：https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    // 「Native P2WPKH」一节。这是**独立于本工程**的公开向量，
    // 用它能同时锚定 sighash 算法、DER 编码、低 S 归一化与 SIGHASH 标志字节。

    /// 官方给出的未签名交易（2 输入：第 0 个是 P2PK，第 1 个是 P2WPKH）。
    const BIP143_UNSIGNED_TX: &str = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
    /// 第 1 个输入（P2WPKH）的锁定脚本。
    const BIP143_INPUT_SPK: &str = "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1";
    /// 第 1 个输入的金额：6 BTC。
    const BIP143_INPUT_VALUE: u64 = 600_000_000;
    /// 官方给出的 sighash（对第 1 个输入、nHashType = SIGHASH_ALL）。
    const BIP143_SIGHASH: &str =
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670";
    /// 官方给出的第 1 个输入对应私钥（裸 32 字节十六进制，非 WIF）。
    const BIP143_PRIVKEY: &str =
        "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9";
    /// 官方给出的最终签名（`DER || 0x01`）。
    const BIP143_SIGNATURE: &str = "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01";
    /// secp256k1 的曲线阶 n（大端），用于构造「高 S」签名。
    const CURVE_ORDER: &str =
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

    // ---- 本地固定测试数据 ----

    /// 一个公开可查的测试私钥（裸 32 字节十六进制，主网）。余额早已归零，不含真实资产。
    ///
    /// 由 WIF `L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy` 独立解码
    /// Base58Check 得到（去掉版本字节与校验和）。
    ///
    /// 为什么改成裸字节而不是 WIF：解析 WIF 的 `Wallet` 属于一体式签名路径，
    /// 已随「SDK 不碰私钥」的改造删除。两段式只需要一把能签出有效签名的私钥，
    /// 以及由它派生的压缩公钥。
    const TEST_SEED: &str =
        "8c112cf628362ecf4d482f68af2dbb50c8a2cb90d226215de925417aa9336a48";
    /// 创世区块 coinbase 的 txid，仅作占位引用（本地签名不需要它真实存在）。
    const TXID_A: &str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    const TXID_B: &str = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098";

    /// 测试密钥对：私钥 + 由它派生的**压缩**公钥。
    fn test_key() -> (SecretKey, CompressedPublicKey) {
        let secret = SecretKey::from_slice(&hex::decode(TEST_SEED).unwrap()).unwrap();
        let secp = Secp256k1::new();
        let public_key = SecpPublicKey::from_secret_key(&secp, &secret);
        let compressed = CompressedPublicKey::from_slice(&public_key.serialize()).unwrap();
        (secret, compressed)
    }

    /// 造一个 UTXO 视图。
    fn utxo(txid: &str, vout: u32, value: u64) -> UtxoView {
        UtxoView {
            txid: txid.to_string(),
            vout,
            value,
            confirmed: true,
            block_height: Some(1),
            block_time: Some(1_700_000_000),
        }
    }

    /// 把紧凑签名的 `s` 换成 `n - s`，得到同一签名的「高 S」孪生兄弟。
    ///
    /// 领域说明：ECDSA 里 `(r, s)` 与 `(r, n - s)` **都是有效签名**，
    /// 但比特币只接受低 S（BIP62）。这个函数用来验证 SDK 会强制归一化。
    fn negate_s(compact: &[u8]) -> [u8; COMPACT_SIGNATURE_LEN] {
        let n = hex::decode(CURVE_ORDER).unwrap();
        let mut out = [0u8; COMPACT_SIGNATURE_LEN];
        out[..32].copy_from_slice(&compact[..32]);
        // 大端 256 位减法，逐字节带借位。
        let mut borrow: i16 = 0;
        for i in (0..32).rev() {
            let a = n[i] as i16;
            let b = compact[32 + i] as i16;
            let diff = a - b - borrow;
            // 负数与 0xff 按位与，正好得到「模 256」的字节值（-1 → 255）。
            out[32 + i] = (diff & 0xff) as u8;
            borrow = if diff < 0 { 1 } else { 0 };
        }
        out
    }

    /// 「agent 侧」的签名动作：拿一段 32 字节摘要，用私钥签出 64 字节紧凑签名。
    fn agent_signatures(
        hashes: &[[u8; 32]],
        secret: &SecretKey,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Vec<Vec<u8>> {
        hashes
            .iter()
            .map(|hash| {
                let message = Message::from_digest(*hash);
                // `serialize_compact()` 产出 `r || s` 共 64 字节。
                secp.sign_ecdsa(&message, secret).serialize_compact().to_vec()
            })
            .collect()
    }

    /// 用选币结果 + 公钥造出上下文（抽出来给多个测试复用）。
    fn context_for(
        tx: &Transaction,
        public_key: &CompressedPublicKey,
        selected: &[Selected],
    ) -> SubmitContext {
        build_context(NetworkArg::Mainnet, tx, public_key, selected).unwrap()
    }

    /// 造一笔「两输入 + 收款 + 找零」的未签名交易，返回 (交易, 选币结果, 上下文)。
    fn two_input_fixture() -> (Transaction, Vec<Selected>, SubmitContext, CompressedPublicKey) {
        let (_secret, public_key) = test_key();
        let addresses = key_addresses(&public_key, Network::Bitcoin);
        let to = addresses.p2wpkh.clone();

        let selection = select_coins(
            vec![
                Selected {
                    utxo: utxo(TXID_A, 0, 100_000),
                    kind: ScriptKind::P2wpkh,
                    script: addresses.p2wpkh.script_pubkey(),
                },
                Selected {
                    utxo: utxo(TXID_B, 1, 60_000),
                    kind: ScriptKind::P2wpkh,
                    script: addresses.p2wpkh.script_pubkey(),
                },
            ],
            120_000,
            5.0,
        )
        .unwrap();

        let tx = build_unsigned_transaction(
            &selection,
            &to.script_pubkey(),
            &addresses.p2wpkh.script_pubkey(),
            120_000,
            true,
        )
        .unwrap();
        let ctx = context_for(&tx, &public_key, &selection.selected);
        (tx, selection.selected.clone(), ctx, public_key)
    }

    // ---- 与外部真值对拍 ----

    /// sighash 必须与 BIP143 官方向量逐字节一致。
    ///
    /// 这条测试锁死的是「**调用哪个库函数、传哪些参数**」——
    /// BIP143（SegWit）与传统算法的 sighash 输入完全不同，
    /// 传错函数不会报错，只会得到一个广播即失败的无效签名。
    #[test]
    fn bip143_sighash_matches_the_official_test_vector() {
        let tx: Transaction = encode::deserialize_hex(BIP143_UNSIGNED_TX).unwrap();
        let spk = ScriptBuf::from(hex::decode(BIP143_INPUT_SPK).unwrap());

        let mut cache = SighashCache::new(&tx);
        let sighash =
            sighash_for_input(&mut cache, 1, &spk, ScriptKind::P2wpkh, BIP143_INPUT_VALUE).unwrap();

        assert_eq!(hex::encode(sighash), BIP143_SIGHASH);
    }

    /// 用官方私钥签官方 sighash，最终字节必须与官方签名**完全一致**。
    ///
    /// 这一条同时验证四件事：sighash 正确（上一条已单测）、DER 编码正确、
    /// 低 S 归一化正确、末尾补的是 `0x01`（SIGHASH_ALL）。
    /// 任一处偏差都会导致字节对不上——这正是「外部真值」的价值。
    #[test]
    fn bip143_signature_matches_the_official_test_vector() {
        let tx: Transaction = encode::deserialize_hex(BIP143_UNSIGNED_TX).unwrap();
        let spk = ScriptBuf::from(hex::decode(BIP143_INPUT_SPK).unwrap());
        let mut cache = SighashCache::new(&tx);
        let sighash =
            sighash_for_input(&mut cache, 1, &spk, ScriptKind::P2wpkh, BIP143_INPUT_VALUE).unwrap();

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&hex::decode(BIP143_PRIVKEY).unwrap()).unwrap();
        let compact = secp
            .sign_ecdsa(&Message::from_digest(sighash), &secret)
            .serialize_compact();

        assert_eq!(hex::encode(encode_signature(&compact).unwrap()), BIP143_SIGNATURE);
    }

    /// 传统（P2PKH）sighash 与**手写 preimage** 对拍。
    ///
    /// 为什么不用库函数自我比对：`SighashCache::legacy_signature_hash` 就是要测的对象，
    /// 拿它自己比自己是恒真的。这里手写一遍序列化，与它算出同一个值才算数。
    #[test]
    fn legacy_sighash_matches_a_hand_written_preimage() {
        let (_secret, public_key) = test_key();
        let addresses = key_addresses(&public_key, Network::Bitcoin);
        let to = addresses.p2wpkh.clone();

        // 两个输入：第 0 个 P2PKH（要签的那个），第 1 个 P2WPKH，外加两个输出。
        let selection = select_coins(
            vec![
                Selected {
                    utxo: utxo(TXID_A, 0, 100_000),
                    kind: ScriptKind::P2pkh,
                    script: addresses.p2pkh.script_pubkey(),
                },
                Selected {
                    utxo: utxo(TXID_B, 1, 60_000),
                    kind: ScriptKind::P2wpkh,
                    script: addresses.p2wpkh.script_pubkey(),
                },
            ],
            120_000,
            5.0,
        )
        .unwrap();
        let tx = build_unsigned_transaction(
            &selection,
            &to.script_pubkey(),
            &addresses.p2wpkh.script_pubkey(),
            120_000,
            false,
        )
        .unwrap();

        let spk = addresses.p2pkh.script_pubkey();
        let mut cache = SighashCache::new(&tx);
        // 传统算法**不**吃金额参数，这里传什么都一样——传 0 是为了让「传错也不影响」
        // 这件事在测试里显式可见（若哪天改成 BIP143，这条会因金额不符而失败）。
        let from_lib = sighash_for_input(&mut cache, 0, &spk, ScriptKind::P2pkh, 0).unwrap();
        let by_hand = legacy_sighash_by_hand(&tx, 0, &spk);

        assert_eq!(hex::encode(from_lib), hex::encode(by_hand));
        // 反证：换个输入下标，哈希必须不同。
        // 少了这条，「两边都写错成同一个常量」也能通过。
        let other = legacy_sighash_by_hand(&tx, 0, &to.script_pubkey());
        assert_ne!(by_hand, other);
    }

    /// 手写传统 SIGHASH_ALL 的 preimage 并做双 SHA256。
    ///
    /// 结构（按比特币原始实现）：
    /// version ‖ 输入数 ‖ 各输入(outpoint, 仅被签那个填 scriptPubKey, sequence)
    ///        ‖ 输出数 ‖ 各输出(value, script) ‖ locktime ‖ hashtype(4 字节)
    fn legacy_sighash_by_hand(
        tx: &Transaction,
        index: usize,
        script_pubkey: &ScriptBuf,
    ) -> [u8; 32] {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&tx.version.0.to_le_bytes());
        // 输入数 / 输出数都很小，直接写成单字节 varint。
        buf.push(tx.input.len() as u8);
        for (i, input) in tx.input.iter().enumerate() {
            buf.extend_from_slice(&encode::serialize(&input.previous_output));
            // **只有被签的那个输入**替换成 scriptPubKey，其余一律空脚本。
            let script = if i == index {
                script_pubkey.as_bytes()
            } else {
                &[]
            };
            buf.push(script.len() as u8);
            buf.extend_from_slice(script);
            buf.extend_from_slice(&input.sequence.to_consensus_u32().to_le_bytes());
        }
        buf.push(tx.output.len() as u8);
        for output in &tx.output {
            buf.extend_from_slice(&output.value.to_sat().to_le_bytes());
            let script = output.script_pubkey.as_bytes();
            buf.push(script.len() as u8);
            buf.extend_from_slice(script);
        }
        buf.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());
        // SIGHASH_ALL = 1，小端 4 字节。
        buf.extend_from_slice(&1u32.to_le_bytes());
        // 比特币的哈希原语是 **SHA256(SHA256(x))**，不是单次 SHA256。
        sha256d::Hash::hash(&buf).to_byte_array()
    }

    // ---- 端到端：两段式必须复现一体式的字节 ----

    /// 重组出的每个见证都必须能被上下文里的公钥验过。
    ///
    /// 一体式路径（本地拿私钥签）已随「SDK 不碰私钥」的改造删除，所以这里不再做
    /// 「两条路径逐字节相同」的对拍，改为**直接验证产物本身**——
    /// 一次覆盖四件事：DER 编码、低 S 归一化（BIP62）、末尾的 SIGHASH_ALL 标志字节、
    /// 以及见证的两项结构。任一项出错都会让验签失败或结构对不上。
    #[test]
    fn assembled_witnesses_all_verify_against_the_context_public_key() {
        let (tx, _selected, ctx, public_key) = two_input_fixture();
        let (secret, _) = test_key();

        let secp = Secp256k1::new();
        let hashes = sighashes(&tx, &ctx).unwrap();
        let signatures = agent_signatures(&hashes, &secret, &secp);
        let assembled = assemble_signed(&ctx, &signatures).unwrap();

        let secp_key: SecpPublicKey = public_key.0;
        for (index, hash) in hashes.iter().enumerate() {
            // P2WPKH 的见证固定两项：`[DER 签名 + 标志字节, 压缩公钥]`。
            let witness = &assembled.input[index].witness;
            assert_eq!(witness.len(), 2, "第 {index} 个输入的见证应为 2 项");
            assert_eq!(
                witness[1],
                public_key.to_bytes(),
                "第 {index} 个输入见证的第二项应是压缩公钥"
            );
            assert_eq!(
                witness[0].last(),
                Some(&0x01),
                "第 {index} 个签名的末尾应是 SIGHASH_ALL 标志字节"
            );
            verify_signature(&secp, hash, &witness[0], &secp_key)
                .unwrap_or_else(|e| panic!("第 {index} 个见证验签失败: {e}"));
        }
        // P2WPKH 的见证不计入 txid，所以补签名不改变交易 ID。
        assert_eq!(assembled.compute_txid(), tx.compute_txid());
    }

    /// P2PKH 输入同样要能重组，且 scriptSig 里放的是**压缩**公钥。
    ///
    /// 这里不比对一体式路径：那条路径的 scriptSig 放的是**未压缩**公钥（65 字节），
    /// 两段式放压缩公钥（33 字节）——两者都是合法的，但字节必然不同。
    /// 所以 P2PKH 分支改为验证「签名确实能通过验签」。
    #[test]
    fn p2pkh_input_is_assembled_with_a_verifiable_script_sig() {
        let (secret, public_key) = test_key();
        let addresses = key_addresses(&public_key, Network::Bitcoin);
        let to = addresses.p2wpkh.clone();

        let selection = select_coins(
            vec![Selected {
                utxo: utxo(TXID_A, 0, 100_000),
                kind: ScriptKind::P2pkh,
                script: addresses.p2pkh.script_pubkey(),
            }],
            50_000,
            5.0,
        )
        .unwrap();
        let tx = build_unsigned_transaction(
            &selection,
            &to.script_pubkey(),
            &addresses.p2wpkh.script_pubkey(),
            50_000,
            false,
        )
        .unwrap();
        let ctx = context_for(&tx, &public_key, &selection.selected);

        let secp = Secp256k1::new();
        let hashes = sighashes(&tx, &ctx).unwrap();
        let signatures = agent_signatures(&hashes, &secret, &secp);
        let assembled = assemble_signed(&ctx, &signatures).unwrap();

        let script_sig = assembled.input[0].script_sig.as_bytes();
        // 公钥是最后压入的，所以位于末尾；且必须是 33 字节的压缩形式。
        assert!(script_sig.ends_with(&public_key.to_bytes()));
        // P2PKH 的签名在 scriptSig 里，会改变 txid——这正是延展性问题的来源。
        assert_ne!(assembled.compute_txid(), tx.compute_txid());
        // 端到端验签：用重组后的交易反推 sighash 应当验不过（因为 scriptSig 变了），
        // 所以改为直接验证「签名对构造时的 sighash 有效」。
        let der = encode_signature(&signatures[0]).unwrap();
        verify_signature(&secp, &hashes[0], &der, &public_key.0).unwrap();
    }

    // ---- 失败路径 ----

    /// 两个输入的签名**交换顺序**必须被验签拦下。
    ///
    /// 领域说明：BTC 每个输入的 sighash 都覆盖全部输入，
    /// 因此「第 0 个输入的签名」对第 1 个输入是无效的。
    /// 若不做验签，错序会拼出一笔结构完好但注定被节点拒绝的交易。
    #[test]
    fn swapping_signatures_between_inputs_is_rejected() {
        let (secret, _public_key) = test_key();
        let (tx, _selected, ctx, _public_key) = two_input_fixture();
        assert_eq!(ctx.inputs.len(), 2);

        let secp = Secp256k1::new();
        let hashes = sighashes(&tx, &ctx).unwrap();
        let mut signatures = agent_signatures(&hashes, &secret, &secp);
        signatures.swap(0, 1);

        let err = assemble_signed(&ctx, &signatures).unwrap_err();
        assert!(
            err.to_string().contains("签名验证失败"),
            "错误信息应指出是验签失败，实际: {err}"
        );
    }

    /// 上下文被篡改（改输出金额）必须在自检阶段就被拒绝。
    #[test]
    fn tampering_with_the_context_breaks_the_self_check() {
        let (secret, _public_key) = test_key();
        let (tx, _selected, mut ctx, _public_key) = two_input_fixture();

        let secp = Secp256k1::new();
        let hashes = sighashes(&tx, &ctx).unwrap();
        let signatures = agent_signatures(&hashes, &secret, &secp);

        // 把收款金额改大 1 sat：重建出的字节就与原记录对不上了。
        ctx.outputs[0].value += 1;
        let err = assemble_signed(&ctx, &signatures).unwrap_err();
        assert!(
            err.to_string().contains("上下文自检失败"),
            "篡改后的上下文必须被自检拦下，实际: {err}"
        );
    }

    /// 签名数量与输入数量不符必须报错，而不是静默只签一部分。
    #[test]
    fn signature_count_must_match_input_count() {
        let (secret, _public_key) = test_key();
        let (tx, _selected, ctx, _public_key) = two_input_fixture();
        let secp = Secp256k1::new();
        let hashes = sighashes(&tx, &ctx).unwrap();
        let signatures = agent_signatures(&hashes, &secret, &secp);

        assert!(assemble_signed(&ctx, &signatures[..1]).is_err());
        // 多给一个签名同样要拒绝——多余签名无处安放，说明调用方理解有误。
        let mut extra = signatures.clone();
        extra.push(signatures[0].clone());
        assert!(assemble_signed(&ctx, &extra).is_err());
    }

    /// 畸形签名（长度不对、乱码）必须被拒绝。
    #[test]
    fn malformed_signatures_are_rejected() {
        assert!(encode_signature(&[]).is_err());
        assert!(encode_signature(&[0u8; 63]).is_err());
        assert!(encode_signature(&[0u8; 65]).is_err());
        // r 超出曲线阶 n（0xffff…ffff > n）同样应被拒绝。
        assert!(encode_signature(&[0xffu8; 64]).is_err());
        // DER 输入应被明确拒绝并给出可读提示，而不是被当成紧凑签名误解析。
        let der = hex::decode(BIP143_SIGNATURE).unwrap();
        assert!(encode_signature(&der).is_err());
    }

    /// `encode_signature` 只做**格式**转换，不做语义校验——`r = 0` 能编出 DER，
    /// 但要靠验签才能拦下。
    ///
    /// 领域说明：`secp256k1::Signature::from_compact` 只检查 r / s 落在**域范围**内，
    /// 并不校验它们是合法的 ECDSA 输出。所以「能编码」不等于「能上链」，
    /// 这也是 [`assemble_signed`] 必须在广播前逐个验签的原因。
    #[test]
    fn encoding_does_not_validate_semantics_but_verification_does() {
        let mut zero_r = [1u8; COMPACT_SIGNATURE_LEN];
        zero_r[..32].fill(0);
        // 能编出 DER 字节。
        let der = encode_signature(&zero_r).unwrap();
        assert!(der.ends_with(&[0x01]));

        // 但验签一定失败。
        let secp = Secp256k1::new();
        let digest = hex::decode(BIP143_SIGHASH).unwrap();
        let mut sighash = [0u8; 32];
        sighash.copy_from_slice(&digest);
        let public_key = parse_public_key(
            "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357",
        )
        .unwrap();
        assert!(verify_signature(&secp, &sighash, &der, &public_key.0).is_err());
    }

    /// **高 S 签名必须被归一化**到与低 S 孪生签名完全相同的字节（BIP62）。
    ///
    /// 为什么必须做：比特币节点只接受 `s ≤ n/2` 的签名，否则判为非标准交易直接拒收。
    /// 而 agent 侧的签名库未必做这件事，所以得由 SDK 兜住。
    #[test]
    fn high_s_signature_is_normalized_to_low_s() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&hex::decode(BIP143_PRIVKEY).unwrap()).unwrap();
        let digest = hex::decode(BIP143_SIGHASH).unwrap();
        let mut digest_bytes = [0u8; 32];
        digest_bytes.copy_from_slice(&digest);

        let low = secp
            .sign_ecdsa(&Message::from_digest(digest_bytes), &secret)
            .serialize_compact();
        let high = negate_s(&low);

        // 前提检查：两个 s 确实不同（否则 negate_s 写错了，这条测试就成了摆设）。
        assert_ne!(low[32..], high[32..]);
        // 两者都必须能解析为合法签名，且归一化后产出同一份字节。
        assert_eq!(
            encode_signature(&low).unwrap(),
            encode_signature(&high).unwrap()
        );
    }

    // ---- 纯函数与序列化 ----

    /// 上下文要能经 JSON 往返而不丢字段——它会被 agent 存下来再回传。
    #[test]
    fn submit_context_survives_a_json_roundtrip() {
        let (_tx, _selected, ctx, _public_key) = two_input_fixture();
        let json = serde_json::to_string(&ctx).unwrap();
        let back: SubmitContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.network, ctx.network);
        assert_eq!(back.public_key, ctx.public_key);
        assert_eq!(back.unsigned_tx_hex, ctx.unsigned_tx_hex);
        assert_eq!(back.inputs.len(), ctx.inputs.len());
        assert_eq!(back.outputs.len(), ctx.outputs.len());
        // 往返后仍应能重建出同一笔交易。
        assert_eq!(
            encode::serialize_hex(&rebuild_unsigned(&back).unwrap()),
            ctx.unsigned_tx_hex
        );
    }

    /// 压缩公钥解析：接受 `0x` 前缀，拒绝未压缩与乱码。
    #[test]
    fn public_key_parsing_accepts_hex_and_rejects_others() {
        let (_secret, public_key) = test_key();
        let hexed = hex::encode(public_key.to_bytes());
        assert_eq!(
            parse_public_key(&hexed).unwrap().to_bytes(),
            public_key.to_bytes()
        );
        // 带 0x 前缀应等价。
        assert_eq!(
            parse_public_key(&format!("0x{hexed}")).unwrap().to_bytes(),
            public_key.to_bytes()
        );
        // 65 字节未压缩公钥：长度不符。
        //
        // 由同一把私钥直接派生未压缩形式（`0x04 ‖ X ‖ Y`，65 字节），
        // 保证这确实是一枚**合法**的未压缩公钥——拒绝它的理由纯粹是「本模块只收压缩」。
        let uncompressed = public_key.0.serialize_uncompressed();
        assert_eq!(uncompressed.len(), 65);
        assert!(parse_public_key(&hex::encode(uncompressed)).is_err());
        // 乱码。
        assert!(parse_public_key("zz").is_err());
        assert!(parse_public_key("02abcd").is_err());
    }

    /// 同一公钥派生的两类地址必须不同，且与网络相关。
    #[test]
    fn key_addresses_are_distinct_and_network_dependent() {
        let (_secret, public_key) = test_key();
        let mainnet = key_addresses(&public_key, Network::Bitcoin);
        assert!(mainnet.p2wpkh.to_string().starts_with("bc1q"));
        assert!(mainnet.p2pkh.to_string().starts_with('1'));
        assert_ne!(mainnet.p2wpkh.to_string(), mainnet.p2pkh.to_string());

        let testnet = key_addresses(&public_key, Network::Testnet);
        assert!(testnet.p2wpkh.to_string().starts_with("tb1q"));
        assert_ne!(mainnet.p2wpkh.to_string(), testnet.p2wpkh.to_string());
    }

    /// 金额不足必须报错；找零低于 dust 阈值时应并入手续费。
    #[test]
    fn coin_selection_reports_insufficient_funds_and_absorbs_dust() {
        let (_secret, public_key) = test_key();
        let script = key_addresses(&public_key, Network::Bitcoin).p2wpkh.script_pubkey();
        let one = vec![Selected {
            utxo: utxo(TXID_A, 0, 10_000),
            kind: ScriptKind::P2wpkh,
            script: script.clone(),
        }];
        // 10 000 sat 全部拿去也付不起 20 000 sat 的转账。
        assert!(select_coins(one, 20_000, 5.0).is_err());

        // 找零只剩 500 sat（< DUST_LIMIT 546）→ 并入手续费，输出只剩 1 个。
        //
        // 数字怎么来的：1 输入 2 输出的估算 vsize = ceil(10.5 + 68 + 31*2) = 141，
        // 费率 1 sat/vB → 手续费 141 sat；取转账额 99_359 时找零 = 100_000 − 99_359 − 141 = 500。
        let selection = select_coins(
            vec![Selected {
                utxo: utxo(TXID_A, 0, 100_000),
                kind: ScriptKind::P2wpkh,
                script,
            }],
            99_359,
            1.0,
        )
        .unwrap();
        assert_eq!(selection.change, 0);
        assert_eq!(selection.output_count, 1);
        // 差额全部给了矿工：141（估算手续费）+ 500（本该找零部分）= 641。
        assert_eq!(selection.fee, 641);
    }

    /// 手续费与找零必须能被**精确复现**——它们直接参与 sighash，
    /// 估错一分钱就会让签名对不上。
    ///
    /// 这里钉住的是估算公式本身：`vsize = ceil(10.5 + 68 + 31 * 2) = 141`，
    /// 费率 5 sat/vB → 手续费 705 sat。
    #[test]
    fn coin_selection_fee_and_change_are_pinned() {
        let (_secret, public_key) = test_key();
        let selection = select_coins(
            vec![Selected {
                utxo: utxo(TXID_A, 0, 100_000),
                kind: ScriptKind::P2wpkh,
                script: key_addresses(&public_key, Network::Bitcoin).p2wpkh.script_pubkey(),
            }],
            50_000,
            5.0,
        )
        .unwrap();
        assert_eq!(selection.fee, 705);
        assert_eq!(selection.change, 100_000 - 50_000 - 705);
        assert_eq!(selection.output_count, 2);
    }

    /// 上下文必须记录**构造时的网络**，供广播阶段做跨网校验。
    #[test]
    fn context_records_the_network_it_was_built_for() {
        let (_tx, selected, _ctx, public_key) = two_input_fixture();
        let addresses = key_addresses(&public_key, Network::Testnet);
        let to = addresses.p2wpkh.clone();
        let selection = select_coins(
            vec![Selected {
                utxo: utxo(TXID_A, 0, 100_000),
                kind: ScriptKind::P2wpkh,
                script: addresses.p2wpkh.script_pubkey(),
            }],
            50_000,
            5.0,
        )
        .unwrap();
        let tx = build_unsigned_transaction(
            &selection,
            &to.script_pubkey(),
            &addresses.p2wpkh.script_pubkey(),
            50_000,
            false,
        )
        .unwrap();
        let ctx = build_context(NetworkArg::Testnet, &tx, &public_key, &selection.selected).unwrap();
        assert_eq!(ctx.network, "testnet");
        // 未使用的 `selected` 来自另一条夹具，这里仅取长度做一致性确认。
        assert_eq!(ctx.inputs.len(), 1);
        assert!(!selected.is_empty());
    }

    /// 上下文必须无损承载 **locktime 与 sequence**——两者都参与 sighash，
    /// 重建时丢掉任何一个都会算出不同的哈希，签出来的东西就废了。
    ///
    /// 领域说明：所有自动夹具（走 `build_unsigned_transaction`）的 locktime 都是 0、
    /// sequence 只有两种取值，覆盖不到「任意值也要能往返」这条路，
    /// 所以这里手工造一笔非零 locktime 的交易来补上。
    #[test]
    fn context_preserves_locktime_and_sequence() {
        let (_secret, public_key) = test_key();
        let selected = vec![Selected {
            utxo: utxo(TXID_A, 0, 2_000),
            kind: ScriptKind::P2wpkh,
            script: key_addresses(&public_key, Network::Bitcoin).p2wpkh.script_pubkey(),
        }];
        let mut tx = Transaction {
            version: Version::TWO,
            // 500_000 是区块高度语义（< 500_000_000 时按高度解释）。
            lock_time: LockTime::from_consensus(500_000),
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(TXID_A).unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: key_addresses(&public_key, Network::Bitcoin).p2wpkh.script_pubkey(),
            }],
        };

        let ctx = build_context(NetworkArg::Mainnet, &tx, &public_key, &selected).unwrap();
        assert_eq!(ctx.locktime, 500_000);
        assert_eq!(
            ctx.inputs[0].sequence,
            Sequence::ENABLE_RBF_NO_LOCKTIME.to_consensus_u32()
        );

        let rebuilt = rebuild_unsigned(&ctx).unwrap();
        assert_eq!(rebuilt.lock_time, tx.lock_time);
        assert_eq!(rebuilt.input[0].sequence, tx.input[0].sequence);

        // 反证：locktime 确实参与 sighash，改一个区块就得换签名。
        tx.lock_time = LockTime::from_consensus(500_001);
        let ctx2 = build_context(NetworkArg::Mainnet, &tx, &public_key, &selected).unwrap();
        let h1 = sighashes(&rebuilt, &ctx).unwrap();
        let h2 = sighashes(&tx, &ctx2).unwrap();
        assert_ne!(h1, h2);
    }

    /// 脚本类型标签与枚举必须能互相还原。
    #[test]
    fn script_type_labels_roundtrip() {
        assert_eq!(script_type_name(ScriptKind::P2wpkh), "p2wpkh");
        assert_eq!(script_type_name(ScriptKind::P2pkh), "p2pkh");
        assert_eq!(parse_script_type("p2wpkh").unwrap(), ScriptKind::P2wpkh);
        assert_eq!(parse_script_type("p2pkh").unwrap(), ScriptKind::P2pkh);
        assert!(parse_script_type("p2tr").is_err());
    }

    /// `finalize` 产出的 txid 与直接计算的一致（P2WPKH 场景下补签名不改变 txid）。
    #[test]
    fn finalize_reports_raw_hex_and_txid() {
        let (secret, _public_key) = test_key();
        let (tx, _selected, ctx, _public_key) = two_input_fixture();
        let secp = Secp256k1::new();
        let hashes = sighashes(&tx, &ctx).unwrap();
        let signatures = agent_signatures(&hashes, &secret, &secp);
        let assembled = assemble_signed(&ctx, &signatures).unwrap();

        let (raw_hex, txid) = finalize(&assembled);
        assert_eq!(raw_hex, encode::serialize_hex(&assembled));
        assert_eq!(txid, assembled.compute_txid().to_string());
        // P2WPKH 的见证不计入 txid，所以与未签名时相同。
        assert_eq!(txid, tx.compute_txid().to_string());
    }

    /// 私钥从未进入上下文：上下文只含公钥。
    ///
    /// 这是一条**契约测试**——若哪天有人把私钥塞进上下文，这条会红。
    #[test]
    fn context_never_carries_the_private_key() {
        let (secret, public_key) = test_key();
        let (_tx, _selected, ctx, _public_key) = two_input_fixture();
        let json = serde_json::to_string(&ctx).unwrap();
        let secret_hex = hex::encode(secret.secret_bytes());
        assert!(
            !json.to_ascii_lowercase().contains(&secret_hex),
            "上下文里出现了私钥字节"
        );
        // 公钥是应当出现的（广播阶段要填进见证）。
        assert!(json.contains(&hex::encode(public_key.to_bytes())));
    }
}
