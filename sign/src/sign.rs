//! 各链「签名 + 组装完整可广播交易」实现。
//!
//! `signtx` 的语义：调用方传入**已构造好的未签名交易**（各链特定序列化，见每函数文档），
//! 本模块用内存里 `fromaddress` 对应的种子重建签名器，对交易签名并把签名装配回交易，
//! 返回 `{signature, signed_tx}`。`signed_tx` 是该链可直接广播的编码（hex 或 base64）。
//!
//! 各链 `txdatahex` 约定（调用方负责构造未签名交易）：
//! - eth ：RLP 编码的未签名交易（typed / legacy 均可），对应 MetaMask 离线签名输入。
//! - sol ：base64 / hex 的 `solana_transaction::Transaction`（legacy，signatures[0] 为占位空签名）。
//! - near：hex 的 Borsh 编码 `near_primitives::transaction::Transaction`（未签名）。
//! - apt ：hex 的 BCS 编码 `aptos_sdk::transaction::types::RawTransaction`。
//! - sui ：hex 的 BCS 编码 `sui_sdk_types::Transaction`（未签名）。
//! - ton ：hex 的待签消息字节（通常是 external message body 的哈希）；通用签名器只出 ed25519 签名，
//!         完整 external message 组装需钱包 code + state-init，超出通用范围。

use crate::store::StoredKey;

/// 一次签名 + 组装的结果。
pub struct SignedResult {
    /// 原始签名（统一 `0x` + hex）。
    pub signature: String,
    /// 装配好的可广播交易；TON 为 `None`（仅签名，见模块文档）。
    pub signed_tx: Option<String>,
    /// `signed_tx` 的编码：`"hex"` 或 `"base64"`。
    pub encoding: String,
    /// 附加说明（如 TON 的组装限制）。
    pub note: Option<String>,
}

/// 入口：按链分派到具体实现。ETH 的合金签名器是异步的，故整体 `async`。
pub async fn sign(chain: &str, txdata: &[u8], key: &StoredKey) -> anyhow::Result<SignedResult> {
    match chain {
        "eth" => sign_eth(txdata, key).await,
        "sol" => sign_sol(txdata, key),
        "near" => sign_near(txdata, key),
        "apt" => sign_apt(txdata, key),
        "sui" => sign_sui(txdata, key),
        "ton" => sign_ton(txdata, key),
        other => Err(anyhow::anyhow!("不支持的链: {other}（可选 eth / sol / near / apt / sui / ton）")),
    }
}

/// ETH：用 k256 重建签名器，对未签名交易做 EIP-155 可恢复签名并 RLP 重组。
async fn sign_eth(txdata: &[u8], key: &StoredKey) -> anyhow::Result<SignedResult> {
    use alloy::consensus::TypedTransaction;
    use alloy::network::TxSigner;
    use alloy::signers::local::PrivateKeySigner;
    use k256::ecdsa::SigningKey;

    let sk = SigningKey::from_slice(&key.seed)
        .map_err(|e| anyhow::anyhow!("ETH 种子非法: {e}"))?;
    let signer = PrivateKeySigner::from_signing_key(sk);

    // 把 RLP 未签名交易解码成合金的 TypedTransaction（typed / legacy 都能解）。
    let mut buf = txdata;
    let mut typed = TypedTransaction::decode_unsigned(&mut buf)
        .map_err(|e| anyhow::anyhow!("ETH 交易解码失败（需 RLP 未签名交易）: {e}"))?;

    // 合金签名器负责算哈希、EIP-155 v、产出可恢复签名。
    let signature = signer
        .sign_transaction(&mut typed)
        .await
        .map_err(|e| anyhow::anyhow!("ETH 签名失败: {e}"))?;

    // 把签名装配回信封，RLP 编码为可广播字节。
    let envelope = typed.into_envelope(signature);
    let sig_bytes = signature.as_bytes().to_vec();
    let tx_bytes = alloy::rlp::encode(&envelope);

    Ok(SignedResult {
        signature: format!("0x{}", hex::encode(sig_bytes)),
        signed_tx: Some(format!("0x{}", hex::encode(tx_bytes))),
        encoding: "hex".to_string(),
        note: None,
    })
}

/// SOL：用种子重建 Keypair，对 message 签名并填回 signatures[0]，bincode 重组为 base64。
fn sign_sol(txdata: &[u8], key: &StoredKey) -> anyhow::Result<SignedResult> {
    use base64::Engine;
    use solana_keypair::keypair_from_seed;
    use solana_signer::Signer;
    use solana_transaction::Transaction;

    // 由 32 字节种子直接重建 Keypair（与生成时一致：seed 即 ed25519 种子）。
    let kp = keypair_from_seed(&key.seed)
        .map_err(|e| anyhow::anyhow!("SOL Keypair 重建失败: {e}"))?;

    let mut tx: Transaction = bincode::deserialize(txdata)
        .map_err(|e| anyhow::anyhow!("SOL 交易解码失败（需 bincode Transaction）: {e}"))?;

    if tx.signatures.is_empty() {
        return Err(anyhow::anyhow!("SOL 交易缺少签名槽（signatures[0] 应为占位签名）"));
    }
    // Solana 对 message 字节签名（无额外前缀）。
    let msg_bytes = bincode::serialize(&tx.message)
        .map_err(|e| anyhow::anyhow!("SOL message 序列化失败: {e}"))?;
    let sig = kp.sign_message(&msg_bytes);
    tx.signatures[0] = sig;

    let out = bincode::serialize(&tx)
        .map_err(|e| anyhow::anyhow!("SOL 交易重组失败: {e}"))?;

    Ok(SignedResult {
        signature: format!("0x{}", hex::encode(sig.as_ref())),
        signed_tx: Some(base64::engine::general_purpose::STANDARD.encode(&out)),
        encoding: "base64".to_string(),
        note: None,
    })
}

/// NEAR：用种子重建 SecretKey，对 Transaction 的 Borsh 序列化字节签名，Borsh 组装 SignedTransaction（hex）。
fn sign_near(txdata: &[u8], key: &StoredKey) -> anyhow::Result<SignedResult> {
    use borsh::BorshDeserialize;
    use ed25519_dalek::SigningKey;
    use near_crypto::{ED25519SecretKey, SecretKey, Signature};
    use near_primitives::transaction::{SignedTransaction, Transaction};

    // NEAR SecretKey 内部是 64 字节 keypair（种子 32 + 公钥 32），由种子重建。
    let sk_dalek = SigningKey::from_bytes(&key.seed);
    let kp_bytes = sk_dalek.to_keypair_bytes();
    let secret = SecretKey::ED25519(ED25519SecretKey(kp_bytes));

    let tx: Transaction = BorshDeserialize::try_from_slice(txdata)
        .map_err(|e| anyhow::anyhow!("NEAR 交易解码失败（需 Borsh Transaction）: {e}"))?;

    // NEAR 对交易的 Borsh 序列化字节签名（即 signable bytes）。
    let signable = borsh::to_vec(&tx)
        .map_err(|e| anyhow::anyhow!("NEAR 交易序列化失败: {e}"))?;
    let signature: Signature = secret.sign(&signable);
    let signed = SignedTransaction::new(signature.clone(), tx);
    let out = borsh::to_vec(&signed)
        .map_err(|e| anyhow::anyhow!("NEAR 交易重组失败: {e}"))?;

    // 取原始 ed25519 签名字节（64 字节）作为响应签名。
    let sig_bytes = match &signature {
        Signature::ED25519(s) => s.to_bytes().to_vec(),
        _ => borsh::to_vec(&signature).unwrap_or_default(),
    };

    Ok(SignedResult {
        signature: format!("0x{}", hex::encode(sig_bytes)),
        signed_tx: Some(format!("0x{}", hex::encode(out))),
        encoding: "hex".to_string(),
        note: None,
    })
}

/// APT：用种子重建 Ed25519PrivateKey，对 RawTransaction 签名，BCS 组装 SignedTransaction（hex）。
fn sign_apt(txdata: &[u8], key: &StoredKey) -> anyhow::Result<SignedResult> {
    use aptos_sdk::crypto::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
    use aptos_sdk::transaction::authenticator::TransactionAuthenticator;
    use aptos_sdk::transaction::types::{RawTransaction, SignedTransaction};

    let sk = Ed25519PrivateKey::from_bytes(&key.seed)
        .map_err(|e| anyhow::anyhow!("APT 私钥重建失败: {e}"))?;
    let raw: RawTransaction = bcs::from_bytes(txdata)
        .map_err(|e| anyhow::anyhow!("APT 交易解码失败（需 BCS RawTransaction）: {e}"))?;

    let raw_bytes = bcs::to_bytes(&raw)
        .map_err(|e| anyhow::anyhow!("APT RawTransaction 序列化失败: {e}"))?;
    // aptos-crypto 的 `sign` 直接返回签名（非 Result）。
    let signature: Ed25519Signature = sk.sign(&raw_bytes);
    let public_key: Ed25519PublicKey = sk.public_key();

    // SignedTransaction 由 RawTransaction + TransactionAuthenticator 组成；
    // authenticator 的 ed25519 构造接收 (公钥字节, 签名字节)。
    let authenticator = TransactionAuthenticator::ed25519(
        public_key.to_bytes().to_vec(),
        signature.to_bytes().to_vec(),
    );
    let signed = SignedTransaction::new(raw, authenticator);
    let out = bcs::to_bytes(&signed)
        .map_err(|e| anyhow::anyhow!("APT 交易重组失败: {e}"))?;

    Ok(SignedResult {
        signature: format!("0x{}", hex::encode(signature.to_bytes())),
        signed_tx: Some(format!("0x{}", hex::encode(out))),
        encoding: "hex".to_string(),
        note: None,
    })
}

/// SUI：用种子重建 ed25519 签名器，按官方约定（intent 前缀 ‖ BCS(Transaction)）签名，
/// 封装为 UserSignature，BCS 组装 SignedTransaction（base64）。
fn sign_sui(txdata: &[u8], key: &StoredKey) -> anyhow::Result<SignedResult> {
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use sui_sdk_types::{
        Intent, IntentAppId, IntentScope, IntentVersion, SignatureScheme, SignedTransaction,
        Transaction, UserSignature,
    };

    let sk = SigningKey::from_bytes(&key.seed);
    let vk = VerifyingKey::from(&sk);

    let raw: Transaction = bcs::from_bytes(txdata)
        .map_err(|e| anyhow::anyhow!("SUI 交易解码失败（需 BCS Transaction）: {e}"))?;
    let raw_bytes = bcs::to_bytes(&raw)
        .map_err(|e| anyhow::anyhow!("SUI Transaction 序列化失败: {e}"))?;

    // Sui 签名域 = intent(3 字节) ‖ 交易 BCS 字节。
    let intent = Intent::new(IntentScope::TransactionData, IntentVersion::V0, IntentAppId::Sui)
        .to_bytes()
        .to_vec();
    let mut msg = intent;
    msg.extend_from_slice(&raw_bytes);

    let sig = sk.sign(&msg);
    let sig_bytes = sig.to_bytes();
    let pub_bytes = vk.to_bytes();

    // UserSignature = flag(0x00) ‖ sig(64) ‖ pubkey(32)。
    let mut full = vec![SignatureScheme::Ed25519 as u8];
    full.extend_from_slice(&sig_bytes);
    full.extend_from_slice(&pub_bytes);
    let user_sig = UserSignature::from_bytes(&full)
        .map_err(|e| anyhow::anyhow!("SUI UserSignature 封装失败: {e}"))?;

    // `SignedTransaction` 字段公开，直接构造（transaction + signatures）。
    let signed = SignedTransaction {
        transaction: raw,
        signatures: vec![user_sig],
    };
    let out = bcs::to_bytes(&signed)
        .map_err(|e| anyhow::anyhow!("SUI 交易重组失败: {e}"))?;

    Ok(SignedResult {
        signature: format!("0x{}", hex::encode(sig_bytes)),
        signed_tx: Some(base64::engine::general_purpose::STANDARD.encode(&out)),
        encoding: "base64".to_string(),
        note: None,
    })
}

/// TON：通用签名器只做 ed25519 签名，返回签名；完整 external message 组装需钱包 code/state-init。
fn sign_ton(txdata: &[u8], key: &StoredKey) -> anyhow::Result<SignedResult> {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(&key.seed);
    let sig = sk.sign(txdata);
    let sig_bytes = sig.to_bytes();
    Ok(SignedResult {
        signature: format!("0x{}", hex::encode(sig_bytes)),
        signed_tx: None,
        encoding: "hex".to_string(),
        note: Some(
            "TON 仅返回 ed25519 签名；完整 external message 组装需钱包 code + state-init，通用签名器不负责"
                .to_string(),
        ),
    })
}
