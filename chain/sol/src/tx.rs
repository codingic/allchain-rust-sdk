//! 密钥管理与转账交易构造、签名、广播。

use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_system_interface::instruction::transfer;
use solana_transaction::Transaction;

/// 生成新的 ed25519 密钥对。
pub fn keygen() -> Keypair {
    Keypair::new()
}

/// 以 Solana CLI 兼容格式导出：JSON 数组形式的 64 字节。
pub fn keypair_to_json(keypair: &Keypair) -> String {
    serde_json::to_string(&keypair.to_bytes().to_vec()).expect("序列化密钥字节数组")
}

/// 密钥字节长度（种子 32 + 公钥 32），与 `Keypair::to_bytes` 一致。
pub const KEYPAIR_LENGTH: usize = 64;

/// 从多种输入解析私钥：
/// - JSON 数组（`[12,34,...]`，Solana CLI 的 keypair 文件格式）
/// - base58 编码的 64 字节
pub fn parse_keypair(input: &str) -> Result<Keypair> {
    let raw = input.trim();
    if raw.starts_with('[') {
        let bytes: Vec<u8> = serde_json::from_str(raw).context("解析 JSON 数组形式的私钥失败")?;
        return keypair_from_bytes(&bytes);
    }
    let bytes = bs58_decode(raw).context("解析 base58 私钥失败")?;
    keypair_from_bytes(&bytes)
}

/// 从文件读取私钥（Solana CLI 的 `~/.config/solana/id.json` 格式）。
pub fn load_keypair_file(path: &Path) -> Result<Keypair> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("读取密钥文件失败: {}", path.display()))?;
    parse_keypair(&content)
}

/// 由 64 字节还原密钥。solana-keypair 3.1 只暴露 base58 构造，因此先编码再转换。
fn keypair_from_bytes(bytes: &[u8]) -> Result<Keypair> {
    if bytes.len() != KEYPAIR_LENGTH {
        bail!(
            "私钥长度应为 {} 字节，实际 {} 字节",
            KEYPAIR_LENGTH,
            bytes.len()
        );
    }
    Ok(Keypair::from_base58_string(&bs58_encode(bytes)))
}

/// 一笔本地构造并签名、尚未广播的转账。
pub struct BuiltTx {
    pub tx: Transaction,
    pub signature: solana_signature::Signature,
    pub from: Pubkey,
    pub to: Pubkey,
    pub lamports: u64,
    pub recent_blockhash: String,
}

/// 构造并签名 SystemProgram.transfer（不打印不广播）。
///
/// 私钥只参与本地签名；返回的交易可交给调用方决定广播或丢弃（dry-run）。
pub fn build_signed_transfer(
    client: &RpcClient,
    keypair: &Keypair,
    to: &Pubkey,
    lamports: u64,
) -> Result<BuiltTx> {
    let from = keypair.pubkey();
    let instruction = transfer(&from, to, lamports);
    let blockhash = client
        .get_latest_blockhash()
        .context("获取最新 blockhash 失败")?;

    let tx = Transaction::new_signed_with_payer(&[instruction], Some(&from), &[keypair], blockhash);

    let signature = tx.signatures.first().copied().unwrap_or_default();
    Ok(BuiltTx {
        tx,
        signature,
        from,
        to: *to,
        lamports,
        recent_blockhash: blockhash.to_string(),
    })
}

/// 转账：构造 SystemProgram.transfer 指令 -> 用最新 blockhash 签名 -> 广播并等待确认。
///
/// `dry_run` 为 true 时只签名并打印，不广播。
pub fn send_tx(
    client: &RpcClient,
    keypair: &Keypair,
    to: &Pubkey,
    lamports: u64,
    dry_run: bool,
) -> Result<solana_signature::Signature> {
    let built = build_signed_transfer(client, keypair, to, lamports)?;

    println!("from             : {}", built.from);
    println!("to               : {}", built.to);
    println!("lamports         : {}", built.lamports);
    println!("recent_blockhash : {}", built.recent_blockhash);
    println!("signature        : {}", built.signature);

    if dry_run {
        println!("# dry-run 模式：未广播");
        return Ok(built.signature);
    }

    let confirmed = client
        .send_and_confirm_transaction(&built.tx)
        .context("广播交易失败（账户可能不存在或余额不足）")?;
    println!("confirmed        : {confirmed}");
    Ok(confirmed)
}

/// 解析地址字符串。
pub fn parse_pubkey(raw: &str) -> Result<Pubkey> {
    Pubkey::from_str(raw.trim()).with_context(|| format!("非法地址: {raw}"))
}

/// 极简 base58 解码（仅用于解析 base58 私钥，避免额外依赖）。
pub fn bs58_decode(input: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut out: Vec<u8> = Vec::new();
    for ch in input.chars() {
        if ch == '1' && out.is_empty() {
            // 前导 1 表示 0 字节
            continue;
        }
        let value = ALPHABET
            .iter()
            .position(|&c| c == (ch as u8))
            .ok_or_else(|| anyhow::anyhow!("base58 中出现非法字符: {ch}"))?;
        let mut carry = value as u32;
        for byte in out.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // 补齐前导零字节
    let leading = input.chars().take_while(|&c| c == '1').count();
    let mut result = vec![0u8; leading];
    result.extend(out);
    Ok(result)
}

/// base58 编码（用于由字节还原 Keypair，也用于测试中的往返验证）。
pub fn bs58_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::new();
    for &byte in bytes {
        let mut carry = byte as u32;
        for d in digits.iter_mut().rev() {
            carry += (*d as u32) * 256;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.insert(0, (carry % 58) as u8);
            carry /= 58;
        }
    }
    let leading = bytes.iter().take_while(|&&b| b == 0).count();
    let mut out = "1".repeat(leading);
    for d in digits {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_json_round_trip() {
        let keypair = keygen();
        let json = keypair_to_json(&keypair);
        let restored = parse_keypair(&json).unwrap();
        assert_eq!(restored.pubkey(), keypair.pubkey());
    }

    #[test]
    fn keypair_base58_round_trip() {
        let keypair = keygen();
        let b58 = bs58_encode(&keypair.to_bytes());
        let restored = parse_keypair(&b58).unwrap();
        assert_eq!(restored.pubkey(), keypair.pubkey());
    }

    #[test]
    fn rejects_invalid_keypair() {
        assert!(parse_keypair("not-a-key").is_err());
        assert!(parse_keypair("[1,2,3]").is_err(), "长度不足应报错");
    }

    #[test]
    fn parses_known_addresses() {
        // 系统程序地址是 32 个零字节
        let system = parse_pubkey("11111111111111111111111111111111").unwrap();
        assert_eq!(system, Pubkey::default());
    }

    #[test]
    fn keypair_length_is_validated() {
        let keypair = keygen();
        let full = keypair.to_bytes();
        assert!(keypair_from_bytes(&full).is_ok(), "完整 64 字节应可还原");
        assert!(
            keypair_from_bytes(&full[..32]).is_err(),
            "截断到 32 字节应报错"
        );
    }

    #[test]
    fn base58_round_trip() {
        let original = b"hello solana rpc";
        let encoded = bs58_encode(original);
        assert_eq!(bs58_decode(&encoded).unwrap(), original.to_vec());
    }
}
