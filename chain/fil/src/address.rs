//! Filecoin 地址编解码（仅实现协议 1：secp256k1 的 f1/t1 地址），纯本地实现。
//!
//! 流程（Filecoin Address Protocol）：
//! 1. payload = blake2b-256(65 字节未压缩 secp256k1 公钥) 的前 20 字节；
//! 2. checksum = blake2b-256(protocol_byte || payload) 的前 4 字节；
//! 3. 小写无填充 RFC4648 base32 编码 `protocol_byte || payload || checksum`；
//! 4. 拼上网络前缀（主网 f / 测试网 t）与协议号 1。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

use allchain_core::{ErrorCode, SdkError, hexutil};

const B32_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

/// 计算指定输出长度的 blake2b（Filecoin 直接用可变长度输出，**不是** 256 位截断）。
fn blake2b_var(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Blake2bVar::new(out_len).expect("输出长度 1..=64 合法");
    hasher.update(data);
    let mut out = vec![0u8; out_len];
    hasher
        .finalize_variable(&mut out)
        .expect("输出缓冲长度匹配");
    out
}

/// f1 地址 payload：blake2b-160（20 字节）。
fn f1_payload(pubkey: &[u8]) -> Vec<u8> {
    blake2b_var(pubkey, 20)
}

/// checksum：blake2b-32（4 字节），输入为 protocol_byte || payload。
fn f1_checksum(payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(1 + payload.len());
    input.push(0x01);
    input.extend_from_slice(payload);
    blake2b_var(&input, 4)
}

/// 标准 RFC4648 base32 编码（小写、无填充，MSB 优先）。
fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().saturating_mul(8).div_ceil(5));
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &byte in data {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32_ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32_ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// 标准 RFC4648 base32 解码（大小写不敏感、允许无填充）。
fn base32_decode(raw: &str) -> Result<Vec<u8>, SdkError> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(raw.len() * 5 / 8);
    for c in raw.chars() {
        let value = B32_ALPHABET
            .iter()
            .position(|&a| a == c.to_ascii_lowercase() as u8)
            .ok_or_else(|| SdkError::invalid_argument(format!("非法 base32 字符: {c}")))?;
        acc = (acc << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

/// 由 65 字节未压缩 secp256k1 公钥派生 f1/t1 地址。
pub fn f1_from_pubkey(pubkey_hex: &str, is_mainnet: bool) -> Result<String, SdkError> {
    let bytes = hexutil::decode_hex(pubkey_hex)?;
    if bytes.len() != 65 {
        return Err(SdkError::invalid_argument(format!(
            "FIL f1 地址需要 65 字节未压缩 secp256k1 公钥，实际 {} 字节",
            bytes.len()
        )));
    }
    let payload = f1_payload(&bytes);
    encode_f1(&payload, is_mainnet)
}

/// 由 20 字节 payload 组装 f1/t1 地址。
///
/// 注意：协议号以 ASCII 数字 `1` 直接拼接，**不参与** base32 编码；
/// base32 只承载 `payload(20) + checksum(4)`。
fn encode_f1(payload: &[u8], is_mainnet: bool) -> Result<String, SdkError> {
    if payload.len() != 20 {
        return Err(SdkError::invalid_argument("f1 payload 必须为 20 字节"));
    }
    let checksum = f1_checksum(payload);

    let mut raw = Vec::with_capacity(24);
    raw.extend_from_slice(payload);
    raw.extend_from_slice(&checksum);
    let prefix = if is_mainnet { "f" } else { "t" };
    Ok(format!("{prefix}1{}", base32_encode(&raw)))
}

/// 解析并校验任意 Filecoin 地址，返回（协议号, payload, 是否主网）。
///
/// - f0/t0 为 ID 地址，payload 以十进制字符串原样返回；
/// - f1/t1 校验 blake2b checksum；
/// - f2/t2（Actor）、f3/t3（BLS）、f4/t4（委托）只做格式校验不做深度解析。
pub fn inspect(raw: &str) -> Result<(u8, Vec<u8>, bool), SdkError> {
    let t = raw.trim();
    let mut chars = t.chars();
    let network_ch = chars
        .next()
        .ok_or_else(|| SdkError::invalid_argument("空地址"))?;
    let is_mainnet = match network_ch {
        'f' => true,
        't' => false,
        _ => {
            return Err(SdkError::invalid_argument(format!(
                "FIL 地址必须以 f/t 开头: {t}"
            )));
        }
    };
    let protocol_ch = chars
        .next()
        .ok_or_else(|| SdkError::invalid_argument("地址缺少协议号"))?;
    let protocol = protocol_ch
        .to_digit(10)
        .ok_or_else(|| SdkError::invalid_argument(format!("非法协议号: {protocol_ch}")))?
        as u8;
    let body = &t[2..];
    if body.is_empty() {
        return Err(SdkError::invalid_argument("地址体为空"));
    }
    match protocol {
        0 => {
            if !body.bytes().all(|b| b.is_ascii_digit()) {
                return Err(SdkError::invalid_argument("f0 ID 地址必须为纯数字"));
            }
            Ok((0, body.as_bytes().to_vec(), is_mainnet))
        }
        1 => {
            let decoded = base32_decode(body)?;
            if decoded.len() != 24 {
                return Err(SdkError::invalid_argument(format!(
                    "f1 地址解码后应为 24 字节（payload20+checksum4），实际 {} 字节",
                    decoded.len()
                )));
            }
            let payload = decoded[0..20].to_vec();
            let checksum = &decoded[20..24];
            if f1_checksum(&payload).as_slice() != checksum {
                return Err(SdkError::new(
                    ErrorCode::InvalidArgument,
                    "f1 地址校验和错误",
                ));
            }
            Ok((1, payload, is_mainnet))
        }
        2..=4 => {
            // 仅做字符集粗校验，保证不会把明显垃圾发给节点。
            if body.bytes().any(|b| !b.is_ascii_alphanumeric()) {
                return Err(SdkError::invalid_argument(format!(
                    "f{protocol} 地址含非法字符"
                )));
            }
            Ok((protocol, body.as_bytes().to_vec(), is_mainnet))
        }
        other => Err(SdkError::invalid_argument(format!(
            "未知地址协议号: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_real_f1_address() {
        // 主网真实 f1 地址，验证 base32 + checksum 实现。
        let addr = "f12xpw7zzjiltyzyjzeolqe535ahpbaiivheh3lpq";
        let (protocol, payload, mainnet) = inspect(addr).unwrap();
        assert_eq!(protocol, 1);
        assert!(mainnet);
        assert_eq!(payload.len(), 20);
        // 重新编码应得到同一地址。
        assert_eq!(encode_f1(&payload, true).unwrap(), addr);
    }

    #[test]
    fn rejects_bad_f1_checksum() {
        let mut s = String::from("f12xpw7zzjiltyzyjzeolqe535ahpbaiivheh3lpq");
        s.replace_range(4..5, "a");
        assert!(inspect(&s).is_err());
    }

    #[test]
    fn accepts_id_address() {
        let (protocol, id, mainnet) = inspect("f02345").unwrap();
        assert_eq!(protocol, 0);
        assert!(mainnet);
        assert_eq!(String::from_utf8(id).unwrap(), "2345");
        assert!(inspect("t01").is_ok());
    }

    #[test]
    fn rejects_wrong_pubkey_length() {
        assert!(f1_from_pubkey(&"ab".repeat(33), true).is_err());
    }
}
