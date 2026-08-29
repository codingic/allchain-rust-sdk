//! CKB 地址（RFC 0021）与 Script（molecule 表）编解码，纯本地实现，不依赖 ckb-sdk。
//!
//! - bech32 使用原始常量（polymod == 1），不是 bech32m；
//! - full 地址 payload = `0x00` + molecule(Script)；
//! - 旧 short 地址 payload = `0x01` + code_hash_index + args，仅支持 secp256k1_blake160（0x00）；
//! - Script 是 molecule table：total_size(u32) + 3 个 offset(u32) + code_hash(32) +
//!   hash_type(1) + args(Bytes = u32 长度 + 原始字节)。

use blake2::Blake2bMac;
use blake2::digest::typenum::U20;
use blake2::digest::{FixedOutput, Update};

use allchain_core::{ErrorCode, SdkError, hexutil};

/// 系统锁 secp256k1_blake160_sighash_all 的 code_hash（主网/测试网相同）。
pub const SECP256K1_BLAKE160_CODE_HASH: [u8; 32] =
    hex_literal_32("9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8");

/// CKB blake2b 使用 personalization `ckb-default-hash`；blake160 取前 20 字节。
pub fn ckb_blake160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Blake2bMac::<U20>::new_with_salt_and_personal(&[], &[], b"ckb-default-hash")
        .expect("20 字节输出与 16 字节 personal 均合法");
    hasher.update(data);
    let digest = hasher.finalize_fixed();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    out
}

/// 解析后的锁脚本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockScript {
    pub code_hash: [u8; 32],
    /// 0=data, 1=type, 2=data1, 4=data2。
    pub hash_type: u8,
    pub args: Vec<u8>,
}

impl LockScript {
    /// 标准 secp256k1_blake160 单签锁脚本，args 为 blake160(压缩公钥)。
    pub fn sighash_blake160(args: [u8; 20]) -> Self {
        Self {
            code_hash: SECP256K1_BLAKE160_CODE_HASH,
            hash_type: 1,
            args: args.to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// molecule Script 编解码
// ---------------------------------------------------------------------------

fn encode_script(script: &LockScript) -> Vec<u8> {
    // 表头：total_size + 3 个 offset，共 16 字节。
    const HEADER: usize = 16;
    let off0 = HEADER as u32;
    let off1 = (HEADER + 32) as u32; // code_hash 固定 32 字节
    let off2 = (HEADER + 32 + 1) as u32; // 之后 1 字节 hash_type
    let total = off2 as usize + 4 + script.args.len(); // args 字段是 Bytes：4 字节长度 + 数据

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u32).to_le_bytes());
    out.extend_from_slice(&off0.to_le_bytes());
    out.extend_from_slice(&off1.to_le_bytes());
    out.extend_from_slice(&off2.to_le_bytes());
    out.extend_from_slice(&script.code_hash);
    out.push(script.hash_type);
    out.extend_from_slice(&(script.args.len() as u32).to_le_bytes());
    out.extend_from_slice(&script.args);
    debug_assert_eq!(out.len(), total);
    out
}

fn decode_script(body: &[u8]) -> Result<LockScript, SdkError> {
    let bad = || SdkError::new(ErrorCode::ParseError, "非法的 molecule Script 编码");
    if body.len() < 16 {
        return Err(bad());
    }
    let read_u32 =
        |i: usize| u32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]) as usize;
    let total = read_u32(0);
    if total != body.len() {
        return Err(bad());
    }
    let off0 = read_u32(4);
    let off1 = read_u32(8);
    let off2 = read_u32(12);
    if !(16..=off1).contains(&off0) || off1 < off0 || off2 < off1 || off2 + 4 > total {
        return Err(bad());
    }
    let code_hash: [u8; 32] = body
        .get(off0..off1)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(bad)?;
    let hash_type = *body.get(off1).ok_or_else(bad)?;
    let args_len = read_u32(off2);
    let args_start = off2 + 4;
    let args = body
        .get(args_start..args_start + args_len)
        .ok_or_else(bad)?
        .to_vec();
    Ok(LockScript {
        code_hash,
        hash_type,
        args,
    })
}

// ---------------------------------------------------------------------------
// bech32（BIP-173，CKB 使用原始 checksum 常量 1）
// ---------------------------------------------------------------------------

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1;
const GEN: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

fn polymod(values: &[u8]) -> u32 {
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = (chk & 0x01ff_ffff) << 5 ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.bytes() {
        out.push(b >> 5);
    }
    out.push(0);
    for b in hrp.bytes() {
        out.push(b & 31);
    }
    out
}

fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend(std::iter::repeat_n(0u8, 6));
    let modulus = polymod(&values) ^ BECH32_CONST;
    let mut checksum = [0u8; 6];
    for (i, slot) in checksum.iter_mut().enumerate() {
        *slot = ((modulus >> (5 * (5 - i))) & 31) as u8;
    }
    checksum
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, SdkError> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let maxv = (1u32 << to) - 1;
    let mut out = Vec::new();
    for &value in data {
        let v = u32::from(value);
        if v >> from != 0 {
            return Err(SdkError::invalid_argument("bech32 位转换时发现越界值"));
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(SdkError::new(
            ErrorCode::ParseError,
            "bech32 padding 不完整",
        ));
    }
    Ok(out)
}

fn bech32_encode(hrp: &str, payload: &[u8]) -> String {
    let mut data = convert_bits(payload, 8, 5, true).expect("8→5 位转换不会失败");
    let checksum = create_checksum(hrp, &data);
    data.extend_from_slice(&checksum);
    let mut out = format!("{hrp}1");
    for v in data {
        out.push(CHARSET[v as usize] as char);
    }
    out
}

fn bech32_decode(raw: &str) -> Result<(String, Vec<u8>), SdkError> {
    if raw.len() < 8 || raw.len() > 255 {
        return Err(SdkError::invalid_argument("地址长度不合法"));
    }
    if raw != raw.to_ascii_lowercase() && raw != raw.to_ascii_uppercase() {
        return Err(SdkError::invalid_argument("地址大小写混用"));
    }
    let lower = raw.to_ascii_lowercase();
    let pos = lower
        .rfind('1')
        .ok_or_else(|| SdkError::invalid_argument("地址缺少分隔符 1"))?;
    let hrp = lower[..pos].to_string();
    let data_part = &lower[pos + 1..];
    let mut values = Vec::with_capacity(data_part.len());
    for c in data_part.bytes() {
        let idx = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or_else(|| SdkError::invalid_argument("地址含非法字符"))?;
        values.push(idx as u8);
    }
    if values.len() < 6 {
        return Err(SdkError::invalid_argument("地址校验和缺失"));
    }
    let mut expanded = hrp_expand(&hrp);
    expanded.extend_from_slice(&values);
    if polymod(&expanded) != BECH32_CONST {
        return Err(SdkError::invalid_argument("地址校验和错误"));
    }
    let payload = convert_bits(&values[..values.len() - 6], 5, 8, false)?;
    Ok((hrp, payload))
}

// ---------------------------------------------------------------------------
// 对外地址编解码
// ---------------------------------------------------------------------------

/// 把锁脚本编码为 CKB 地址；`is_mainnet` 决定 hrp 是 ckb 还是 ckt。
pub fn encode_address(script: &LockScript, is_mainnet: bool) -> String {
    let mut payload = Vec::with_capacity(1 + 73);
    payload.push(0x00); // full address format
    payload.extend(encode_script(script));
    bech32_encode(if is_mainnet { "ckb" } else { "ckt" }, &payload)
}

/// 旧 short 格式的 secp256k1_blake160 地址（payload = 0x01 0x00 + 20 字节 args）。
///
/// 该格式已被官方标记为 deprecated，但历史地址仍广泛存在，因此保留编码能力。
pub fn encode_short_sighash_address(args: &[u8], is_mainnet: bool) -> Result<String, SdkError> {
    if args.len() != 20 {
        return Err(SdkError::invalid_argument(format!(
            "short 单签地址的 args 必须是 20 字节 blake160，实际 {} 字节",
            args.len()
        )));
    }
    let mut payload = Vec::with_capacity(22);
    payload.push(0x01); // short format
    payload.push(0x00); // code_hash_index = secp256k1_blake160
    payload.extend_from_slice(args);
    Ok(bech32_encode(
        if is_mainnet { "ckb" } else { "ckt" },
        &payload,
    ))
}

/// 解析 CKB 地址，返回锁脚本与是否主网。
pub fn decode_address(raw: &str) -> Result<(LockScript, bool), SdkError> {
    let (hrp, payload) = bech32_decode(raw.trim())?;
    let is_mainnet = match hrp.as_str() {
        "ckb" => true,
        "ckt" => false,
        other => {
            return Err(SdkError::invalid_argument(format!(
                "非法 CKB 地址前缀: {other}（应为 ckb / ckt）"
            )));
        }
    };
    let format = *payload
        .first()
        .ok_or_else(|| SdkError::invalid_argument("空地址 payload"))?;
    match format {
        // full format
        0x00 => Ok((decode_script(&payload[1..])?, is_mainnet)),
        // 旧 short format：0x01 + code_hash_index + args，仅支持 secp256k1_blake160（index 0x00）。
        0x01 => {
            let body = &payload[1..];
            let index = *body
                .first()
                .ok_or_else(|| SdkError::invalid_argument("短地址缺少 code_hash_index"))?;
            if index != 0x00 {
                return Err(SdkError::unsupported(format!(
                    "短地址 code_hash_index={index:#04x} 已废弃，请使用 full 格式地址"
                )));
            }
            let args = body
                .get(1..)
                .ok_or_else(|| SdkError::invalid_argument("短地址缺少 args"))?;
            Ok((
                LockScript {
                    code_hash: SECP256K1_BLAKE160_CODE_HASH,
                    hash_type: 1,
                    args: args.to_vec(),
                },
                is_mainnet,
            ))
        }
        other => Err(SdkError::invalid_argument(format!(
            "未知 CKB 地址格式类型: {other:#04x}"
        ))),
    }
}

/// 压缩 secp256k1 公钥（33 字节）→ 标准单签地址。
pub fn address_from_compressed_pubkey(
    pubkey_hex: &str,
    is_mainnet: bool,
) -> Result<String, SdkError> {
    let bytes = hexutil::decode_hex(pubkey_hex)?;
    if bytes.len() != 33 {
        return Err(SdkError::invalid_argument(format!(
            "CKB 单签公钥需为 33 字节压缩 secp256k1 公钥，实际 {} 字节",
            bytes.len()
        )));
    }
    let mut args = [0u8; 20];
    args.copy_from_slice(&ckb_blake160(&bytes));
    Ok(encode_address(
        &LockScript::sighash_blake160(args),
        is_mainnet,
    ))
}

/// 编译期把 64 位十六进制常量转为 [u8;32]。
const fn hex_literal_32(hex: &str) -> [u8; 32] {
    let bytes = hex.as_bytes();
    assert!(bytes.len() == 64, "code_hash 必须是 32 字节十六进制");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = hex_nibble(bytes[i * 2]);
        let lo = hex_nibble(bytes[i * 2 + 1]);
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    out
}

const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("非法十六进制字符"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_known_short_address_vector() {
        // CKB 官方文档经典 short 地址向量。
        let args = hexutil::decode_hex("b39bbc0b3673c7d36450bc14cfcdad2d559c6c64").unwrap();
        assert_eq!(
            encode_short_sighash_address(&args, true).unwrap(),
            "ckb1qyqt8xaupvm8837nv3gtc9x0ekkj64vud3jqfwyw5v"
        );
        assert!(
            encode_short_sighash_address(&args, false)
                .unwrap()
                .starts_with("ckt1")
        );
    }

    #[test]
    fn encodes_and_decodes_full_address_roundtrip() {
        let mut args = [0u8; 20];
        args.copy_from_slice(
            &hexutil::decode_hex("36c329ed630d6ce750712a477543672adab57f4c").unwrap(),
        );
        let script = LockScript::sighash_blake160(args);
        let addr = encode_address(&script, true);
        assert!(
            addr.starts_with("ckb1qp"),
            "full 地址应以 ckb1qp 开头，实际 {addr}"
        ); // full 格式首字节 0x00 + total_size 高比特
        let (decoded, mainnet) = decode_address(&addr).unwrap();
        assert!(mainnet);
        assert_eq!(decoded, script);
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut s = "ckb1qyqt8xaupvm8837nv3gtc9x0ekkj64vud3jqfwyw5v".to_string();
        s.replace_range(7..8, "q"); // 改动数据部分一个字符（t→q）
        assert!(decode_address(&s).is_err());
    }

    #[test]
    fn blake160_is_stable() {
        let a = ckb_blake160(b"hello");
        let b = ckb_blake160(b"hello");
        assert_eq!(a, b);
        assert_ne!(a, ckb_blake160(b"world"));
    }
}
