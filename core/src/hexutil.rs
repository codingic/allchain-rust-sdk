//! 十六进制编解码工具，供各链适配器解析调用方传入的公钥 / 哈希。
//!
//! 放在 core 里是为了让四链对「用户输入的 hex」有一致的行为与一致的报错文案：
//! - 允许 `0x` / `0X` 前缀；
//! - 大小写不敏感；
//! - 输出统一为**小写、无前缀**。

use crate::SdkError;

/// 解码十六进制字符串。
///
/// 允许 `0x` / `0X` 前缀，大小写不敏感；奇数长度或含非法字符时返回
/// `INVALID_ARGUMENT`。
pub fn decode_hex(raw: &str) -> Result<Vec<u8>, SdkError> {
    let trimmed = raw.trim();
    let body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    hex::decode(body).map_err(|_| {
        SdkError::invalid_argument(format!(
            "非法十六进制字符串: {raw}（长度必须为偶数，且只含 0-9a-fA-F）"
        ))
    })
}

/// 小写十六进制编码，**不带** `0x` 前缀。
pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// 小写十六进制编码，带 `0x` 前缀。
pub fn encode_hex_prefixed(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_accepts_prefix_and_case() {
        assert_eq!(
            decode_hex("0xDEADBEEF").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            decode_hex("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(decode_hex("  0X00ff ").unwrap(), vec![0x00, 0xff]);
    }

    #[test]
    fn decode_rejects_odd_length() {
        let err = decode_hex("0xabc").unwrap_err();
        assert!(err.message.contains("非法十六进制"));
    }

    #[test]
    fn encode_roundtrip() {
        let bytes = vec![0x04u8, 0x11, 0x00, 0xff];
        let encoded = encode_hex(&bytes);
        assert_eq!(encoded, "041100ff");
        assert_eq!(encode_hex_prefixed(&bytes), "0x041100ff");
        assert_eq!(decode_hex(&encoded).unwrap(), bytes);
    }
}
