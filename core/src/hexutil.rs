//! 十六进制编解码工具，供各链适配器解析调用方传入的公钥 / 哈希。
//!
//! 放在 core 里是为了让四链对「用户输入的 hex」有一致的行为与一致的报错文案：
//! - 允许 `0x` / `0X` 前缀；
//! - 大小写不敏感；
//! - 输出统一为**小写、无前缀**。
//!
//! 说明：这里的「四链」指首期接入的 ETH / BTC / SOL / NEAR；后续各链
//! 只要复用本模块，就能自动获得同样的宽松输入与统一报错。

// 只引入 `SdkError`，不引入具体链的类型：本模块不依赖任何链的知识。
use crate::SdkError;

/// 解码十六进制字符串。
///
/// 允许 `0x` / `0X` 前缀，大小写不敏感；奇数长度或含非法字符时返回
/// `INVALID_ARGUMENT`。
///
/// 语法说明：返回 `Result<Vec<u8>, SdkError>`——`Result` 是 Rust 的
/// 「要么成功、要么出错」二选一枚举，取值为 `Ok(值)` 或 `Err(错误)`。
/// 调用方必须显式处理 `Err`（通常用 `?` 向上传播），编译器会强制这一点。
pub fn decode_hex(raw: &str) -> Result<Vec<u8>, SdkError> {
    // `&str` 是**字符串切片引用**（借用，不取得所有权），
    // 因此函数内部不能修改调用方的字符串，也不会替它释放内存。
    let trimmed = raw.trim();
    let body = trimmed
        // `strip_prefix` 返回 `Option<&str>`：有前缀就 `Some(去掉前缀后的部分)`，
        // 没有就是 `None`。它不会修改原字符串，只是换个切片起点。
        .strip_prefix("0x")
        // `or_else(闭包)` 只在 `Option` 为 `None` 时**才调用闭包**（惰性求值），
        // 与 `or(另一个 Option)` 相对——后者会无条件先把备选项算出来。
        .or_else(|| trimmed.strip_prefix("0X"))
        // `unwrap_or(默认值)`：两个前缀都不是，那就原样使用 `trimmed`。
        .unwrap_or(trimmed);

    // `hex::decode` 自己返回的 `Err` 类型信息量太低（只说 InvalidHexCharacter 之类），
    // 因此用 `map_err(闭包)` 把错误**换掉**：保留 `Err` 位置，替换里面的错误值。
    // 闭包的 `|_|` 表示「我不关心原始错误的具体内容」。
    hex::decode(body).map_err(|_| {
        // 报错里回显用户原始输入 `raw`（内联捕获 `{raw}`），
        // 排查「用户到底传了什么」时非常关键。
        SdkError::invalid_argument(format!(
            "非法十六进制字符串: {raw}（长度必须为偶数，且只含 0-9a-fA-F）"
        ))
    })
    // 整个 `map_err(..)` 表达式是函数体最后一句且不带分号 → 作为返回值。
}

/// 小写十六进制编码，**不带** `0x` 前缀。
///
/// 参数 `&[u8]` 是**字节切片**：调用方可以传 `Vec<u8>`、数组 `[u8; 32]`、
/// 或另一切片的子区间，都不需要所有权转移。比写 `Vec<u8>` 参数宽松得多。
pub fn encode_hex(bytes: &[u8]) -> String {
    // 返回 `String`（拥有所有权的堆上字符串），而不是 `&str`——
    // 因为编码结果是新造出来的数据，没有任何现成的内存可以借用。
    hex::encode(bytes)
}

/// 小写十六进制编码，带 `0x` 前缀。
///
/// 与 [`encode_hex`] 的区别只在输出形态，用于需要符合 ETH / JSON-RPC 惯例的场合。
pub fn encode_hex_prefixed(bytes: &[u8]) -> String {
    // `format!` 宏与 `println!` 同族，区别在于它把结果**返回成 String** 而非打印。
    format!("0x{}", hex::encode(bytes))
}

/// 单元测试模块：`#[cfg(test)]` 保证它只在 `cargo test` 时编译。
#[cfg(test)]
mod tests {
    // 把父模块（本文件）的条目全部导入，于是可以直接写 `decode_hex`。
    use super::*;

    /// 前缀与大小写都应被正常接受。
    #[test]
    fn decode_accepts_prefix_and_case() {
        assert_eq!(
            decode_hex("0xDEADBEEF").unwrap(),
            // `vec![..]` 宏构造 `Vec<u8>`；元素类型由 `decode_hex` 的返回值反推为 `u8`。
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            decode_hex("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        // 前后空白 + 大写 `0X` 前缀 + 混合大小写，都应容错。
        assert_eq!(decode_hex("  0X00ff ").unwrap(), vec![0x00, 0xff]);
    }

    /// 奇数长度必须报错，且错误码为 INVALID_ARGUMENT（文案含「非法十六进制」）。
    #[test]
    fn decode_rejects_odd_length() {
        // `unwrap_err()` 是 `unwrap()` 的镜像：断言结果是 `Err` 并取出其中的错误值。
        let err = decode_hex("0xabc").unwrap_err();
        assert!(err.message.contains("非法十六进制"));
    }

    /// 编码 / 解码往返一致，且带前缀版本只多两个字符。
    #[test]
    fn encode_roundtrip() {
        // `0x04u8` 中的 `u8` 后缀显式指定整数字面量类型，
        // 于是整个 `vec!` 被推断为 `Vec<u8>`，不必额外标注。
        let bytes = vec![0x04u8, 0x11, 0x00, 0xff];
        // `&bytes` 把 `Vec<u8>` 借成 `&[u8]` 切片（deref coercion）。
        let encoded = encode_hex(&bytes);
        assert_eq!(encoded, "041100ff");
        assert_eq!(encode_hex_prefixed(&bytes), "0x041100ff");
        assert_eq!(decode_hex(&encoded).unwrap(), bytes);
    }
}
