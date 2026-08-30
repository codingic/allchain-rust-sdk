//! SOL 单位换算与公钥/私钥解析。
//!
//! 设计要点：Solana 的最小单位是 **lamport**，1 SOL = 10^9 lamport（9 位小数）。
//! 金额换算全程走「字符串切分 + 整数运算」，绝不经过 `f64`——
//! 0.1 这类十进制小数在二进制浮点里无法精确表示，一旦过了浮点就会引入分币级误差。

// `anyhow` 是面向**应用层**的错误处理库：`Result<T>` 是 `Result<T, anyhow::Error>` 的别名，
// 错误类型是**装箱的 trait object**，能容纳任意实现了 `std::error::Error` 的错误。
// 与 core 里的 `SdkError` 分工不同：本层（链 crate 内部）用 anyhow 快速串联各种
// 第三方 SDK 的错误类型，到 adapter 层再统一转成 `SdkError`。
// - `Result` → 上面说的类型别名；
// - `bail!`  → 宏，等价于 `return Err(anyhow!(..))`，用于提前返回错误。
use anyhow::{Result, bail};

/// 1 SOL = 10^9 lamports。
///
/// 语法说明：`pub const` 是**编译期常量**，类型 `u64` 必须显式写出。
/// 字面量里的下划线 `1_000_000_000` 只是**视觉分隔符**，不影响数值
/// （Rust 允许在数字中任意插入 `_`）。
/// `pub` 让 adapter / CLI 也能引用它，不必各处重复同一个魔法数字。
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

/// SOL 的小数位数，与 [`LAMPORTS_PER_SOL`] 的指数一致。
///
/// 刻意**不**加 `pub`：它是本文件的实现细节，解析与格式化都在这一个文件内闭环，
/// 不外泄就不会出现「改了精度却漏改某处」的问题。
const SOL_DECIMALS: usize = 9;

/// 把十进制字符串（如 `0.5`）解析为 lamports，避免浮点精度损失。
/// 只接受**非负十进制小数**（拒绝 `-1`、`1e9`、`0x10` 等写法）：转账金额没有负数语义，
/// 科学计数法会引入精度歧义，一律拒绝比默默算错更安全。
///
/// 语法说明：返回值 `Result<u64>` 中的 `u64` 即 lamport 数，与 Solana 链上
/// （`get_balance`、SystemProgram.transfer）的表示一致，无需再转换。
pub fn parse_sol(input: &str) -> Result<u64> {
    // `trim()` 去掉首尾空白（命令行/表单粘进来的字符串常带空格）。
    // 它返回 `&str`（原串的一个切片），不产生新的 `String` 分配。
    let s = input.trim();
    if s.is_empty() {
        // `bail!` 展开成 `return Err(anyhow!(..))`，是 anyhow 里提前返回错误的惯用写法。
        bail!("金额不能为空");
    }
    // `split_once('.')` 按**第一个** `.` 把字符串切成前后两半，返回 `Option<(&str, &str)>`。
    // 与 `split('.')` 迭代器不同，它只切一次并直接给出两半，正好对应「整数部分 / 小数部分」。
    // 没有小数点时走 `None` 分支、小数部分视为空串，于是 "5" 与 "5.0" 等价。
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    // 逐字符校验：`.chars()` 是 Unicode 字符迭代器，`.all(|c| ..)` 要求**全部**满足闭包。
    // `is_ascii_digit()` 只认 `0-9`，因此全角数字、正负号、空格都会被拒绝
    // （注意 `trim` 只处理首尾，字符串中间的空格到这里会被判非法）。
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        bail!("金额格式非法: {input}（仅支持十进制数字，如 0.5）");
    }
    // 精度守卫：小数位超过 9 位意味着金额不足 1 lamport，链上无法表示，直接拒绝，
    // 而不是静默截断——静默截断会让调用方以为金额对得上，实际差了一个数量级。
    if frac_part.len() > SOL_DECIMALS {
        bail!("金额小数位最多 {SOL_DECIMALS} 位: {input}");
    }
    // 右侧补零到 9 位，于是 "5" → "500000000"（即 0.5 SOL）。
    // 格式化微语言拆解 `{frac_part:0<width$}`：
    //   `0`     → 填充字符是 '0'；
    //   `<`     → 左对齐，即**在右侧填充**；
    //   `width` → 宽度取自同名变量（见行尾的 `width = SOL_DECIMALS`）；
    //   `$`     → 表示 `width` 是命名参数而非字面量宽度。
    // 注意方向与下面 `format_sol` 里的 `0>` 相反，两者别写反。
    let frac_padded = format!("{frac_part:0<width$}", width = SOL_DECIMALS);
    // `parse()` 的目标类型由**变量标注** `let whole: u64` 推导出来，
    // 这是 turbofish（`parse::<u64>()`）之外另一种指定类型的方式。
    // `map_err` 把 `ParseIntError` 转成 anyhow 错误，顺带补上用户可读的上下文。
    let whole: u64 = int_part
        .parse()
        .map_err(|_| anyhow::anyhow!("金额超出 u64 范围: {input}"))?;
    // 整数运算组合子链，全程**不会溢出 panic**：
    // - `checked_mul` / `checked_add`：溢出时返回 `None`，而不是 debug 下 panic、release 下回绕；
    // - `and_then(|v| ..)`：只有上一步是 `Some` 才继续，把两步「可能失败」的运算串成一条链；
    // - `ok_or_else(|| ..)`：把最终的 `Option<u64>` 转成 `Result`，且**惰性**构造错误对象
    //   （对比 `ok_or(..)` 会无条件构造，闭包形式更省）。
    // 这里不能直接用 `?` 提前返回：`Option` 不是 `Result`，必须先转换。
    //
    // 末行无分号，是函数体最后一个表达式，即返回值。
    whole
        .checked_mul(LAMPORTS_PER_SOL)
        .and_then(|v| v.checked_add(frac_padded.parse::<u64>().unwrap_or(0)))
        .ok_or_else(|| anyhow::anyhow!("金额超出 u64 范围: {input}"))
}

/// 把 lamports 格式化为 SOL 字符串，去掉无意义的尾随零。
/// `1_500_000_000` → `"1.5"`；`1_000_000_000` → `"1"`（不是 "1.0"）。
///
/// 与 core 的 `format_units(lamports, 9)` 功能重叠；本函数存在的意义是给
/// **CLI 打印路径**一个不依赖 core 的轻量实现，且入参固定为 `u64` 的 lamport。
pub fn format_sol(lamports: u64) -> String {
    // 整数除法 `/` 与取余 `%` 配合，把小数点「左移」9 位：
    // 商是整数部分，余数是小数部分（已隐含 9 位小数的量纲）。
    let int_part = lamports / LAMPORTS_PER_SOL;
    let frac_part = lamports % LAMPORTS_PER_SOL;
    // 小数部分为 0 时提前返回，避免出现 "1." 这种难看的尾巴。
    if frac_part == 0 {
        return int_part.to_string();
    }
    // `{frac_part:0>width$}`：`0` 是填充字符、`>` 表示右对齐，即**在左侧补零**。
    // 补零是必须的：1 lamport 的余数是 `1`，不补零就会印成 "0.1"，
    // 而正确值是 0.000000001，差了 8 个数量级。
    let frac = format!("{frac_part:0>width$}", width = SOL_DECIMALS);
    // `trim_end_matches('0')` 去掉尾随零。上一行已保证是 9 位定长，
    // 所以裁剪不会误伤有效数字。参数是**字符** `'0'`（单引号）而非字符串 `"0"`。
    format!("{}.{}", int_part, frac.trim_end_matches('0'))
}

/// 单元测试模块。
///
/// 语法说明：`#[cfg(test)]` 是**条件编译属性**：只有 `cargo test` 时才编译这段，
/// 正式构建里完全不存在。`use super::*` 把父模块（本文件）的全部条目导入进来，
/// 于是可以直接写 `parse_sol(..)` 而不必写 `super::parse_sol(..)`。
#[cfg(test)]
mod tests {
    use super::*;

    /// 往返（round-trip）测试：解析与格式化应互为逆运算。
    /// `#[test]` 把函数注册为用例；失败靠 `panic!` 表达，`assert_eq!` 内部即 panic。
    #[test]
    fn sol_round_trip() {
        assert_eq!(parse_sol("1").unwrap(), LAMPORTS_PER_SOL);
        assert_eq!(parse_sol("0.5").unwrap(), 500_000_000);
        assert_eq!(parse_sol("0.000000001").unwrap(), 1);
        assert_eq!(format_sol(LAMPORTS_PER_SOL), "1");
        assert_eq!(format_sol(500_000_000), "0.5");
        assert_eq!(format_sol(1), "0.000000001");
    }

    /// 非法输入必须报错，而不是静默截断。
    #[test]
    fn rejects_bad_input() {
        // 非数字字符。
        assert!(parse_sol("abc").is_err());
        // 10 位小数 = 0.1 lamport，低于最小单位，应拒绝而非截断为 0。
        //
        // `assert!(..)` 直接断言布尔条件，比 `assert_eq!(x.is_err(), true)` 更符合惯例，
        // 且失败时宏能打印出表达式原文，便于定位。
        assert!(parse_sol("0.0000000001").is_err());
    }
}
