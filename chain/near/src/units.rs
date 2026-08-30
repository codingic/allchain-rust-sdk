//! NEAR 单位换算：yoctoNEAR、TGas。

//! ## 为什么一切都用整数/字符串，绝不用 f64
//! NEAR 的最小单位 **yoctoNEAR** 有 24 位小数：1 NEAR = 10^24 yoctoNEAR。
//! 这个量级远超 f64 能精确表示的范围（f64 只有 53 位有效位，
//! 从 2^53 约 9.0e15 开始就无法区分相邻整数了）。
//! 一旦过了浮点，转账金额就会出现「差几个 yocto」的误差。
//! 因此本文件全程用 `u128` + 字符串切分，与 core 的 `format_units` 思路一致。

use anyhow::{Result, bail};

/// 1 NEAR = 10^24 yoctoNEAR。
///
/// 24 位小数是 NEAR 的标志性设计，也是「金额必须用 u128 / 字符串承载」的根源。
/// `u128` 的上限约 3.4e38，装 10^24 量级的数绰绰有余。
pub const YOCTO_PER_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
/// 1 TGas = 10^12 gas units。
///
/// NEAR 的 gas 账单以 gas unit 计价，但用户习惯说 TGas（tera gas），
/// 两者差 10^12 倍。单笔交易的 gas 上限是 300 TGas。
pub const GAS_PER_TGAS: u64 = 1_000_000_000_000;
/// 函数默认追加 gas。
///
/// 100 TGas 足以覆盖绝大多数简单合约调用；复杂的跨合约调用需要调用方显式加。
pub const DEFAULT_TGAS: u64 = 100;

/// NEAR 的小数位数，与 [`YOCTO_PER_NEAR`] 的指数一致。
///
/// 刻意**不**导出：它是本文件的实现细节，不外泄就不会被改坏。
const NEAR_DECIMALS: usize = 24;

/// 把十进制字符串（如 `1.25`）解析为 yoctoNEAR，避免浮点精度损失。
pub fn parse_near(input: &str) -> Result<u128> {
    // `trim()` 去首尾空白（命令行输入常带空格/换行）。返回 `&str`，零分配。
    let s = input.trim();
    if s.is_empty() {
        bail!("金额不能为空");
    }
    // `split_once('.')` 按第一个 `.` 切出「整数部分 / 小数部分」，
    // 返回 `Option<(&str, &str)>`；没有小数点时小数部分取空串，于是 "1" 与 "1.0" 等价。
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    // 逐字符校验：`.chars().all(|c| c.is_ascii_digit())` 要求**全部**是 0-9，
    // 因此负号、科学计数法、全角数字、中间空格全部被拒。
    // 转账金额没有负数语义，宁可明确报错也不要默默接受。
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        bail!("金额格式非法: {input}（仅支持十进制数字，如 0.01）");
    }
    // 精度守卫：小数位超过 24 位意味着不足 1 yoctoNEAR，链上无法表示。
    // 直接拒绝而非截断——截断会让调用方以为金额对得上。
    if frac_part.len() > NEAR_DECIMALS {
        bail!("金额小数位最多 {NEAR_DECIMALS} 位: {input}");
    }
    // 整数部分解析成 u128。这里用 `unwrap_or(0)` 兜底而不是 `?`：
    // 结合上面的逐字符校验，走到这里说明**全是数字**，
    // 解析只可能因为「超出 u128 范围」而失败，那种情况会被下面的 checked_mul 一并拦下
    // （一个大到溢出的整数部分乘以 10^24 必然溢出）。
    // 显式标注 `let mut yocto: u128` 指定 parse 的目标类型。
    let mut yocto: u128 = int_part.parse().unwrap_or(0);
    // 小数部分**右侧**补零到 24 位，于是 "5" → "500000000000000000000000"（0.5 NEAR）。
    // 格式化串 `{frac_part:0<width$}`：`0` 是填充字符、`<` 是左对齐（即在右侧填充）、
    // `width$` 表示宽度取自行尾的同名变量。
    let frac_padded = format!("{frac_part:0<width$}", width = NEAR_DECIMALS);
    // 整数运算组合子链，全程**不会溢出 panic**：
    // - `checked_mul(YOCTO_PER_NEAR)`：整数部分 × 10^24，溢出返回 `None`；
    // - `and_then(|v| v.checked_add(..))`：加上小数部分，溢出返回 `None`；
    // - `ok_or_else(|| ..)`：把 `Option` 转成 `Result`，且**惰性**构造错误对象。
    //
    // 这里**必须**用 `?` 而不是 `unwrap`：溢出是真实可能发生的（用户填了个天文数字），
    // 把它变成一条可读的错误远比 panic 掉整个进程好。
    yocto = yocto
        .checked_mul(YOCTO_PER_NEAR)
        .and_then(|v| v.checked_add(frac_padded.parse::<u128>().unwrap_or(0)))
        .ok_or_else(|| anyhow::anyhow!("金额超出 u128 范围: {input}"))?;
    Ok(yocto)
}

/// 把 yoctoNEAR 格式化为 NEAR 字符串，去掉无意义的尾随零。
pub fn format_near(yocto: u128) -> String {
    // 与 SOL 那侧同样的套路：商是整数部分，余数是小数部分（已隐含 24 位小数的量纲）。
    let int_part = yocto / YOCTO_PER_NEAR;
    let frac_part = yocto % YOCTO_PER_NEAR;
    // 小数部分为 0 时提前返回，避免出现 "1." 这种尾巴。
    if frac_part == 0 {
        return int_part.to_string();
    }
    // `{frac_part:0>width$}`：`0` 是填充字符、`>` 是右对齐（即**在左侧补零**）。
    // 补零是必须的：1 yoctoNEAR 的余数是 `1`，不补零会印成 "0.1"，
    // 而正确值是 0.000000000000000000000001，差了 23 个数量级——
    // 小数位越多，这个坑越致命。
    let frac = format!("{frac_part:0>width$}", width = NEAR_DECIMALS);
    let frac_trimmed = frac.trim_end_matches('0');
    // 内联命名参数：`{int_part}` / `{frac_trimmed}` 直接捕获同名变量（Rust 2021 特性）。
    format!("{int_part}.{frac_trimmed}")
}

/// 把 TGas 字符串（如 `30`）解析为 gas units，缺省使用 [`DEFAULT_TGAS`]。
///
/// **这是本文件里唯一允许用浮点的地方**：gas 是「资源预算」而不是「金额」，
/// 精度要求低（gas 单价本身也是浮动的），且上限只有 300 TGas，
/// 用 f64 表示不会有任何精度问题。换成整数解析反而让 "30.5" 这类输入变得别扭。
///
/// 语法说明：参数是 `Option<&str>`——`None` 表示「没给，用默认值」。
pub fn parse_tgas(input: Option<&str>) -> Result<u64> {
    // `unwrap_or("")`：没给时按空串处理，走下面的「空则默认」分支。
    // 这样 `None` 与 `Some("")` 两种输入得到一致的结果，调用方不必区分。
    let raw = input.unwrap_or("");
    let s = raw.trim();
    if s.is_empty() {
        return Ok(DEFAULT_TGAS * GAS_PER_TGAS);
    }
    // 解析成 f64（标注 `let tgas: f64` 指定目标类型）。
    // `map_err` 把 `ParseFloatError` 换成带中文说明的 anyhow 错误。
    let tgas: f64 = s
        .parse()
        .map_err(|_| anyhow::anyhow!("gas 格式非法: {s}（应为数字，单位 TGas）"))?;
    // 范围校验：0 与负数无意义；超过 300 TGas 是**协议硬上限**，
    // 节点会直接拒绝，与其等到广播时报错，不如在这里拦下。
    if tgas <= 0.0 || tgas > 300.0 {
        bail!("gas 超出范围: {s} TGas（单笔交易上限 300 TGas）");
    }
    // TGas → gas units，`.round()` 四舍五入到最近的整数再用 `as u64` 截断。
    // 这里 `as` 是安全的：tgas <= 300，乘 10^12 后约 3e14，远小于 u64 上限（约 1.8e19）。
    Ok((tgas * GAS_PER_TGAS as f64).round() as u64)
}

/// 单元测试模块：`#[cfg(test)]` 保证只在 `cargo test` 时编译，正式构建里不存在。
#[cfg(test)]
mod tests {
    use super::*;

    /// 往返测试：解析与格式化互为逆运算，且覆盖 24 位小数的边界。
    #[test]
    fn near_round_trip() {
        assert_eq!(parse_near("1").unwrap(), YOCTO_PER_NEAR);
        // 0.001 NEAR = 10^21 yoctoNEAR，正好卡在 u64 装不下（u64 上限约 1.8e19）
        // 而 u128 能装下的区间——这条断言实际上在守护「必须用 u128」这个决定。
        assert_eq!(parse_near("0.001").unwrap(), 1_000_000_000_000_000_000_000);
        assert_eq!(
            parse_near("1.5").unwrap(),
            1_500_000_000_000_000_000_000_000
        );
        assert_eq!(format_near(YOCTO_PER_NEAR), "1");
        assert_eq!(format_near(1_000_000_000_000_000_000_000), "0.001");
    }

    /// 非法输入必须报错而不是静默截断。
    #[test]
    fn rejects_bad_input() {
        // 非数字字符。
        assert!(parse_near("abc").is_err());
        // 25 位小数 = 0.1 yoctoNEAR，低于最小单位，应拒绝。
        assert!(parse_near("1.0000000000000000000000001").is_err());
    }
}
