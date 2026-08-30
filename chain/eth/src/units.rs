//! ETH 单位换算：wei / gwei / ether。
//!
//! 全文件不出现 `f64`：链上金额一律用 `U256`（256 位无符号整数）承载，
//! 十进制字符串到整数的换算靠**字符串补齐 + 整数运算**完成。
//! 原因与 core 的 `format_units` 一致——f64 只有 53 位有效位，
//! 装不下 10^18 量级的 wei 精确值。

// `U256` 是 alloy 的大整数类型：EVM 的字长就是 256 位，
// 用它能无损表达 uint256 类型的所有链上数值，`u128` 在极端情况下会溢出。
use alloy::primitives::U256;
// `bail!` 是 anyhow 的宏，等价于 `return Err(anyhow!(..))`，用于提前返回错误。
use anyhow::{Result, bail};

/// 1 ether = 10^18 wei。
///
/// 语法说明：数字里的 `_` 只是**千位分隔符**，编译器会忽略它，
/// 纯粹为了提高可读性（等价于 1000000000000000000）。
pub const WEI_PER_ETHER: u128 = 1_000_000_000_000_000_000;
/// 1 gwei = 10^9 wei。gas 价格通常以 gwei 报价。
pub const WEI_PER_GWEI: u128 = 1_000_000_000;
/// 单笔交易 gas 上限（以太坊主块当前上限 30M，常规交互 10M 足够且更安全）。
///
/// 领域说明：这是一个**防御性上限**。gas limit 是「愿意为这笔交易支付的最大
/// 计算量」，填太大意味着把整个账户余额暴露给一笔可能失控的交易；
/// 主网单块 gas 上限约 3000 万，这里取 1000 万既够用又留了安全边界。
pub const MAX_GAS_LIMIT: u64 = 10_000_000;

/// ether 的小数位数（私有常量，不给外部依赖）。
const ETHER_DECIMALS: usize = 18;

/// 把十进制字符串（如 `0.01`）解析为 wei，纯整数运算避免浮点精度损失。
///
/// 输入单位由 `unit` 指定（`ether` 或 `gwei`），输出始终为 wei。
///
/// 算法：拆成整数部分与小数部分 → 小数部分右补齐到 `decimals` 位 →
/// 分别解析成整数 → `整数 * 10^decimals + 小数`。
/// 例：`"0.01"` + ether → `0 * 10^18 + 10000000000000000`。
pub fn parse_amount(input: &str, unit: &str) -> Result<U256> {
    // `trim()` 去掉首尾空白；用户输入常带空格，先归一化再校验。
    let s = input.trim();
    if s.is_empty() {
        bail!("金额不能为空");
    }
    // `match` 在这里同时充当「单位查表」与「非法单位报错」两件事。
    let decimals = match unit {
        "ether" => ETHER_DECIMALS,
        "gwei" => 9,
        // `other` 是**绑定模式**：匹配任意值并把它绑定到变量上，供错误信息使用。
        other => bail!("未知金额单位: {other}（支持 ether / gwei）"),
    };

    // `split_once('.')` 返回 `Option<(&str, &str)>`：
    // 有小数点 → `Some((整数部分, 小数部分))`；没有 → `None`。
    // 用它而不是 `split('.')` 迭代器，是因为小数点最多一个，语义更精确。
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    // `chars().all(闭包)`：所有字符都满足条件才为 true。
    // 这里逐个确认是 ASCII 数字，从而挡掉负号、指数记数法（1e18）、全角数字等。
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        bail!("金额格式非法: {input}（仅支持十进制数字，如 0.01）");
    }
    // 超过精度的小数直接拒绝，而不是静默截断——静默截断会让用户少转钱却毫无察觉。
    if frac_part.len() > decimals {
        bail!("金额小数位最多 {decimals} 位: {input}");
    }

    // 格式化微语言：`0<` 表示**左对齐**并用 `0` 填充，`width` 取自同名变量。
    // 于是 "01" + 18 位 → "010000000000000000"（即 0.01 ether 的小数部分）。
    let frac_padded = format!("{frac_part:0<width$}", width = decimals);
    // `U256` 实现了 `FromStr`，所以 `parse()` 能直接得到大整数；
    // 用 `map_err` 换掉标准库那个不带上下文的 `ParseIntError`。
    let whole: U256 = int_part
        .parse()
        .map_err(|_| anyhow::anyhow!("金额整数部分超出范围: {input}"))?;
    let frac: U256 = frac_padded
        .parse()
        .map_err(|_| anyhow::anyhow!("金额小数部分超出范围: {input}"))?;
    // `U256::pow` 的指数也必须是 `U256`，所以要先把 `usize` 转一次。
    // `U256` 的加法在超出 2^256 时 debug 模式会 panic、release 模式回绕，
    // 但 ETH 总供应量约 1.2 亿 ether，远低于 2^256/10^18，实务上不触及。
    Ok(whole * U256::from(10u64).pow(U256::from(decimals)) + frac)
}

/// 把 wei 格式化为十进制字符串（去掉无意义的尾随零），小数位不超过 `decimals`。
///
/// 与 core 的 `format_units` 做同一件事，只是入参是 `U256` 而非 `u128`。
pub fn format_wei(wei: U256, decimals: usize) -> String {
    let base = U256::from(10u64).pow(U256::from(decimals));
    // `/` 与 `%` 是整数除法与取余，`U256` 上都已实现。
    let int_part = wei / base;
    let frac_part = wei % base;
    // 小数部分为 0 时直接返回整数部分，避免出现 "1." 这种尾巴。
    if frac_part.is_zero() {
        return int_part.to_string();
    }
    // `mut` 声明可变绑定，因为下面要对同一个变量重新赋值。
    let mut frac = frac_part.to_string();
    // `0>` 表示**右对齐**补零：值 "1" + 宽度 18 → "100000000000000000" 再左补零成
    // "000000000000000001"。这一步不可省——否则 0.0000001 会被印成 "0.1"。
    frac = format!("{frac:0>width$}", width = decimals);
    // `trim_end_matches('0')` 去掉尾部多余的 0；它返回的是 `&str` 切片，不产生新分配。
    let frac = frac.trim_end_matches('0');
    format!("{int_part}.{frac}")
}

/// 解析 gas limit（纯整数），缺省使用 `default`。
///
/// `input` 为 `None` 或空串时返回 `default`——命令行里「不传 --gas」是常态，
/// 不该因此报错。
pub fn parse_gas_limit(input: Option<&str>, default: u64) -> Result<u64> {
    // `unwrap_or("")`：把 `Option<&str>` 展平成 `&str`，`None` 时给空串占位，
    // 这样后面的 trim / is_empty 两条分支可以合并处理。
    let raw = input.unwrap_or("").trim();
    if raw.is_empty() {
        return Ok(default);
    }
    let gas: u64 = raw
        .parse()
        .map_err(|_| anyhow::anyhow!("gas limit 格式非法: {raw}（应为整数，单位 gas）"))?;
    // 上界是 `MAX_GAS_LIMIT`，下界是 1：gas limit 为 0 的交易必然立即失败，
    // 属于典型的输入错误，提前拦下比让节点拒绝更友好。
    if gas == 0 || gas > MAX_GAS_LIMIT {
        bail!("gas limit 超出范围: {gas}（允许 1..={MAX_GAS_LIMIT}）");
    }
    Ok(gas)
}

/// 单元测试模块：`#[cfg(test)]` 保证只在 `cargo test` 时编译。
#[cfg(test)]
mod tests {
    // 把父模块的全部条目导入本作用域。
    use super::*;

    /// ether 的解析与格式化互为逆运算（往返测试）。
    #[test]
    fn ether_round_trip() {
        assert_eq!(
            parse_amount("1", "ether").unwrap(),
            U256::from(WEI_PER_ETHER)
        );
        assert_eq!(
            parse_amount("0.001", "ether").unwrap(),
            U256::from(1_000_000_000_000_000u128)
        );
        assert_eq!(
            parse_amount("1.5", "ether").unwrap(),
            U256::from(1_500_000_000_000_000_000u128)
        );
        assert_eq!(format_wei(U256::from(WEI_PER_ETHER), 18), "1");
        assert_eq!(
            format_wei(U256::from(1_000_000_000_000_000u128), 18),
            "0.001"
        );
    }

    /// gwei 走的是另一条精度分支（9 位小数）。
    #[test]
    fn gwei_round_trip() {
        assert_eq!(
            parse_amount("30", "gwei").unwrap(),
            U256::from(30_000_000_000u128)
        );
        assert_eq!(
            parse_amount("1.5", "gwei").unwrap(),
            U256::from(1_500_000_000u128)
        );
        assert_eq!(format_wei(U256::from(30_000_000_000u128), 9), "30");
    }

    /// 各类非法输入都必须被拒绝，而不是被静默截断。
    #[test]
    fn rejects_bad_input() {
        assert!(parse_amount("abc", "ether").is_err());
        // 19 位小数——超出 18 位精度
        assert!(parse_amount("1.0000000000000000001", "ether").is_err());
        // wei 不是本函数支持的输入单位
        assert!(parse_amount("1", "wei").is_err());
        assert!(parse_gas_limit(Some("0"), 21000).is_err());
        assert!(parse_gas_limit(Some("999999999"), 21000).is_err());
    }
}
