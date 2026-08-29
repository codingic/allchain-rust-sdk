//! ETH 单位换算：wei / gwei / ether。

use alloy::primitives::U256;
use anyhow::{Result, bail};

/// 1 ether = 10^18 wei。
pub const WEI_PER_ETHER: u128 = 1_000_000_000_000_000_000;
/// 1 gwei = 10^9 wei。
pub const WEI_PER_GWEI: u128 = 1_000_000_000;
/// 单笔交易 gas 上限（以太坊主块当前上限 30M，常规交互 10M 足够且更安全）。
pub const MAX_GAS_LIMIT: u64 = 10_000_000;

const ETHER_DECIMALS: usize = 18;

/// 把十进制字符串（如 `0.01`）解析为 wei，纯整数运算避免浮点精度损失。
///
/// 输入单位由 `unit` 指定（`ether` 或 `gwei`），输出始终为 wei。
pub fn parse_amount(input: &str, unit: &str) -> Result<U256> {
    let s = input.trim();
    if s.is_empty() {
        bail!("金额不能为空");
    }
    let decimals = match unit {
        "ether" => ETHER_DECIMALS,
        "gwei" => 9,
        other => bail!("未知金额单位: {other}（支持 ether / gwei）"),
    };

    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        bail!("金额格式非法: {input}（仅支持十进制数字，如 0.01）");
    }
    if frac_part.len() > decimals {
        bail!("金额小数位最多 {decimals} 位: {input}");
    }

    let frac_padded = format!("{frac_part:0<width$}", width = decimals);
    let whole: U256 = int_part
        .parse()
        .map_err(|_| anyhow::anyhow!("金额整数部分超出范围: {input}"))?;
    let frac: U256 = frac_padded
        .parse()
        .map_err(|_| anyhow::anyhow!("金额小数部分超出范围: {input}"))?;
    Ok(whole * U256::from(10u64).pow(U256::from(decimals)) + frac)
}

/// 把 wei 格式化为十进制字符串（去掉无意义的尾随零），小数位不超过 `decimals`。
pub fn format_wei(wei: U256, decimals: usize) -> String {
    let base = U256::from(10u64).pow(U256::from(decimals));
    let int_part = wei / base;
    let frac_part = wei % base;
    if frac_part.is_zero() {
        return int_part.to_string();
    }
    let mut frac = frac_part.to_string();
    frac = format!("{frac:0>width$}", width = decimals);
    let frac = frac.trim_end_matches('0');
    format!("{int_part}.{frac}")
}

/// 解析 gas limit（纯整数），缺省使用 `default`。
pub fn parse_gas_limit(input: Option<&str>, default: u64) -> Result<u64> {
    let raw = input.unwrap_or("").trim();
    if raw.is_empty() {
        return Ok(default);
    }
    let gas: u64 = raw
        .parse()
        .map_err(|_| anyhow::anyhow!("gas limit 格式非法: {raw}（应为整数，单位 gas）"))?;
    if gas == 0 || gas > MAX_GAS_LIMIT {
        bail!("gas limit 超出范围: {gas}（允许 1..={MAX_GAS_LIMIT}）");
    }
    Ok(gas)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn rejects_bad_input() {
        assert!(parse_amount("abc", "ether").is_err());
        assert!(parse_amount("1.0000000000000000001", "ether").is_err());
        assert!(parse_amount("1", "wei").is_err());
        assert!(parse_gas_limit(Some("0"), 21000).is_err());
        assert!(parse_gas_limit(Some("999999999"), 21000).is_err());
    }
}
