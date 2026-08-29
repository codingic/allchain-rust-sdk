//! NEAR 单位换算：yoctoNEAR、TGas。

use anyhow::{Result, bail};

/// 1 NEAR = 10^24 yoctoNEAR。
pub const YOCTO_PER_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
/// 1 TGas = 10^12 gas units。
pub const GAS_PER_TGAS: u64 = 1_000_000_000_000;
/// 函数默认追加 gas。
pub const DEFAULT_TGAS: u64 = 100;

const NEAR_DECIMALS: usize = 24;

/// 把十进制字符串（如 `1.25`）解析为 yoctoNEAR，避免浮点精度损失。
pub fn parse_near(input: &str) -> Result<u128> {
    let s = input.trim();
    if s.is_empty() {
        bail!("金额不能为空");
    }
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        bail!("金额格式非法: {input}（仅支持十进制数字，如 0.01）");
    }
    if frac_part.len() > NEAR_DECIMALS {
        bail!("金额小数位最多 {NEAR_DECIMALS} 位: {input}");
    }
    let mut yocto: u128 = int_part.parse().unwrap_or(0);
    let frac_padded = format!("{frac_part:0<width$}", width = NEAR_DECIMALS);
    yocto = yocto
        .checked_mul(YOCTO_PER_NEAR)
        .and_then(|v| v.checked_add(frac_padded.parse::<u128>().unwrap_or(0)))
        .ok_or_else(|| anyhow::anyhow!("金额超出 u128 范围: {input}"))?;
    Ok(yocto)
}

/// 把 yoctoNEAR 格式化为 NEAR 字符串，去掉无意义的尾随零。
pub fn format_near(yocto: u128) -> String {
    let int_part = yocto / YOCTO_PER_NEAR;
    let frac_part = yocto % YOCTO_PER_NEAR;
    if frac_part == 0 {
        return int_part.to_string();
    }
    let frac = format!("{frac_part:0>width$}", width = NEAR_DECIMALS);
    let frac_trimmed = frac.trim_end_matches('0');
    format!("{int_part}.{frac_trimmed}")
}

/// 把 TGas 字符串（如 `30`）解析为 gas units，缺省使用 [`DEFAULT_TGAS`]。
pub fn parse_tgas(input: Option<&str>) -> Result<u64> {
    let raw = input.unwrap_or("");
    let s = raw.trim();
    if s.is_empty() {
        return Ok(DEFAULT_TGAS * GAS_PER_TGAS);
    }
    let tgas: f64 = s
        .parse()
        .map_err(|_| anyhow::anyhow!("gas 格式非法: {s}（应为数字，单位 TGas）"))?;
    if tgas <= 0.0 || tgas > 300.0 {
        bail!("gas 超出范围: {s} TGas（单笔交易上限 300 TGas）");
    }
    Ok((tgas * GAS_PER_TGAS as f64).round() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn near_round_trip() {
        assert_eq!(parse_near("1").unwrap(), YOCTO_PER_NEAR);
        assert_eq!(parse_near("0.001").unwrap(), 1_000_000_000_000_000_000_000);
        assert_eq!(
            parse_near("1.5").unwrap(),
            1_500_000_000_000_000_000_000_000
        );
        assert_eq!(format_near(YOCTO_PER_NEAR), "1");
        assert_eq!(format_near(1_000_000_000_000_000_000_000), "0.001");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_near("abc").is_err());
        assert!(parse_near("1.0000000000000000000000001").is_err());
    }
}
