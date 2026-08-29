//! SOL 单位换算与公钥/私钥解析。

use anyhow::{Result, bail};

/// 1 SOL = 10^9 lamports。
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

const SOL_DECIMALS: usize = 9;

/// 把十进制字符串（如 `0.5`）解析为 lamports，避免浮点精度损失。
pub fn parse_sol(input: &str) -> Result<u64> {
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
        bail!("金额格式非法: {input}（仅支持十进制数字，如 0.5）");
    }
    if frac_part.len() > SOL_DECIMALS {
        bail!("金额小数位最多 {SOL_DECIMALS} 位: {input}");
    }
    let frac_padded = format!("{frac_part:0<width$}", width = SOL_DECIMALS);
    let whole: u64 = int_part
        .parse()
        .map_err(|_| anyhow::anyhow!("金额超出 u64 范围: {input}"))?;
    whole
        .checked_mul(LAMPORTS_PER_SOL)
        .and_then(|v| v.checked_add(frac_padded.parse::<u64>().unwrap_or(0)))
        .ok_or_else(|| anyhow::anyhow!("金额超出 u64 范围: {input}"))
}

/// 把 lamports 格式化为 SOL 字符串，去掉无意义的尾随零。
pub fn format_sol(lamports: u64) -> String {
    let int_part = lamports / LAMPORTS_PER_SOL;
    let frac_part = lamports % LAMPORTS_PER_SOL;
    if frac_part == 0 {
        return int_part.to_string();
    }
    let frac = format!("{frac_part:0>width$}", width = SOL_DECIMALS);
    format!("{}.{}", int_part, frac.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sol_round_trip() {
        assert_eq!(parse_sol("1").unwrap(), LAMPORTS_PER_SOL);
        assert_eq!(parse_sol("0.5").unwrap(), 500_000_000);
        assert_eq!(parse_sol("0.000000001").unwrap(), 1);
        assert_eq!(format_sol(LAMPORTS_PER_SOL), "1");
        assert_eq!(format_sol(500_000_000), "0.5");
        assert_eq!(format_sol(1), "0.000000001");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_sol("abc").is_err());
        assert!(parse_sol("0.0000000001").is_err());
    }
}
