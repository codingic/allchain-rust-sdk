//! BTC <-> satoshi 的精确换算、费率解析与 vsize 估算。

use anyhow::{Result, bail};

/// 1 BTC = 10^8 satoshi。
pub const SAT_PER_BTC: u64 = 100_000_000;
/// 缺省费率（sat/vB）。
pub const DEFAULT_FEE_RATE: f64 = 5.0;
/// 找零低于该值就不再单独输出（作为手续费消化），546 sat 是 P2PKH 的 dust 阈值。
pub const DUST_LIMIT: u64 = 546;

const BTC_DECIMALS: usize = 8;

/// 把十进制 BTC 字符串（如 `0.001`）解析为 satoshi，避免浮点精度损失。
pub fn parse_btc(input: &str) -> Result<u64> {
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
        bail!("金额格式非法: {input}（仅支持十进制数字，如 0.001）");
    }
    if frac_part.len() > BTC_DECIMALS {
        bail!("金额小数位最多 {BTC_DECIMALS} 位: {input}");
    }
    let frac_padded = format!("{frac_part:0<width$}", width = BTC_DECIMALS);
    let sat: u64 = int_part
        .parse()
        .map_err(|_| anyhow::anyhow!("金额超出 u64 范围: {input}"))?;
    sat.checked_mul(SAT_PER_BTC)
        .and_then(|v| v.checked_add(frac_padded.parse::<u64>().unwrap_or(0)))
        .ok_or_else(|| anyhow::anyhow!("金额超出 u64 范围: {input}"))
}

/// 带单位的金额解析：`0.001`（默认 BTC）、`0.001btc`、`25000sat`。
pub fn parse_amount(input: &str) -> Result<u64> {
    let s = input.trim().to_ascii_lowercase();
    if let Some(num) = s.strip_suffix("sat").or_else(|| s.strip_suffix("sats")) {
        return num
            .trim()
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("金额格式非法: {input}"));
    }
    let num = s.strip_suffix("btc").unwrap_or(&s).trim();
    parse_btc(num)
}

/// 把 satoshi 格式化为 BTC 字符串，去掉无意义的尾随零。
pub fn format_btc(sat: u64) -> String {
    let int_part = sat / SAT_PER_BTC;
    let frac_part = sat % SAT_PER_BTC;
    if frac_part == 0 {
        return int_part.to_string();
    }
    let frac = format!("{frac_part:0>width$}", width = BTC_DECIMALS);
    format!("{int_part}.{}", frac.trim_end_matches('0'))
}

/// 解析费率（sat/vB），缺省使用 [`DEFAULT_FEE_RATE`]。
pub fn parse_fee_rate(input: Option<&str>) -> Result<f64> {
    let s = input.unwrap_or("").trim();
    if s.is_empty() {
        return Ok(DEFAULT_FEE_RATE);
    }
    let rate: f64 = s
        .parse()
        .map_err(|_| anyhow::anyhow!("费率格式非法: {s}（应为数字，单位 sat/vB）"))?;
    if rate <= 0.0 || rate > 10_000.0 {
        bail!("费率超出范围: {s} sat/vB（允许 0 ~ 10000）");
    }
    Ok(rate)
}

/// 输入 / 输出的脚本类型，用于估算交易虚拟体积。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptKind {
    /// 原生隔离见证 P2WPKH。
    P2wpkh,
    /// 传统 P2PKH。
    P2pkh,
}

impl ScriptKind {
    /// 单个输入的 vsize（vB，已含见证数据折扣）。
    pub fn input_vsize(self) -> f64 {
        match self {
            ScriptKind::P2wpkh => 68.0,
            ScriptKind::P2pkh => 148.0,
        }
    }

    /// 单个输出的 vsize（vB）。
    pub fn output_vsize(self) -> f64 {
        match self {
            ScriptKind::P2wpkh => 31.0,
            ScriptKind::P2pkh => 34.0,
        }
    }
}

/// 估算交易虚拟体积：10.5 vB 基础开销 + 各输入 / 输出体积（向上取整）。
pub fn estimate_vsize(inputs: &[ScriptKind], output_kind: ScriptKind, output_count: usize) -> u64 {
    let total = 10.5
        + inputs.iter().map(|k| k.input_vsize()).sum::<f64>()
        + output_kind.output_vsize() * output_count as f64;
    total.ceil() as u64
}

/// 按费率把 vsize 换算为手续费（sat），至少 1 sat/vB 的下限保护由调用方保证。
pub fn fee_for_vsize(vsize: u64, fee_rate: f64) -> u64 {
    (vsize as f64 * fee_rate).ceil().max(1.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btc_round_trip() {
        assert_eq!(parse_btc("1").unwrap(), SAT_PER_BTC);
        assert_eq!(parse_btc("0.001").unwrap(), 100_000);
        assert_eq!(parse_btc("1.5").unwrap(), 150_000_000);
        assert_eq!(format_btc(SAT_PER_BTC), "1");
        assert_eq!(format_btc(100_000), "0.001");
        assert_eq!(format_btc(1), "0.00000001");
    }

    #[test]
    fn parses_units() {
        assert_eq!(parse_amount("25000sat").unwrap(), 25_000);
        assert_eq!(parse_amount("0.001BTC").unwrap(), 100_000);
        assert!(parse_amount("abc").is_err());
        assert!(parse_btc("0.000000001").is_err());
    }

    #[test]
    fn vsize_grows_with_inputs() {
        let one = estimate_vsize(&[ScriptKind::P2wpkh], ScriptKind::P2wpkh, 2);
        let two = estimate_vsize(
            &[ScriptKind::P2wpkh, ScriptKind::P2wpkh],
            ScriptKind::P2wpkh,
            2,
        );
        assert_eq!(two - one, 68);
        assert_eq!(fee_for_vsize(one, 2.0), one * 2);
    }
}
