//! BTC <-> satoshi 的精确换算、费率解析与 vsize 估算。
//!
//! 领域背景（BTC 的三个计量单位，极易混淆）：
//! - **size**  ：序列化后的字节数；
//! - **weight**：权重单位（WU），隔离见证（SegWit）引入。`1 vB = 4 WU`，
//!               见证数据按 1 WU/字节、非见证数据按 4 WU/字节计，
//!               于是带见证的交易能享受约 75% 的「折扣」；
//! - **vsize** ：虚拟字节（vB），`vsize = ceil(weight / 4)`，
//!               **手续费就是按 vsize × 费率（sat/vB）结算的**。
//! 区块容量上限是 4,000,000 WU（= 1,000,000 vB），不是 1 MB 字节。

use anyhow::{Result, bail};

/// 1 BTC = 10^8 satoshi。
///
/// `satoshi`（聪）是 BTC 的**最小不可分割单位**，链上所有金额都是它的整数倍。
/// 这与 ETH 的 wei 地位相同，只是精度只有 8 位（ETH 是 18 位）。
pub const SAT_PER_BTC: u64 = 100_000_000;
/// 缺省费率（sat/vB）。
pub const DEFAULT_FEE_RATE: f64 = 5.0;
/// 找零低于该值就不再单独输出（作为手续费消化），546 sat 是 P2PKH 的 dust 阈值。
///
/// 领域说明：**dust（粉尘）** 指「金额小到花掉它的手续费比它本身还贵」的输出。
/// 节点默认拒绝转发会产生这类输出的交易。546 sat 是 P2PKH 的经典阈值，
/// 算法来自「花费该输出所需的最小交易体积 × 最低费率（3 sat/vB）」。
/// 与其让交易被拒，不如把这点余额直接并入手续费。
pub const DUST_LIMIT: u64 = 546;

/// BTC 的小数位数（私有常量，不给外部依赖）。
const BTC_DECIMALS: usize = 8;

/// 把十进制 BTC 字符串（如 `0.001`）解析为 satoshi，避免浮点精度损失。
///
/// 算法与 ETH 的 `parse_amount` 完全一致，只是精度换成 8 位：
/// 拆分整数/小数部分 → 小数右补齐到 8 位 → 整数运算合成。
pub fn parse_btc(input: &str) -> Result<u64> {
    let s = input.trim();
    if s.is_empty() {
        bail!("金额不能为空");
    }
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    // 逐字符确认是 ASCII 数字，挡掉负号、指数记数法、全角数字等写法。
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        bail!("金额格式非法: {input}（仅支持十进制数字，如 0.001）");
    }
    // 超出 8 位小数直接拒绝，而不是静默截断——静默截断会让用户少转钱却毫无察觉。
    if frac_part.len() > BTC_DECIMALS {
        bail!("金额小数位最多 {BTC_DECIMALS} 位: {input}");
    }
    // `0<` = 左对齐、用 0 填充："001" + 8 位 → "00100000"（即 0.001 BTC）。
    let frac_padded = format!("{frac_part:0<width$}", width = BTC_DECIMALS);
    let sat: u64 = int_part
        .parse()
        .map_err(|_| anyhow::anyhow!("金额超出 u64 范围: {input}"))?;
    // `checked_mul` / `checked_add` 是**溢出安全**的算术方法：
    // 溢出时返回 `None` 而不是回绕（release 模式下普通 `*` / `+` 会静默回绕）。
    // 用 `and_then` 把两步运算串起来——任意一步失败整体就是 `None`。
    sat.checked_mul(SAT_PER_BTC)
        // 小数部分已补齐到 8 位且长度合法，解析必然成功，
        // `unwrap_or(0)` 只是为了让类型统一成 `u64`。
        .and_then(|v| v.checked_add(frac_padded.parse::<u64>().unwrap_or(0)))
        // `ok_or_else(闭包)`：`Option` → `Result`，惰性构造错误。
        .ok_or_else(|| anyhow::anyhow!("金额超出 u64 范围: {input}"))
}

/// 带单位的金额解析：`0.001`（默认 BTC）、`0.001btc`、`25000sat`。
///
/// 语法说明：`strip_suffix` 返回 `Option<&str>`：有该后缀则返回去掉后的部分。
/// 用 `or_else(闭包)` 串起两个候选后缀——**先试长的 `sats` 再试短的 `sat`** 会更稳，
/// 这里顺序相反但无妨，因为 `strip_suffix("sat")` 对 "25000sats" 返回 None
/// （它是后缀匹配，不是前缀），不会误切。
pub fn parse_amount(input: &str) -> Result<u64> {
    // `to_ascii_lowercase` 先归一化大小写，于是 `0.001BTC` / `25000SAT` 都能识别。
    let s = input.trim().to_ascii_lowercase();
    if let Some(num) = s.strip_suffix("sat").or_else(|| s.strip_suffix("sats")) {
        return num
            .trim()
            // 直接以 satoshi 为单位时是纯整数，不再有小数。
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("金额格式非法: {input}"));
    }
    // 去掉可选的 `btc` 后缀；`unwrap_or(&s)` 在没有后缀时退回整个字符串。
    let num = s.strip_suffix("btc").unwrap_or(&s).trim();
    parse_btc(num)
}

/// 把 satoshi 格式化为 BTC 字符串，去掉无意义的尾随零。
pub fn format_btc(sat: u64) -> String {
    let int_part = sat / SAT_PER_BTC;
    let frac_part = sat % SAT_PER_BTC;
    // 小数部分为 0 时直接返回整数，避免出现 "1." 这种尾巴。
    if frac_part == 0 {
        return int_part.to_string();
    }
    // `0>` = 右对齐、左侧补零：1 sat → "00000001"，这一左补零不可省。
    let frac = format!("{frac_part:0>width$}", width = BTC_DECIMALS);
    format!("{int_part}.{}", frac.trim_end_matches('0'))
}

/// 解析费率（sat/vB），缺省使用 [`DEFAULT_FEE_RATE`]。
pub fn parse_fee_rate(input: Option<&str>) -> Result<f64> {
    // `unwrap_or("")` 把 `Option<&str>` 展平成 `&str`，
    // 于是「没传」与「传了空串」两条分支可以合并处理。
    let s = input.unwrap_or("").trim();
    if s.is_empty() {
        return Ok(DEFAULT_FEE_RATE);
    }
    let rate: f64 = s
        .parse()
        .map_err(|_| anyhow::anyhow!("费率格式非法: {s}（应为数字，单位 sat/vB）"))?;
    // 上界 10000 sat/vB 是防御性的：正常主网费率很少超过几百，
    // 填到五位数基本都是把「sat/字节」或笔误当成了「sat/vB」。
    if rate <= 0.0 || rate > 10_000.0 {
        bail!("费率超出范围: {s} sat/vB（允许 0 ~ 10000）");
    }
    Ok(rate)
}

/// 输入 / 输出的脚本类型，用于估算交易虚拟体积。
///
/// 领域说明：不同脚本类型的输入体积差异极大（68 vs 148 vB），
/// 因为 P2WPKH 的签名放在**见证字段**里、只算 1/4 权重，
/// 而 P2PKH 的签名塞在 scriptSig 里、按全价计。
/// 这正是 SegWit 能降低手续费的原理。
///
/// 语法说明：`Copy` 让它可以按值复制而不转移所有权，
/// 于是 `estimate_vsize(&[ScriptKind], ..)` 里能直接重复用同一个值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptKind {
    /// 原生隔离见证 P2WPKH（`bc1q...`）。
    P2wpkh,
    /// 传统 P2PKH（`1...`）。
    P2pkh,
}

impl ScriptKind {
    /// 单个输入的 vsize（vB，已含见证数据折扣）。
    pub fn input_vsize(self) -> f64 {
        match self {
            // 68 vB：outpoint 36 字节 + 空 scriptSig 1 字节 + sequence 4 字节，
            // 合计 41 非见证字节（164 WU）；见证含 72 字节签名 + 33 字节公钥
            // 加 2 字节长度前缀（约 108 WU）；(164 + 108) / 4 ≈ 68 vB。
            ScriptKind::P2wpkh => 68.0,
            // 148 vB：scriptSig 里要放 72 字节签名 + 33 字节公钥及推送前缀，
            // 全部按非见证数据全价计，故比 P2WPKH 大一倍多。
            ScriptKind::P2pkh => 148.0,
        }
    }

    /// 单个输出的 vsize（vB）。
    pub fn output_vsize(self) -> f64 {
        match self {
            // 8 字节金额 + 1 字节脚本长度 + 22 字节 P2WPKH 脚本 = 31 字节。
            ScriptKind::P2wpkh => 31.0,
            // 8 字节金额 + 1 字节脚本长度 + 25 字节 P2PKH 脚本 = 34 字节。
            ScriptKind::P2pkh => 34.0,
        }
    }
}

/// 估算交易虚拟体积：10.5 vB 基础开销 + 各输入 / 输出体积（向上取整）。
///
/// 10.5 vB 是固定开销：version 4 字节 + 输入计数 1 + 输出计数 1 + locktime 4，
/// 共 10 字节非见证数据（40 WU），再加 SegWit 的 marker/flag 2 字节（2 WU），
/// 合计 42 WU = 10.5 vB。
pub fn estimate_vsize(inputs: &[ScriptKind], output_kind: ScriptKind, output_count: usize) -> u64 {
    let total = 10.5
        // `inputs.iter()` 产生 `&ScriptKind`；`.map(|k| k.input_vsize())` 里
        // `k` 是引用，但方法接收的是 `self`（`Copy` 类型），会自动解引用。
        // `sum::<f64>()` 用 turbofish 语法指定求和结果的类型。
        + inputs.iter().map(|k| k.input_vsize()).sum::<f64>()
        // `output_count as f64`：整数到浮点的显式转换。
        + output_kind.output_vsize() * output_count as f64;
    // `ceil()` 向上取整：节点按**整数** vB 计费，估小了会导致费率不足。
    total.ceil() as u64
}

/// 按费率把 vsize 换算为手续费（sat），至少 1 sat/vB 的下限保护由调用方保证。
///
/// 向下取整会低于节点要求的最低费率，因此这里用 `ceil()` 向上取整，
/// 宁可多付 1 sat 也不要交易卡在内存池里。
pub fn fee_for_vsize(vsize: u64, fee_rate: f64) -> u64 {
    // `.max(1.0)` 兜底：保证手续费至少 1 sat，零费率交易会被节点直接拒绝。
    (vsize as f64 * fee_rate).ceil().max(1.0) as u64
}

/// 单元测试模块：`#[cfg(test)]` 保证只在 `cargo test` 时编译。
#[cfg(test)]
mod tests {
    use super::*;

    /// BTC 的解析与格式化互为逆运算（往返测试）。
    #[test]
    fn btc_round_trip() {
        assert_eq!(parse_btc("1").unwrap(), SAT_PER_BTC);
        assert_eq!(parse_btc("0.001").unwrap(), 100_000);
        assert_eq!(parse_btc("1.5").unwrap(), 150_000_000);
        assert_eq!(format_btc(SAT_PER_BTC), "1");
        assert_eq!(format_btc(100_000), "0.001");
        // 1 sat —— 最小单位，验证左补零逻辑
        assert_eq!(format_btc(1), "0.00000001");
    }

    /// 带单位后缀的解析：sat 与 btc 走两条不同分支。
    #[test]
    fn parses_units() {
        assert_eq!(parse_amount("25000sat").unwrap(), 25_000);
        // 大写后缀也应被接受（已 to_ascii_lowercase 归一化）
        assert_eq!(parse_amount("0.001BTC").unwrap(), 100_000);
        assert!(parse_amount("abc").is_err());
        // 9 位小数——超出 8 位精度
        assert!(parse_btc("0.000000001").is_err());
    }

    /// 多一个 P2WPKH 输入应恰好多 68 vB；费率换算应为线性。
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
