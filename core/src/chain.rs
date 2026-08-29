//! 链标识与元信息。

use serde::{Deserialize, Serialize};

/// 支持的公链。序列化为小写短名。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainKind {
    Eth,
    Btc,
    Sol,
    Near,
    /// Aptos（Move，REST）。
    Apt,
    /// Arweave（REST/GraphQL 网关）。
    Ar,
    /// Nervos CKB（JSON-RPC）。
    Ckb,
    /// Filecoin（JSON-RPC）。
    Fil,
    /// Sui（GraphQL）。
    Sui,
    /// The Open Network（toncenter REST）。
    Ton,
}

/// 只读四件套。
const READ_CAPABILITIES: [&str; 4] = ["status", "balance", "block", "tx"];
/// 只读 + 公钥派生地址（纯本地计算）。
const READ_AND_DERIVE_CAPABILITIES: [&str; 5] =
    ["status", "balance", "block", "tx", "address_from_pubkey"];
/// 全量能力（含本地签名转账）。
const FULL_CAPABILITIES: [&str; 6] = [
    "status",
    "balance",
    "block",
    "tx",
    "address_from_pubkey",
    "transfer",
];

impl ChainKind {
    /// 全部受支持的链，按稳定顺序返回。
    pub const ALL: [ChainKind; 10] = [
        ChainKind::Eth,
        ChainKind::Btc,
        ChainKind::Sol,
        ChainKind::Near,
        ChainKind::Apt,
        ChainKind::Ar,
        ChainKind::Ckb,
        ChainKind::Fil,
        ChainKind::Sui,
        ChainKind::Ton,
    ];

    /// 链短名，与 JSON / CLI 参数一致。
    pub fn as_str(self) -> &'static str {
        match self {
            ChainKind::Eth => "eth",
            ChainKind::Btc => "btc",
            ChainKind::Sol => "sol",
            ChainKind::Near => "near",
            ChainKind::Apt => "apt",
            ChainKind::Ar => "ar",
            ChainKind::Ckb => "ckb",
            ChainKind::Fil => "fil",
            ChainKind::Sui => "sui",
            ChainKind::Ton => "ton",
        }
    }

    /// 解析链短名，大小写不敏感。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "eth" | "ethereum" => Some(ChainKind::Eth),
            "btc" | "bitcoin" => Some(ChainKind::Btc),
            "sol" | "solana" => Some(ChainKind::Sol),
            "near" => Some(ChainKind::Near),
            "apt" | "aptos" => Some(ChainKind::Apt),
            "ar" | "arweave" => Some(ChainKind::Ar),
            "ckb" | "nervos" => Some(ChainKind::Ckb),
            "fil" | "filecoin" => Some(ChainKind::Fil),
            "sui" => Some(ChainKind::Sui),
            "ton" => Some(ChainKind::Ton),
            _ => None,
        }
    }

    /// 原生资产符号。
    pub fn symbol(self) -> &'static str {
        match self {
            ChainKind::Eth => "ETH",
            ChainKind::Btc => "BTC",
            ChainKind::Sol => "SOL",
            ChainKind::Near => "NEAR",
            ChainKind::Apt => "APT",
            ChainKind::Ar => "AR",
            ChainKind::Ckb => "CKB",
            ChainKind::Fil => "FIL",
            ChainKind::Sui => "SUI",
            ChainKind::Ton => "TON",
        }
    }

    /// 最小单位名称（wei / satoshi / lamport / yoctoNEAR / octa / winston …）。
    pub fn unit_name(self) -> &'static str {
        match self {
            ChainKind::Eth => "wei",
            ChainKind::Btc => "satoshi",
            ChainKind::Sol => "lamport",
            ChainKind::Near => "yoctoNEAR",
            ChainKind::Apt => "octa",
            ChainKind::Ar => "winston",
            ChainKind::Ckb => "shannon",
            ChainKind::Fil => "attoFIL",
            ChainKind::Sui => "MIST",
            ChainKind::Ton => "nanoton",
        }
    }

    /// 原生资产精度（小数位数）。
    pub fn decimals(self) -> u8 {
        match self {
            ChainKind::Eth => 18,
            ChainKind::Btc => 8,
            ChainKind::Sol => 9,
            ChainKind::Near => 24,
            ChainKind::Apt => 8,
            ChainKind::Ar => 12,
            ChainKind::Ckb => 8,
            ChainKind::Fil => 18,
            ChainKind::Sui => 9,
            ChainKind::Ton => 9,
        }
    }

    /// 统一门面在未显式指定 `--network` 时使用的网络，**十链一律默认主网**。
    pub fn default_network(self) -> &'static str {
        "mainnet"
    }

    /// 该链在统一接口下真实可用的能力清单。
    ///
    /// 前四条链具备全量能力（含本地签名转账）；六条新链首期提供只读查询，
    /// 其中五条额外支持纯本地的公钥派生地址，TON 的地址依赖钱包合约 StateInit，
    /// 无法仅由公钥确定，因此只声明只读能力。
    pub fn capabilities(self) -> &'static [&'static str] {
        match self {
            ChainKind::Eth | ChainKind::Btc | ChainKind::Sol | ChainKind::Near => {
                &FULL_CAPABILITIES
            }
            ChainKind::Apt | ChainKind::Ar | ChainKind::Ckb | ChainKind::Fil | ChainKind::Sui => {
                &READ_AND_DERIVE_CAPABILITIES
            }
            ChainKind::Ton => &READ_CAPABILITIES,
        }
    }

    /// 是否支持原生资产转账（写操作）。
    pub fn supports_transfer(self) -> bool {
        matches!(
            self,
            ChainKind::Eth | ChainKind::Btc | ChainKind::Sol | ChainKind::Near
        )
    }
}

impl std::fmt::Display for ChainKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 把最小单位整数格式化为十进制字符串，避免 f64 精度丢失。
///
/// `1_500_000_000_000_000_000` wei + 18 位 → `"1.5"`。
pub fn format_units(amount: u128, decimals: u8) -> String {
    let divisor = 10u128.pow(decimals as u32);
    let integer = amount / divisor;
    let fraction = amount % divisor;
    if fraction == 0 {
        return integer.to_string();
    }
    let frac_str = format!("{fraction:0width$}", width = decimals as usize);
    let trimmed = frac_str.trim_end_matches('0');
    format!("{integer}.{trimmed}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_is_case_insensitive() {
        assert_eq!(ChainKind::parse("ETH"), Some(ChainKind::Eth));
        assert_eq!(ChainKind::parse(" Solana "), Some(ChainKind::Sol));
        assert_eq!(ChainKind::parse("Aptos"), Some(ChainKind::Apt));
        assert_eq!(ChainKind::parse("arweave"), Some(ChainKind::Ar));
        assert_eq!(ChainKind::parse("nervos"), Some(ChainKind::Ckb));
        assert_eq!(ChainKind::parse("FILECOIN"), Some(ChainKind::Fil));
        assert_eq!(ChainKind::parse("sui"), Some(ChainKind::Sui));
        assert_eq!(ChainKind::parse("TON"), Some(ChainKind::Ton));
        assert_eq!(ChainKind::parse("doge"), None);
    }

    #[test]
    fn all_variants_are_complete() {
        assert_eq!(ChainKind::ALL.len(), 10);
        for kind in ChainKind::ALL {
            // 每条链至少具备只读四件套。
            assert!(kind.capabilities().len() >= 4);
            assert_eq!(kind.default_network(), "mainnet");
        }
    }

    #[test]
    fn format_units_keeps_precision() {
        assert_eq!(format_units(1_500_000_000_000_000_000, 18), "1.5");
        assert_eq!(format_units(150_000_000, 8), "1.5");
        assert_eq!(format_units(1_500_000_000, 9), "1.5");
        assert_eq!(format_units(42, 8), "0.00000042");
        assert_eq!(format_units(0, 18), "0");
        assert_eq!(format_units(100, 0), "100");
    }
}
