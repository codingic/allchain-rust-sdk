//! 网络选择（mainnet / testnet / testnet4 / signet / regtest）与默认端点。

use std::path::PathBuf;

use bitcoin::Network;

/// CLI 可选网络。
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
    Testnet4,
    Signet,
    Regtest,
}

impl NetworkArg {
    /// 映射到 rust-bitcoin 的 [`Network`]。
    pub fn network(self) -> Network {
        match self {
            NetworkArg::Mainnet => Network::Bitcoin,
            NetworkArg::Testnet => Network::Testnet,
            NetworkArg::Testnet4 => Network::Testnet4,
            NetworkArg::Signet => Network::Signet,
            NetworkArg::Regtest => Network::Regtest,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Testnet => "testnet",
            NetworkArg::Testnet4 => "testnet4",
            NetworkArg::Signet => "signet",
            NetworkArg::Regtest => "regtest",
        }
    }

    /// Esplora REST 端点（mempool.space 兼容实现，用于地址 / UTXO / 费率查询与广播）。
    pub fn esplora_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://mempool.space/api",
            NetworkArg::Testnet => "https://mempool.space/testnet/api",
            NetworkArg::Testnet4 => "https://mempool.space/testnet4/api",
            NetworkArg::Signet => "https://mempool.space/signet/api",
            NetworkArg::Regtest => "http://127.0.0.1:3000/api",
        }
    }

    /// bitcoind JSON-RPC 默认端口。
    pub fn node_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "http://127.0.0.1:8332",
            NetworkArg::Testnet => "http://127.0.0.1:18332",
            NetworkArg::Testnet4 => "http://127.0.0.1:48332",
            NetworkArg::Signet => "http://127.0.0.1:38332",
            NetworkArg::Regtest => "http://127.0.0.1:18443",
        }
    }

    /// 区块浏览器基址，用于拼接交易 / 地址链接。
    pub fn explorer_base(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://mempool.space",
            NetworkArg::Testnet => "https://mempool.space/testnet",
            NetworkArg::Testnet4 => "https://mempool.space/testnet4",
            NetworkArg::Signet => "https://mempool.space/signet",
            NetworkArg::Regtest => "http://127.0.0.1:3000",
        }
    }

    /// bitcoind 数据目录下该网络对应的子目录（cookie 探测用）。
    fn datadir_subdir(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "",
            NetworkArg::Testnet => "testnet3",
            NetworkArg::Testnet4 => "testnet4",
            NetworkArg::Signet => "signet",
            NetworkArg::Regtest => "regtest",
        }
    }

    /// 探测 bitcoind 的 `.cookie` 文件（macOS 与 Linux 两条常见路径），不存在返回 None。
    pub fn default_cookie(self) -> Option<PathBuf> {
        let home = PathBuf::from(std::env::var_os("HOME")?);
        let sub = self.datadir_subdir();
        [
            home.join("Library/Application Support/Bitcoin").join(sub),
            home.join(".bitcoin").join(sub),
        ]
        .into_iter()
        .map(|dir| dir.join(".cookie"))
        .find(|path| path.is_file())
    }
}

impl std::fmt::Display for NetworkArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
