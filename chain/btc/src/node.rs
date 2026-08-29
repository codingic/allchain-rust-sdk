//! 网络选择、认证方式与 JSON-RPC 客户端构造。

use std::path::PathBuf;

use anyhow::{Context, Result};
use bitcoincore_rpc::{Auth, Client};
use clap::ValueEnum;

/// 预置网络选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
    Regtest,
}

impl NetworkArg {
    /// 比特币核心各网络的默认 RPC 端口。
    pub fn default_rpc_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "http://127.0.0.1:8332",
            NetworkArg::Testnet => "http://127.0.0.1:18332",
            NetworkArg::Regtest => "http://127.0.0.1:18443",
        }
    }

    /// 各网络默认的 cookie 文件路径（macOS 数据目录）。
    pub fn default_cookie_path(self) -> Option<PathBuf> {
        let home = std::env::var_os("HOME")?;
        let dir = match self {
            NetworkArg::Mainnet => "Bitcoin",
            NetworkArg::Testnet => "Bitcoin/testnet3",
            NetworkArg::Regtest => "Bitcoin/regtest",
        };
        Some(
            PathBuf::from(home)
                .join("Library/Application Support")
                .join(dir)
                .join(".cookie"),
        )
    }

    pub fn network(self) -> bitcoin::Network {
        match self {
            NetworkArg::Mainnet => bitcoin::Network::Bitcoin,
            NetworkArg::Testnet => bitcoin::Network::Testnet,
            NetworkArg::Regtest => bitcoin::Network::Regtest,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Testnet => "testnet",
            NetworkArg::Regtest => "regtest",
        }
    }
}

/// 构造 bitcoind RPC 客户端。
///
/// 认证优先级：显式 `--user/--pass` > `--cookie` > 该网络默认 cookie 文件。
pub fn connect(
    rpc_url: &str,
    user: Option<&str>,
    pass: Option<&str>,
    cookie: Option<&str>,
    network: NetworkArg,
) -> Result<Client> {
    if let (Some(u), Some(p)) = (user, pass) {
        return Client::new(rpc_url, Auth::UserPass(u.to_string(), p.to_string()))
            .context("连接 bitcoind 失败（用户密码认证）");
    }

    let cookie_path = cookie
        .map(PathBuf::from)
        .or_else(|| network.default_cookie_path())
        .filter(|p| p.exists());

    match cookie_path {
        Some(path) => {
            let display = path.display().to_string();
            Client::new(rpc_url, Auth::CookieFile(path))
                .with_context(|| format!("连接 bitcoind 失败（cookie: {display}）"))
        }
        None => Client::new(rpc_url, Auth::None).with_context(|| {
            format!(
                "连接 bitcoind 失败：未找到认证信息。请用 --user/--pass 或 --cookie 指定，\
                 默认 cookie 路径为 {}",
                network
                    .default_cookie_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            )
        }),
    }
}
