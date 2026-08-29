//! 网络端点与 RPC Provider 构造。

use alloy::providers::RootProvider;
use anyhow::{Context, Result};

/// 预置网络选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NetworkArg {
    Mainnet,
    Sepolia,
    Localnet,
}

impl NetworkArg {
    pub fn rpc_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://ethereum-rpc.publicnode.com",
            NetworkArg::Sepolia => "https://ethereum-sepolia-rpc.publicnode.com",
            NetworkArg::Localnet => "http://127.0.0.1:8545",
        }
    }

    pub fn explorer_base(self) -> Option<&'static str> {
        match self {
            NetworkArg::Mainnet => Some("https://etherscan.io"),
            NetworkArg::Sepolia => Some("https://sepolia.etherscan.io"),
            NetworkArg::Localnet => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Sepolia => "sepolia",
            NetworkArg::Localnet => "localnet",
        }
    }
}

/// 解析命令行/预置的端点字符串为 URL。
pub fn parse_url(rpc_url: &str) -> Result<url::Url> {
    url::Url::parse(rpc_url).with_context(|| format!("非法 RPC 端点: {rpc_url}"))
}

/// 连接到指定 URL 的只读 HTTP Provider（无钱包、不填充交易字段）。
pub fn connect(rpc_url: &str) -> Result<RootProvider> {
    Ok(RootProvider::new_http(parse_url(rpc_url)?))
}
