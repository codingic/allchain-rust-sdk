//! 集群端点、commitment 与 RPC 客户端构造。

use clap::ValueEnum;
use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::rpc_client::RpcClient;

/// 预置集群选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ClusterArg {
    Mainnet,
    Devnet,
    Testnet,
    Localnet,
}

impl ClusterArg {
    pub fn rpc_url(self) -> &'static str {
        match self {
            ClusterArg::Mainnet => "https://api.mainnet-beta.solana.com",
            ClusterArg::Devnet => "https://api.devnet.solana.com",
            ClusterArg::Testnet => "https://api.testnet.solana.com",
            ClusterArg::Localnet => "http://127.0.0.1:8899",
        }
    }

    pub fn explorer_base(self) -> Option<&'static str> {
        match self {
            ClusterArg::Mainnet => Some("https://explorer.solana.com"),
            ClusterArg::Devnet => Some("https://explorer.solana.com"),
            ClusterArg::Testnet => Some("https://explorer.solana.com"),
            ClusterArg::Localnet => None,
        }
    }

    /// Explorer 的集群后缀参数（mainnet 无后缀）。
    pub fn explorer_cluster(self) -> &'static str {
        match self {
            ClusterArg::Mainnet => "",
            ClusterArg::Devnet => "?cluster=devnet",
            ClusterArg::Testnet => "?cluster=testnet",
            ClusterArg::Localnet => "?cluster=custom&customUrl=http%3A%2F%2F127.0.0.1%3A8899",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ClusterArg::Mainnet => "mainnet",
            ClusterArg::Devnet => "devnet",
            ClusterArg::Testnet => "testnet",
            ClusterArg::Localnet => "localnet",
        }
    }
}

/// CLI 侧的 commitment 选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CommitmentArg {
    Processed,
    Confirmed,
    Finalized,
}

impl From<CommitmentArg> for CommitmentConfig {
    fn from(value: CommitmentArg) -> Self {
        match value {
            CommitmentArg::Processed => CommitmentConfig::processed(),
            CommitmentArg::Confirmed => CommitmentConfig::confirmed(),
            CommitmentArg::Finalized => CommitmentConfig::finalized(),
        }
    }
}

/// 构造 RPC 客户端（带超时提示：公共节点对 getBlock 等重接口有限流）。
pub fn connect(rpc_url: &str, commitment: CommitmentConfig) -> RpcClient {
    RpcClient::new_with_commitment(rpc_url.to_string(), commitment)
}
