//! 网络端点与 RPC 客户端构造。

use near_jsonrpc_client::JsonRpcClient;

/// 预置网络选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
    Localnet,
}

impl NetworkArg {
    pub fn rpc_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://rpc.mainnet.near.org",
            NetworkArg::Testnet => "https://rpc.testnet.near.org",
            NetworkArg::Localnet => "http://127.0.0.1:3030",
        }
    }

    pub fn explorer_base(self) -> Option<&'static str> {
        match self {
            NetworkArg::Mainnet => Some("https://explorer.near.org"),
            NetworkArg::Testnet => Some("https://explorer.testnet.near.org"),
            NetworkArg::Localnet => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Testnet => "testnet",
            NetworkArg::Localnet => "localnet",
        }
    }
}

use near_primitives::views::TxExecutionStatus;

/// 交易查询的等待阶段（对应 NEAR RPC 的 `wait_until` 参数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum WaitUntilArg {
    /// 不等待，立即返回当前状态
    None,
    /// 交易已入块（未最终确认）
    Included,
    /// 交易已完成执行（乐观，默认）
    ExecutedOptimistic,
    /// 交易已入最终确认区块
    IncludedFinal,
    /// 交易在最终区块中完成执行
    Executed,
    /// 所有收据（含退款收据）均已最终确认
    Final,
}

impl From<WaitUntilArg> for TxExecutionStatus {
    fn from(value: WaitUntilArg) -> Self {
        match value {
            WaitUntilArg::None => TxExecutionStatus::None,
            WaitUntilArg::Included => TxExecutionStatus::Included,
            WaitUntilArg::ExecutedOptimistic => TxExecutionStatus::ExecutedOptimistic,
            WaitUntilArg::IncludedFinal => TxExecutionStatus::IncludedFinal,
            WaitUntilArg::Executed => TxExecutionStatus::Executed,
            WaitUntilArg::Final => TxExecutionStatus::Final,
        }
    }
}

/// 连接到指定 URL 的 JSON-RPC 客户端。
pub fn connect(rpc_url: &str) -> JsonRpcClient {
    JsonRpcClient::connect(rpc_url)
}
