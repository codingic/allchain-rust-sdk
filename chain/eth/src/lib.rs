//! eth-sdk：基于 alloy（Ethereum 官方 Rust SDK）的链能力库。
//!
//! 供 `acli` 统一门面复用；`eth-rpc-cli` 二进制仍然保留，作为单链命令行入口。

pub mod adapter;
pub mod network;
pub mod queries;
pub mod transactions;
pub mod units;
