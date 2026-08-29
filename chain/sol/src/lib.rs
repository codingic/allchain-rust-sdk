//! sol-sdk：基于 solana-rpc-client 4.2 的链能力库。
//!
//! 注意：Solana RPC 客户端是同步阻塞 API，统一门面中需包在 `spawn_blocking` 内调用。

pub mod adapter;
pub mod cluster;
pub mod queries;
pub mod tx;
pub mod units;
