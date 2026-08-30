//! sui-sdk：基于 Sui 官方 GraphQL RPC 的链能力库，实现统一 `ChainClient` 契约。
//!
//! 模块划分：
//! - `adapter` —— `ChainClient` trait 的实现，是唯一对外暴露的门面；
//! - `network` —— 预置网络与 GraphQL 端点。
//!
//! 能力边界：与 FIL 一样是**只读查询 + 本地公钥派生地址**，不支持转账。
//! 地址派生是纯本地的 `blake2b-256(flag || pubkey)`，不依赖任何链上状态，
//! 详见 `adapter::derive_address`。
//!
//! 为什么没有独立的 `address` 模块：Sui 的地址派生只有哈希一步，
//! 比 Filecoin 的「哈希 + 校验和 + base32」简单得多，放在 adapter 里足够。

/// 链能力实现：`ChainClient` trait 的 Sui 版本。
pub mod adapter;
/// 预置网络与端点常量。
pub mod network;
