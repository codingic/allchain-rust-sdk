//! sui-sdk：基于 Sui 官方 GraphQL RPC 的链能力库，实现统一 `ChainClient` 契约。
//!
//! 模块划分：
//! - `adapter` —— `ChainClient` trait 的实现，是唯一对外暴露的门面；
//! - `network` —— 预置网络与 GraphQL 端点；
//! - `tx` —— 交易构造与广播。**无私钥**的两段式流程与一体式 `transfer`
//!   共用同一份签名原语（intent 消息 + blake2b-256 摘要），详见该模块文档。
//!
//! 能力边界：只读查询 + 本地公钥派生地址 + 转账（一体式与两段式两条路径）。
//! 地址派生是纯本地的 `blake2b-256(flag || pubkey)`，不依赖任何链上状态，
//! 详见 `adapter::derive_address`。
//!
//! 为什么没有独立的 `address` 模块：Sui 的地址派生只有哈希一步，
//! 比 Filecoin 的「哈希 + 校验和 + base32」简单得多，放在 adapter 里足够。

/// 链能力实现：`ChainClient` trait 的 Sui 版本。
pub mod adapter;
/// 预置网络与端点常量。
pub mod network;
/// 交易构造、签名原语与广播。
pub mod tx;
