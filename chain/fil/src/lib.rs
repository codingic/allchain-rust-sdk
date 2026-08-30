//! fil-sdk：基于 Filecoin Lotus JSON-RPC 的链能力库，实现统一 `ChainClient` 契约。
//!
//! 模块划分：
//! - `adapter` —— `ChainClient` trait 的实现，是唯一对外暴露的门面；
//! - `address` —— Filecoin 地址的手写编解码（不依赖官方 `forest` / `lotus` 库）；
//! - `network` —— 预置网络与 RPC 端点。
//!
//! 能力边界（与 `core::ChainKind::capabilities` 保持一致）：
//! **只读查询 + 本地公钥派生地址**，不支持转账。
//! Filecoin 的转账需要构造并签名一条 message（含 gas 三元组、nonce、Method 号），
//! 本项目首期不提供，因此 `transfer` 走 trait 默认实现返回 `UNSUPPORTED`。
//!
//! 语法说明：`pub mod` 声明一个**公共模块**，外部可写 `fil_sdk::adapter::FilClient`。
//! Rust 的模块树与文件系统一一对应：`src/lib.rs` 是 crate 根，
//! `pub mod adapter;` 对应 `src/adapter.rs`（或 `src/adapter/mod.rs`）。

/// 链能力实现：`ChainClient` trait 的 Filecoin 版本。
pub mod adapter;
/// 地址编解码，纯本地实现，不访问网络。
pub mod address;
/// 预置网络与端点常量。
pub mod network;
