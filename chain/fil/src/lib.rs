//! fil-sdk：基于 Filecoin Lotus JSON-RPC 的链能力库，实现统一 `ChainClient` 契约。
//!
//! 模块划分：
//! - `adapter` —— `ChainClient` trait 的实现，是唯一对外暴露的门面；
//! - `address` —— Filecoin 地址的手写编解码（不依赖官方 `forest` / `lotus` 库）；
//! - `network` —— 预置网络与 RPC 端点；
//! - `tx`      —— **无私钥两段式**转账（构造 → agent 签名 → 广播）的纯逻辑。
//!
//! 能力：只读查询 + 本地公钥派生地址 + 原生转账。
//! 转账有两条路径：
//! - 一体式 `transfer`：私钥进 SDK，包办构造 + 签名 + 广播；
//! - 两段式 `build_transfer` / `submit_tx`：**私钥不进 SDK**，
//!   SDK 只负责构造与广播，签名留给调用方（agent）。
//!
//! 两条路径共用 `tx` 模块里的纯函数（CID 计算、签名摘要、Lotus JSON 组装），
//! 因此产出的消息字节完全一致。
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
/// 无私钥两段式转账的构造与重组逻辑。
pub mod tx;
