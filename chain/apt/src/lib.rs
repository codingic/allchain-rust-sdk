//! apt-sdk：基于 Aptos 官方 REST API（v1）的链能力库，实现统一 `ChainClient` 契约。
//!
//! 只读查询（status / balance / block / tx）走 REST；地址派生为纯本地 SHA3-256 计算。
//!
//! 关于依赖的取舍：`Cargo.toml` 里虽然列了 `aptos-sdk`，但本 crate 实际**没有**
//! 直接调用它——所有请求都走 `chain_rpcutil::Http` 的 REST GET。
//! 这样设计有两个好处：
//! 1. 官方 SDK 会拖入一整棵依赖树（Move 类型、BCS 序列化、ed25519 实现等），
//!    而我们只需要四个只读接口，代价不成比例；
//! 2. 响应先统一反序列化成 `serde_json::Value` 再按需取字段，
//!    上游字段微调时不必同步维护一大批镜像结构体。
//!
//! 明确的能力边界：本 crate **只提供只读查询与本地公钥派生地址**，不支持转账。
//! Aptos 的转账需要构造 `EntryFunction` 的 BCS 负载并用账户的 sequence_number 签名，
//! 属于写路径，当前未实现；`ChainClient::transfer` 走 trait 默认分支返回 `UNSUPPORTED`。

// `pub mod` 把这个模块暴露给 crate 外。`mod` 本身是私有可见性，加 `pub` 才对外可见。
pub mod adapter;
pub mod network;
