//! eth-sdk：基于 alloy（Ethereum 官方 Rust SDK）的链能力库。
//!
//! 供 `acli` 统一门面复用；`eth-rpc-cli` 二进制仍然保留，作为单链命令行入口。
//!
//! 模块分层（与 trait 契约的对应关系）：
//! - `network`      —— 网络枚举与默认端点，负责造出 `RootProvider`；
//! - `queries`      —— 单链 CLI 使用的**打印型**查询函数，直接往 stdout 输出；
//! - `transactions` —— 构造 / 本地签名 / 广播，私钥只在本进程内使用；
//! - `units`        —— wei / gwei / ether 的纯整数换算；
//! - `adapter`      —— 实现 `allchain_core::ChainClient`，把上面几层的结果
//!   映射成 core 的统一 View 结构（不打印、只返回数据）。

/// 统一契约 `ChainClient` 的 ETH 实现，本 crate 对外的主要出口。
pub mod adapter;
/// 网络枚举与 Provider 构造。
pub mod network;
/// 单链 CLI 的只读查询打印（status / account / balance / block / tx / call）。
pub mod queries;
/// 交易构造、本地签名与广播。
pub mod transactions;
/// wei / gwei / ether 单位换算。
pub mod units;
