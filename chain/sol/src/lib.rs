//! sol-sdk：基于 solana-rpc-client 4.2 的链能力库。
//!
//! 注意：Solana RPC 客户端是同步阻塞 API，统一门面中需包在 `spawn_blocking` 内调用。
//!
//! ## 依赖形态
//! solana 官方 SDK 从 2.x 起把原先的单体 crate 拆成了几十个细粒度 crate
//! （`solana-pubkey` / `solana-keypair` / `solana-transaction` / `solana-rpc-client` …），
//! 本 crate 只按需引入其中十来个。好处是编译面小，代价是**版本号互不统一**
//! （`solana-pubkey 4.2` 与 `solana-keypair 3.1` 同时存在很正常），
//! 升级时不要想当然地把所有 `solana-*` 拉到同一个版本号。
//!
//! ## 模块分层
//! - [`cluster`]  ：集群端点与 commitment，只负责「连哪里、以什么确认级别读」；
//! - [`queries`]  ：**CLI 直调**的只读查询，函数直接 `println!` 打印，返回 `anyhow::Result`；
//! - [`tx`]       ：密钥管理与转账交易的构造 / 签名 / 广播；
//! - [`units`]    ：lamport <-> SOL 的纯函数换算；
//! - [`adapter`]  ：实现 core 的 `ChainClient` trait，是**统一门面唯一会用到的入口**。
//!
//! 前四个模块是「链的原生能力」，最后一个是「对统一契约的适配」：
//! adapter 会复用 `tx` / `units` 里的纯计算，但不复用 `queries` 的打印逻辑，
//! 因为统一门面要求返回结构化数据（各 `View`）而不是打印文本。

/// 对 core 的 `ChainClient` trait 的实现，统一门面通过它访问本链。
pub mod adapter;
/// 集群端点、commitment 与 RPC 客户端构造。
pub mod cluster;
/// 只读查询（status / get_block / get_tx / balance），带命令行打印。
pub mod queries;
/// 密钥管理与转账交易的构造、签名、广播。
pub mod tx;
/// SOL / lamport 单位换算。
pub mod units;
