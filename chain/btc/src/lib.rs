//! btc-sdk：基于 rust-bitcoin / bitcoincore-rpc / Esplora 的链能力库。
//!
//! `backend` 中的 *View 结构体是查询层的数据模型，同时供统一门面做 JSON 序列化。
//!
//! 与 ETH crate 最大的差别：**BTC 全节点不提供「按地址查余额」的能力**。
//! bitcoind 只索引交易（且默认连 txindex 都未必开），地址 → UTXO 的映射
//! 必须由**外部索引器**提供。因此本 crate 采用双数据源：
//! - `esplora`  —— mempool.space 兼容的 REST 索引器，负责**地址类**查询；
//! - `node`     —— 可选的本地 bitcoind JSON-RPC，负责**节点类**查询与广播。
//!   `backend::Chain` 把两者封装成一个统一视图，调用方不用关心数据来自哪边。
//!
//! ⚠️ 易错点：本 crate 里名为 `rpc_url` 的参数指的是 **Esplora 索引器地址**
//! （形如 `https://mempool.space/api`），**不是** bitcoind 的 JSON-RPC 端点
//! （形如 `http://127.0.0.1:8332`）。后者单独由 `--node-url` 指定。

/// 统一契约 `ChainClient` 的 BTC 实现，本 crate 对外的主要出口。
pub mod adapter;
/// 双数据源（Esplora + 可选 bitcoind）的统一封装与查询视图。
pub mod backend;
/// Esplora REST 索引器的 HTTP 客户端与响应模型。
pub mod esplora;
/// 网络枚举与各自默认的索引器 / 节点端点。
pub mod network;
/// 查询结果的格式化打印（单链 CLI 使用）。
pub mod queries;
/// 从 WIF 私钥派生地址、选币、构造交易并离线签名。
pub mod transactions;
/// BTC / satoshi 换算、费率解析与 vsize 估算。
pub mod units;
