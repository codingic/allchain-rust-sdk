//! btc-sdk：基于 rust-bitcoin / bitcoincore-rpc / Esplora 的链能力库。
//!
//! `backend` 中的 *View 结构体是查询层的数据模型，同时供统一门面做 JSON 序列化。

pub mod adapter;
pub mod backend;
pub mod esplora;
pub mod network;
pub mod queries;
pub mod transactions;
pub mod units;
