//! apt-sdk：基于 Aptos 官方 REST API（v1）的链能力库，实现统一 `ChainClient` 契约。
//!
//! 只读查询（status / balance / block / tx）走 REST；地址派生为纯本地 SHA3-256 计算。

pub mod adapter;
pub mod network;
