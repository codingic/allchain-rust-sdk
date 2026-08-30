//! ar-sdk：基于 Arweave 公共 HTTP 网关的链能力库，实现统一 `ChainClient` 契约。
//!
//! 领域背景（Arweave 与其余九条链的差异点）：
//! - 它是**去中心化存储链**，区块里装的是数据（transaction 的 `data`）而非纯粹的转账；
//! - 密钥体系是 **RSA-PSS 4096 位**，而不是椭圆曲线（ed25519 / secp256k1）。
//!   地址 = `base64url(sha256(RSA 公钥模数 n 的原始字节))`，固定 43 字符；
//! - 最小单位 `winston`，精度 12（1 AR = 10^12 winston）；
//! - 官方不提供 JSON-RPC，只有一组 REST 端点（`/info`、`/tx/{id}`、`/wallet/{addr}/balance`），
//!   以及可选的 GraphQL 网关（本 crate 只用 REST）。
//!
//! 关于依赖：`Cargo.toml` 里列了 `arweave-rs`，但本 crate 并未调用它——
//! 请求统一走 `chain_rpcutil::Http`。理由与 apt / ckb 一致：只需要四个只读端点，
//! 不值得为此拖入一整棵依赖树（那会引入 RSA、GraphQL 客户端等重量级依赖）。
//!
//! 明确的能力边界：本 crate **只提供只读查询与本地公钥派生地址**，不支持转账。
//! Arweave 的转账要用 RSA-PSS 对交易的完整字段签名并做 chunk 上传，
//! 属于写路径，当前未实现；`ChainClient::transfer` 走 trait 默认分支返回 `UNSUPPORTED`。

pub mod adapter;
pub mod network;
