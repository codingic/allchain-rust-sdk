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
//! 关于依赖：`arweave-rs` 只在**写路径**上被调用——交易的 deep hash 与
//! RSA-PSS 签名原语由它提供（`adapter::transfer` 与 `tx` 模块）；
//! 读路径（`/info`、`/tx/{id}`、余额…）一律走 `chain_rpcutil::Http`，
//! 因为只需要几个 REST 端点，不值得为它们再引一条依赖链。
//!
//! 能力边界：
//! - 读路径全部支持；
//! - 写路径有**两条**：
//!   - `ChainClient::transfer` 是**一体式**——私钥（JWK）进 SDK，签名与广播都在内部完成；
//!   - `ChainClient::build_transfer` + `ChainClient::submit_tx` 是**两段式**——
//!     SDK 只负责构造与广播，签名由调用方（agent）用自己的私钥完成，
//!     私钥**从不进入本进程**。纯计算部分在 [`tx`] 模块。
//!
//! 两段式在 AR 上有一个其它链没有的硬约束：交易的 `owner` 字段要写 RSA 模数 n，
//! 而地址是 `sha256(n)` 的哈希——**单向不可逆**，无法从地址反推模数，
//! 因此 `BuildTransferRequest::public_key` 在 AR 上是**必填**的。

pub mod adapter;
pub mod network;
pub mod tx;
