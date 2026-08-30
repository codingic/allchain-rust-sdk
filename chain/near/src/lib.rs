//! near-sdk：基于 near-jsonrpc-client 0.22 的链能力库。
//!
//! ## 依赖版本配对（改动前务必先读）
//! near 官方把 SDK 拆成了 **多个独立演进的 crate**，且版本号并不同步：
//! 本 crate 用的是 `near-jsonrpc-client 0.22` + `near-primitives 0.37` + `near-crypto 0.37`。
//! `near-jsonrpc-client` 的内部就依赖 `near-primitives`，**两边版本不一致会在编译期
//! 报「类型来自不同版本的 crate」这类极难读懂的错误**，升级时必须成套升。
//!
//! ## NEAR 的三个关键概念
//! 1. **具名账户（named account）**：NEAR 没有「地址」，账户是一个**人类可读的名字**
//!    （`alice.near`、`bob.testnet`），链上按名字索引。
//!    这与 ETH / BTC / SOL 那种「公钥的哈希/编码」模型完全不同，
//!    也意味着统一契约里的 `address` 参数在 NEAR 上传的是**账户名**。
//! 2. **yoctoNEAR**：最小单位，1 NEAR = 10^24 yoctoNEAR（24 位小数）。
//!    这个量级**超出 f64 的 53 位有效位**，也超出 u64，
//!    因此金额一律用 `u128` 或字符串承载，绝不能过浮点。
//! 3. **访问密钥（AccessKey）**：账户下可以挂多把不同权限的密钥，
//!    交易用「账户 ID + 公钥 + nonce」标识，nonce 是**每把密钥**独立递增的
//!    （不是每个账户一个），这与 EVM 的账户 nonce 不同。
//!
//! ## 模块分层
//! - [`network`]      ：网络端点、RPC 客户端构造，以及 `wait_until` 的 CLI 枚举；
//! - [`queries`]      ：只读查询（status / view_account / view_access_key / block / tx / call_function）；
//! - [`transactions`] ：交易构造、离线签名与广播；
//! - [`units`]        ：yoctoNEAR / TGas 的单位换算；
//! - [`adapter`]      ：实现 core 的 `ChainClient` trait，统一门面唯一会用到的入口。
//!
//! 与 SOL 那一侧不同，NEAR 的官方 JSON-RPC 客户端**本身就是 async 的**，
//! 所以这里不需要 `spawn_blocking` 那层包装。

/// 对 core 的 `ChainClient` trait 的实现，统一门面通过它访问本链。
pub mod adapter;
/// 网络端点、`wait_until` 枚举与 RPC 客户端构造。
pub mod network;
/// 只读查询（status / view_account / view_access_key / block / tx / call_function）。
pub mod queries;
/// 交易构造、离线签名与广播。
pub mod transactions;
/// NEAR / yoctoNEAR / TGas 的单位换算。
pub mod units;
