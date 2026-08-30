//! ckb-sdk：基于 Nervos CKB JSON-RPC 的链能力库，实现统一 `ChainClient` 契约。
//!
//! 领域背景（CKB 与其余九条链最大的不同）：
//! - 它是 **UTXO 模型的变体**——「Cell」模型。Cell 有四个字段：
//!   `capacity`（容量，字节数，同时就是金额）、`data`、`type script`、`lock script`。
//!   没有「账户余额」这个概念，余额 = 该 lock script 名下所有 **live cell** 的 capacity 之和。
//!   这就是为什么 `balance()` 必须走 `get_cells` **翻页累加**而不是一次查询拿到。
//! - 最小单位 `shannon`，精度 8（1 CKB = 10^8 shannon）；Cell 里存的 capacity 单位也是 shannon。
//! - 密钥用 **secp256k1**（与 BTC / ETH 同族，与 APT 的 ed25519、AR 的 RSA 都不同）。
//!
//! 关于依赖：`Cargo.toml` 里列了 `ckb-sdk`，但本 crate 的**运行代码**并未调用它——
//! 请求统一走 `chain_rpcutil::Http` 的 JSON-RPC，地址编解码则是 `address.rs` 里的手写实现
//! （blake160 + bech32/bech32m，约 300 行）。理由：官方 SDK 会拖入 ckb-types、molecule、
//! secp256k1 等一整棵依赖树，而我们只需要四个只读接口 + 地址编解码。
//!
//! 不过 `ckb-sdk` 被留在 `[dev-dependencies]` 里，是**有意**的：
//! 它只用于 `tests/official_sdk_crosscheck.rs`，充当地址编码的「标准答案」。
//! 手写编解码最大的风险是「自往返通过、但与链上不一致」——
//! bech32 与 bech32m 只差一个常量，编错了自己解码自己永远是对的，
//! 只有跟官方实现对拍才暴露得出来。
//!
//! 明确的能力边界：本 crate **只提供只读查询与本地公钥派生地址**，不支持转账。
//! CKB 转账要收集 live cell、构造 CellDeps、算手续费并签名 witness，
//! 属于写路径，当前未实现；`ChainClient::transfer` 走 trait 默认分支返回 `UNSUPPORTED`。

pub mod adapter;
pub mod address;
pub mod network;
