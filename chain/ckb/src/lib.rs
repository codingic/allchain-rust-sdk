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
//! 关于依赖：`Cargo.toml` 里列了 `ckb-sdk`（重命名为 `official-ckb-sdk` 以避开本
//! crate 的 `[lib] name = "ckb_sdk"` 撞名）。它现在**同时**用于两处：
//! - 地址编解码的对拍（`tests/official_sdk_crosscheck.rs`）。
//!   手写编解码最大的风险是「自往返通过、但与链上不一致」——
//!   bech32 与 bech32m 只差一个常量，编错了自己解码自己永远是对的，
//!   只有跟官方实现对拍才暴露得出来。
//! - 转账路径（`adapter.rs` + `tx.rs`）：cell 收集、容量平衡、witness 签名摘要。
//!   这些逻辑踩错一字节就会产出「能广播、但节点永远拒收」的交易，
//!   手写不划算。其中「待签摘要」直接调用官方 `unlock::generate_message`，
//!   本 crate 不复刻哈希拼接。
//!
//! 转账有两条路径：
//! - 一体式 `transfer`：私钥进 SDK，包办构造 + 签名 + 广播；
//! - 两段式 `build_transfer` / `submit_tx`：**私钥不进 SDK**，
//!   SDK 只负责构造与广播，签名留给调用方（agent）。
//!
//! 两条路径共用 `tx` 模块里的纯函数与同一批官方组件，
//! 因此产出的交易字节完全一致（`tx.rs` 里有逐字节对拍测试）。

pub mod adapter;
pub mod address;
pub mod network;
pub mod tx;
