//! apt-sdk：基于 Aptos 官方 REST API（v1）的链能力库，实现统一 `ChainClient` 契约。
//!
//! 只读查询（status / balance / block / tx）走 REST；地址派生为纯本地 SHA3-256 计算。
//!
//! ## 依赖的取舍：只读路径与写路径走**两套**实现
//! - **只读查询**（status / balance / block / tx）不碰 `aptos-sdk`，
//!   直接走 `chain_rpcutil::Http` 的 REST GET。理由有二：
//!   1. 官方 SDK 会拖入一整棵依赖树（Move 类型、BCS 序列化、ed25519 实现等），
//!      而四个只读接口用不上它们，代价不成比例；
//!   2. 响应先统一反序列化成 `serde_json::Value` 再按需取字段，
//!      上游字段微调时不必同步维护一大批镜像结构体。
//! - **写路径**（构造 / 签名 / 广播）一律用 `aptos-sdk`。
//!   BCS 编码与 `APTOS::RawTransaction` 签名前缀这类细节**必须**与链上逐字节一致；
//!   手写实现的偏差在广播前不会暴露，代价远高于多引一个依赖。
//!
//! ## 两种转账形态
//! - `ChainClient::transfer`：**一体式**，本进程持有私钥，构造 + 签名 + 广播一次做完；
//! - `ChainClient::build_transfer` + `ChainClient::submit_tx`：**两段式**，
//!   SDK 只负责组装与广播，签名权留在调用方手里（见 [`tx`] 模块）。
//!   注意 Aptos 的地址是 `sha3_256(公钥 || 0x00)`，哈希不可逆，
//!   因此两段式的 `build_transfer` **必须**由调用方显式给出 `public_key`。

// `pub mod` 把这个模块暴露给 crate 外。`mod` 本身是私有可见性，加 `pub` 才对外可见。
pub mod adapter;
pub mod network;
/// 交易的「无私钥」构造与广播（两段式流程的第一段与第三段）。
pub mod tx;
