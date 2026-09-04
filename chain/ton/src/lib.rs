//! ton-sdk：基于 toncenter REST v2 的链能力库，实现统一 `ChainClient` 契约。
//!
//! 模块划分：
//! - `adapter` —— `ChainClient` trait 的实现，是唯一对外暴露的门面；
//! - `network` —— 预置网络与 REST 端点。
//!
//! 能力边界（三条新链里最窄的一条）：**只提供只读查询**。
//!
//! **不实现 `address_from_pubkey` 的原因**：TON 的地址是钱包合约
//! **StateInit** 的哈希，而 StateInit 由 workchain、初始数据（含公钥）
//! 与**合约代码**三部分共同决定。同一把公钥配上不同版本的钱包合约
//! （V3 / V4R2 / W5 …）会得到完全不同的地址，因此「公钥 → 地址」不是函数。
//! 这条限制同样影响转账：必须先知道用的是哪版钱包合约，才能构造出合法的外部消息。
//! 调用 `address_from_pubkey` 会走 trait 默认实现返回 `UNSUPPORTED`。

/// 链能力实现：`ChainClient` trait 的 TON 版本。
pub mod adapter;
/// 预置网络与端点常量。
pub mod network;
/// 无私钥转账构造：外部消息 body 拼装、待签哈希计算、签名区定位与回填。
///
/// 抽成独立模块的原因：TON 的交易是 **cell 树**而非扁平字节，
/// 「签名放在第几个字节」随钱包版本而变。把这些易错的序列化细节
/// 收在纯函数里，才能脱离网络做逐字节的断言。
pub mod tx;
