//! allchain-core：跨链统一契约层。
//!
//! 定义四链共有的数据模型、错误码与 [`ChainClient`] 能力 trait，
//! 使外部调用方只需面对一套接口，无需了解各链 SDK 的差异。
//!
//! 本文件是 crate 的**根模块**（crate root）。它只做两件事：
//! 1. 用 `pub mod` 声明有哪些子模块；
//! 2. 用 `pub use` 把各子模块里最常用的类型**重导出**（re-export）到根路径。
//!    之所以要做第 2 步：调用方写 `allchain_core::SdkError` 就够了，
//!    不必知道它实际定义在 `allchain_core::error` 里。这样以后调整内部文件划分，
//!    只要重导出不变，就不会破坏外部代码。

/// 链标识与元信息（`ChainKind`、能力清单、金额格式化）。
pub mod chain;
/// 统一响应信封 `Envelope<T>`：CLI / HTTP / MCP 共用的输出结构。
pub mod envelope;
/// 统一错误码 `ErrorCode` 与错误载体 `SdkError`。
pub mod error;
/// 十六进制编解码工具，各链适配器共用。
pub mod hexutil;
/// 跨链统一数据模型（`StatusView` / `BalanceView` / `BlockView` / `TxView` …）。
pub mod model;
/// 统一链能力 trait `ChainClient`。
pub mod traits;

// 以下是重导出。`pub use` 把「某个路径下的条目」在**当前模块**再暴露一次，
// 于是这些类型同时拥有两个可用路径：`allchain_core::error::SdkError`
// 与 `allchain_core::SdkError`。
pub use chain::ChainKind;
// `parse_units` 是 `format_units` 的逆运算，六条新链的 `transfer` 都依赖它把人类可读金额
// 解析成最小单位整数；重导出到根路径，调用方写 `allchain_core::parse_units` 即可。
pub use chain::parse_units;
pub use envelope::Envelope;
pub use error::{ErrorCode, SdkError};
// 大括号里可以一次导入多个条目，不必写多行 `pub use`。
pub use model::{
    AddressView, BalanceView, BlockView, BuildTransferRequest, BuildTransferView, StatusView,
    SubmitRequest, SubmitView, TransferRequest, TransferView, TxStatus, TxView,
};
// `ChainClient` 是 trait，重导出方式与 struct / enum 完全一致。
pub use traits::ChainClient;
