//! allchain-core：跨链统一契约层。
//!
//! 定义四链共有的数据模型、错误码与 [`ChainClient`] 能力 trait，
//! 使外部调用方只需面对一套接口，无需了解各链 SDK 的差异。

pub mod chain;
pub mod envelope;
pub mod error;
pub mod hexutil;
pub mod model;
pub mod traits;

pub use chain::ChainKind;
pub use envelope::Envelope;
pub use error::{ErrorCode, SdkError};
pub use model::{
    AddressView, BalanceView, BlockView, StatusView, TransferRequest, TransferView, TxStatus,
    TxView,
};
pub use traits::ChainClient;
