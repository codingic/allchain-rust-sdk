//! 统一链能力 trait：四链适配器共同实现的查询与转账契约。

use async_trait::async_trait;

use crate::{
    AddressView, BalanceView, BlockView, ChainKind, SdkError, StatusView, TransferRequest,
    TransferView, TxView,
};

/// 一条链的最小可用能力集。
///
/// 只读查询为必实现项；`transfer`（签名广播）由支持写操作的链实现，
/// 未实现的链走默认分支返回 `UNSUPPORTED`，不影响既有调用方。
#[async_trait]
pub trait ChainClient: Send + Sync {
    /// 所属链。
    fn kind(&self) -> ChainKind;

    /// 当前连接的网络名，如 `mainnet` / `testnet` / `devnet` / `sepolia`。
    fn network(&self) -> &str;

    /// 实际使用的 RPC 端点，便于调用方判断是否打到了预期节点。
    fn rpc_url(&self) -> &str;

    /// 链与节点状态。
    async fn status(&self) -> Result<StatusView, SdkError>;

    /// 查询地址/账户余额。
    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError>;

    /// 查询区块。`reference` 为 `None` 时取最新区块；否则可以是高度或哈希，
    /// 具体支持形式由各链适配器决定并在错误中说明。
    async fn block(&self, reference: Option<&str>) -> Result<BlockView, SdkError>;

    /// 查询交易。
    async fn tx(&self, hash: &str) -> Result<TxView, SdkError>;

    /// 由公钥派生地址。**纯本地计算**，不访问 RPC。
    ///
    /// - 公钥的编码格式由各链适配器自行规定，并在错误信息中说明；
    /// - 返回值里的 `network` 仍取当前客户端的网络，因为 BTC 的 bech32 hrp
    ///   与 base58 版本字节随网络而变；
    /// - 默认实现返回 `UNSUPPORTED`，新链接入时可以选择不实现。
    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        // 默认分支不消费参数，显式绑定以避免误用。
        let _ = pubkey;
        Err(SdkError::unsupported(format!(
            "{} 尚不支持由公钥派生地址",
            self.kind()
        )))
    }

    /// 转账：本地构造、签名并广播（`dry_run` 为 `true` 时只签名不广播）。
    ///
    /// 私钥只参与本地签名，不离开本进程。金额为人类可读原生单位。
    /// 默认返回 `UNSUPPORTED`，支持写操作的链才需要实现。
    async fn transfer(&self, req: TransferRequest) -> Result<TransferView, SdkError> {
        // 默认分支不消费参数，显式绑定以避免误用。
        let _ = req;
        Err(SdkError::unsupported(format!(
            "{} 尚不支持转账",
            self.kind()
        )))
    }
}
