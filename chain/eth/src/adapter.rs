//! eth 链对统一 `ChainClient` 契约的实现。
//!
//! 复用 [`crate::queries`] 的参数解析逻辑，但把结果映射为 core 定义的结构化视图，
//! 不再直接打印。

use std::str::FromStr;

use alloy::consensus::Transaction as _;
use alloy::eips::BlockId;
use alloy::network::{ReceiptResponse, TransactionResponse};
use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::types::Transaction;
use async_trait::async_trait;
use serde_json::json;

use allchain_core::{
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, SdkError, StatusView,
    TransferRequest, TransferView, TxStatus, TxView, hexutil,
};

use crate::network::{self, NetworkArg};
use crate::queries::parse_block_reference;

/// ETH 链客户端。持有一个只读 HTTP Provider，可安全并发复用。
pub struct EthClient {
    network: String,
    rpc_url: String,
    provider: RootProvider,
}

impl EthClient {
    /// 构造客户端。`network` 为 `mainnet` / `sepolia` / `localnet`，
    /// 缺省用 `mainnet`；显式给出 `rpc_url` 时优先使用，网络名标记为 `custom`。
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let (network_name, url) = match custom {
            Some(url) => ("custom".to_string(), url),
            None => {
                let net = parse_network(network)?;
                (net.as_str().to_string(), net.rpc_url().to_string())
            }
        };

        let provider = network::connect(&url).map_err(|e| fail("连接 RPC 端点失败", e))?;
        Ok(Self {
            network: network_name,
            rpc_url: url,
            provider,
        })
    }

    fn fail(&self, context: &str, err: impl std::fmt::Display) -> SdkError {
        fail(context, err)
    }
}

fn parse_network(raw: Option<&str>) -> Result<NetworkArg, SdkError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(NetworkArg::Mainnet),
        Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("sepolia") => Ok(NetworkArg::Sepolia),
        Some("localnet") => Ok(NetworkArg::Localnet),
        Some(other) => Err(SdkError::invalid_argument(format!(
            "ETH 不支持的网络: {other}（可选 mainnet / sepolia / localnet）"
        ))),
    }
}

fn fail(context: &str, err: impl std::fmt::Display) -> SdkError {
    allchain_core::error::classify(&format!("{context}: {err}"))
}

#[async_trait]
impl ChainClient for EthClient {
    fn kind(&self) -> ChainKind {
        ChainKind::Eth
    }

    fn network(&self) -> &str {
        &self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        let version = self
            .provider
            .get_client_version()
            .await
            .map_err(|e| self.fail("查询客户端版本失败", e))?;
        let chain_id = self
            .provider
            .get_chain_id()
            .await
            .map_err(|e| self.fail("查询链 ID 失败", e))?;
        let block = self
            .provider
            .get_block(BlockId::latest())
            .await
            .map_err(|e| self.fail("查询最新区块失败", e))?
            .ok_or_else(|| SdkError::not_found("节点未返回最新区块"))?;

        Ok(
            StatusView::new(ChainKind::Eth, &self.network, &self.rpc_url)
                .with_height(block.header.number)
                .with_hash(block.header.hash.to_string())
                .with_version(version)
                .with_extra(json!({ "chain_id": chain_id })),
        )
    }

    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        let addr = parse_address(address)?;
        let balance = self
            .provider
            .get_balance(addr)
            .await
            .map_err(|e| self.fail("查询余额失败", e))?;
        let raw = to_u128(balance)?;
        Ok(BalanceView::new(
            ChainKind::Eth,
            &self.network,
            address,
            raw,
        ))
    }

    async fn block(&self, reference: Option<&str>) -> Result<BlockView, SdkError> {
        let block_id = parse_block_reference(reference)
            .map_err(|e| SdkError::invalid_argument(e.to_string()))?;
        let block = self
            .provider
            .get_block(block_id)
            .await
            .map_err(|e| self.fail("查询区块失败", e))?
            .ok_or_else(|| {
                SdkError::not_found("节点未返回该区块（高度超前或不存在，历史区块需归档节点）")
            })?;

        let header = &block.header;
        Ok(
            BlockView::new(ChainKind::Eth, &self.network, header.hash.to_string())
                .with_height(header.number)
                .with_parent(header.parent_hash.to_string())
                .with_timestamp(header.timestamp as i64)
                .with_tx_count(block.transactions.len() as u64)
                .with_extra(json!({
                    "miner": header.beneficiary.to_string(),
                    "gas_used": header.gas_used,
                    "gas_limit": header.gas_limit,
                })),
        )
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        let tx_hash = parse_hash(hash)?;
        let tx: Option<Transaction> = self
            .provider
            .get_transaction_by_hash(tx_hash)
            .await
            .map_err(|e| self.fail("查询交易失败", e))?;
        let tx = tx.ok_or_else(|| {
            SdkError::not_found("交易不在该节点数据中，历史交易请使用归档节点端点")
        })?;

        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|e| self.fail("查询交易回执失败", e))?;

        let status = match &receipt {
            Some(r) if r.status() => TxStatus::Success,
            Some(_) => TxStatus::Failed,
            None => TxStatus::Pending,
        };

        let mut view = TxView::new(ChainKind::Eth, &self.network, hash, status)
            .with_from(tx.from().to_string())
            .with_amount(to_u128(tx.value())?);

        if let Some(to) = tx.to() {
            view = view.with_to(to.to_string());
        }
        if let Some(height) = tx.block_number() {
            view = view.with_height(height);
        }
        if let Some(r) = &receipt {
            let fee = r.gas_used() as u128 * r.effective_gas_price();
            view = view.with_fee(fee).with_extra(json!({
                "nonce": tx.nonce(),
                "gas_used": r.gas_used(),
                "input_bytes": tx.input().len(),
            }));
        }

        Ok(view)
    }

    async fn transfer(&self, req: TransferRequest) -> Result<TransferView, SdkError> {
        let to = parse_address(&req.to)?;
        let value = crate::units::parse_amount(&req.amount, "ether")
            .map_err(|e| SdkError::invalid_argument(format!("非法金额: {e}")))?;
        let amount_raw = to_u128(value)?;
        let signer = crate::transactions::parse_signer(&req.private_key)
            .map_err(|e| SdkError::invalid_argument(e.to_string()))?;
        let from = signer.address().to_string();

        if req.dry_run {
            let signed =
                crate::transactions::build_signed_transfer(&self.rpc_url, &signer, to, value)
                    .await
                    .map_err(|e| self.fail("本地签名转账失败", e))?;
            return Ok(TransferView::new(
                ChainKind::Eth,
                &self.network,
                Some(from),
                req.to,
                amount_raw,
                Some(signed.tx_hash.to_string()),
                false,
            )
            .with_extra(json!({
                "signed_raw": signed.signed_raw,
                "chain_id": signed.chain_id,
                "nonce": signed.nonce,
                "max_fee_gwei": crate::units::format_wei(U256::from(signed.max_fee_per_gas), 9),
                "max_priority_fee_gwei": crate::units::format_wei(U256::from(signed.max_priority_fee_per_gas), 9),
            })));
        }

        let (tx_hash, success, block_number, gas_used) =
            crate::transactions::transfer_silent(&self.rpc_url, signer, to, value)
                .await
                .map_err(|e| self.fail("广播转账失败", e))?;

        Ok(TransferView::new(
            ChainKind::Eth,
            &self.network,
            Some(from),
            req.to,
            amount_raw,
            Some(tx_hash.to_string()),
            true,
        )
        .with_extra(json!({
            "success": success,
            "block_number": block_number,
            "gas_used": gas_used,
        })))
    }

    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        let coords = parse_uncompressed_pubkey(pubkey)?;
        let address = address_from_coords(&coords);

        Ok(AddressView::new(
            ChainKind::Eth,
            &self.network,
            hexutil::encode_hex_prefixed(&coords),
            address.to_checksum(None),
            "eoa",
            coords.len(),
        )
        .with_extra(json!({
            "lowercase": hexutil::encode_hex_prefixed(address.as_slice()),
            "derivation": "keccak256(uncompressed_pubkey)[12..32]",
        })))
    }
}

/// 解析未压缩 secp256k1 公钥。
///
/// 接受两种十六进制写法：65 字节带 `04` 前缀（标准 SEC1 未压缩格式），
/// 或 64 字节裸坐标（x || y）。带 `0x` 前缀与否均可。
fn parse_uncompressed_pubkey(raw: &str) -> Result<[u8; 64], SdkError> {
    let bytes = hexutil::decode_hex(raw)?;
    match bytes.len() {
        65 if bytes[0] == 0x04 => slice64(&bytes[1..], raw),
        65 => Err(SdkError::invalid_argument(format!(
            "ETH 公钥的 65 字节格式必须以 04 开头（未压缩标志），实际以 {:02x} 开头；\
             若这是压缩公钥（02/03 开头），请先解压成 64 字节坐标",
            bytes[0]
        ))),
        64 => slice64(&bytes, raw),
        33 => Err(SdkError::invalid_argument(
            "ETH 不支持压缩公钥：请先解压为 64 字节坐标（x || y）".to_string(),
        )),
        other => Err(SdkError::invalid_argument(format!(
            "ETH 公钥需为 64 字节坐标或 65 字节带 04 前缀的十六进制，实际 {other} 字节"
        ))),
    }
}

fn slice64(bytes: &[u8], raw: &str) -> Result<[u8; 64], SdkError> {
    bytes.try_into().map_err(|_| {
        SdkError::new(
            allchain_core::ErrorCode::Internal,
            format!("公钥切片长度异常: {raw}"),
        )
    })
}

/// 地址 = keccak256(未压缩公钥去掉 04 前缀)[12..32]。
fn address_from_coords(coords: &[u8; 64]) -> Address {
    let hash = keccak256(coords);
    Address::from_slice(&hash[12..])
}

fn parse_address(raw: &str) -> Result<Address, SdkError> {
    Address::from_str(raw.trim()).map_err(|_| {
        SdkError::invalid_argument(format!("非法 ETH 地址: {raw}（期望 0x + 40 位十六进制）"))
    })
}

fn parse_hash(raw: &str) -> Result<B256, SdkError> {
    B256::from_str(raw.trim()).map_err(|_| {
        SdkError::invalid_argument(format!("非法交易哈希: {raw}（期望 0x + 64 位十六进制）"))
    })
}

fn to_u128(value: alloy::primitives::U256) -> Result<u128, SdkError> {
    u128::try_from(value)
        .map_err(|_| SdkError::new(allchain_core::ErrorCode::ParseError, "金额超出 u128 范围"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 私钥 0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318 的公钥。
    // 向量由独立的纯 Python 实现（secp256k1 点乘已用 2G/3G/nG 校验，Keccak 已用
    // 空串与 "abc" 公开向量校验）交叉验证过。
    const COORDS_HEX: &str = "4e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de";
    const UNCOMPRESSED_HEX: &str = "044e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de";
    const EXPECT_CHECKSUM: &str = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23";
    const EXPECT_LOWER: &str = "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23";

    #[test]
    fn derives_address_from_64_byte_coords() {
        let coords = parse_uncompressed_pubkey(COORDS_HEX).unwrap();
        assert_eq!(coords.len(), 64);
        assert_eq!(
            address_from_coords(&coords).to_checksum(None),
            EXPECT_CHECKSUM
        );
    }

    #[test]
    fn address_matches_keccak_last_20_bytes() {
        let coords = parse_uncompressed_pubkey(COORDS_HEX).unwrap();
        let hash = keccak256(coords);
        let address = Address::from_slice(&hash[12..]);
        assert_eq!(
            hexutil::encode_hex_prefixed(address.as_slice()),
            EXPECT_LOWER
        );
        assert_eq!(address.to_checksum(None), EXPECT_CHECKSUM);
    }

    #[test]
    fn accepts_uncompressed_prefix_and_0x() {
        let a = parse_uncompressed_pubkey(UNCOMPRESSED_HEX).unwrap();
        let b = parse_uncompressed_pubkey(&format!("0x{COORDS_HEX}")).unwrap();
        let c = parse_uncompressed_pubkey(&COORDS_HEX.to_uppercase()).unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn rejects_compressed_and_bad_length() {
        assert!(parse_uncompressed_pubkey("02").is_err());
        assert!(parse_uncompressed_pubkey(&"ab".repeat(33)).is_err());
        // 65 字节但前缀不是 04 —— 典型的压缩公钥误传
        assert!(parse_uncompressed_pubkey(&format!("02{}", "ab".repeat(64))).is_err());
        let err = parse_uncompressed_pubkey("not-hex").unwrap_err();
        assert!(err.message.contains("非法十六进制"));
    }
}
