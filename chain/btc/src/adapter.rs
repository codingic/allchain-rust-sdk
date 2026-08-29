//! btc 链对统一 `ChainClient` 契约的实现。
//!
//! 直接复用 `backend::Chain` 已有的双数据源（Esplora 索引器 / 自建 bitcoind）能力，
//! 把其 View 结构映射为 core 的统一模型。

use async_trait::async_trait;
use bitcoin::address::NetworkUnchecked;
use bitcoin::key::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, Network, PublicKey};
use serde_json::json;

use allchain_core::{
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, SdkError, StatusView,
    TransferRequest, TransferView, TxStatus, TxView, hexutil,
};

use crate::backend::Chain;
use crate::network::NetworkArg;

/// BTC 客户端。地址/UTXO 类查询必须有索引器，默认走 Esplora。
pub struct BtcClient {
    network: String,
    rpc_url: String,
    chain: Chain,
}

impl BtcClient {
    /// `rpc_url` 对 BTC 而言是 **Esplora 索引器地址**（不是 JSON-RPC 端点）；
    /// 提供时覆盖当前网络的默认索引器。
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        let net = parse_network(network)?;
        let esplora = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| net.esplora_url().to_string());

        let chain = Chain::new(net, &esplora, None).map_err(|e| fail("初始化链数据源失败", e))?;
        let rpc_url = chain.endpoint();
        Ok(Self {
            network: net.to_string(),
            rpc_url,
            chain,
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
        Some("testnet") => Ok(NetworkArg::Testnet),
        Some("testnet4") => Ok(NetworkArg::Testnet4),
        Some("signet") => Ok(NetworkArg::Signet),
        Some("regtest") => Ok(NetworkArg::Regtest),
        Some(other) => Err(SdkError::invalid_argument(format!(
            "BTC 不支持的网络: {other}（可选 mainnet / testnet / testnet4 / signet / regtest）"
        ))),
    }
}

fn fail(context: &str, err: impl std::fmt::Display) -> SdkError {
    allchain_core::error::classify(&format!("{context}: {err}"))
}

#[async_trait]
impl ChainClient for BtcClient {
    fn kind(&self) -> ChainKind {
        ChainKind::Btc
    }

    fn network(&self) -> &str {
        &self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        let v = self
            .chain
            .status()
            .await
            .map_err(|e| self.fail("查询链状态失败", e))?;
        Ok(
            StatusView::new(ChainKind::Btc, &self.network, &self.rpc_url)
                .with_height(v.blocks)
                .with_hash(v.best_block_hash)
                .with_extra(json!({
                    "source": v.source,
                    "difficulty": v.difficulty,
                    "mempool_txs": v.mempool_txs,
                    "mempool_bytes": v.mempool_bytes,
                    "headers": v.headers,
                    "median_time": v.median_time,
                })),
        )
    }

    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        let v = self
            .chain
            .address(address)
            .await
            .map_err(|e| self.fail("查询地址失败", e))?;
        Ok(BalanceView::new(
            ChainKind::Btc,
            &self.network,
            address,
            v.confirmed_balance as u128,
        )
        .with_extra(json!({
            "unconfirmed_balance": v.unconfirmed_balance,
            "tx_count": v.tx_count,
            "total_received": v.total_received,
            "total_sent": v.total_sent,
            "funded_txo_count": v.funded_txo_count,
            "spent_txo_count": v.spent_txo_count,
        })))
    }

    async fn block(&self, reference: Option<&str>) -> Result<BlockView, SdkError> {
        let v = self
            .chain
            .block(reference)
            .await
            .map_err(|e| self.fail("查询区块失败", e))?;

        let mut view = BlockView::new(ChainKind::Btc, &self.network, v.hash)
            .with_height(v.height)
            .with_timestamp(v.timestamp as i64)
            .with_tx_count(v.tx_count);
        if let Some(prev) = v.prev_hash {
            view = view.with_parent(prev);
        }
        Ok(view.with_extra(json!({
            "size": v.size,
            "weight": v.weight,
            "merkle_root": v.merkle_root,
            "nonce": v.nonce,
            "difficulty": v.difficulty,
            "confirmations": v.confirmations,
            "next_hash": v.next_hash,
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        let v = self
            .chain
            .tx(hash)
            .await
            .map_err(|e| self.fail("查询交易失败", e))?;

        let status = if v.confirmed {
            TxStatus::Success
        } else {
            TxStatus::Pending
        };
        let mut view = TxView::new(ChainKind::Btc, &self.network, hash, status);

        // BTC 以 UTXO 为模型，没有单一的「付款账户」；取首个非 coinbase 输入作为概览。
        if let Some(addr) = v
            .inputs
            .iter()
            .find(|i| !i.coinbase)
            .and_then(|i| i.address.clone())
        {
            view = view.with_from(addr);
        }
        if let Some(addr) = v.outputs.first().and_then(|o| o.address.clone()) {
            view = view.with_to(addr);
        }
        if let Some(fee) = v.fee {
            view = view.with_fee(fee as u128);
        }
        if let Some(height) = v.block_height {
            view = view.with_height(height);
        }
        if let Some(time) = v.block_time {
            view = view.with_timestamp(time as i64);
        }
        if let Some(confirmations) = v.confirmations {
            view = view.with_confirmations(confirmations);
        }

        // 金额语义在多输入输出下不适用，完整明细放在 extra 里由调用方自行计算。
        let inputs: Vec<_> = v
            .inputs
            .iter()
            .map(|i| {
                json!({
                    "txid": i.txid,
                    "vout": i.vout,
                    "value": i.value,
                    "address": i.address,
                    "script_type": i.script_type,
                    "coinbase": i.coinbase,
                })
            })
            .collect();
        let outputs: Vec<_> = v
            .outputs
            .iter()
            .map(|o| {
                json!({
                    "index": o.index,
                    "value": o.value,
                    "address": o.address,
                    "script_type": o.script_type,
                })
            })
            .collect();

        Ok(view.with_extra(json!({
            "size": v.size,
            "weight": v.weight,
            "vsize": v.vsize,
            "version": v.version,
            "locktime": v.locktime,
            "inputs": inputs,
            "outputs": outputs,
        })))
    }

    async fn transfer(&self, req: TransferRequest) -> Result<TransferView, SdkError> {
        let network = self.chain.network().network();
        let to = req
            .to
            .trim()
            .parse::<Address<NetworkUnchecked>>()
            .map_err(|_| SdkError::invalid_argument(format!("非法 BTC 地址: {}", req.to)))?
            .require_network(network)
            .map_err(|e| SdkError::invalid_argument(format!("地址网络不匹配: {e}")))?;

        let amount_sat = crate::units::parse_amount(&req.amount)
            .map_err(|e| SdkError::invalid_argument(format!("非法金额: {e}")))?;

        let built = crate::transactions::build_transfer(
            &self.chain,
            &req.private_key,
            &to,
            amount_sat,
            None,
            false,
            false,
        )
        .await
        .map_err(|e| self.fail("构造签名转账失败", e))?;

        let txid = if req.dry_run {
            built.txid.clone()
        } else {
            self.chain
                .broadcast(&built.raw_hex)
                .await
                .map_err(|e| self.fail("广播交易失败", e))?
        };

        let inputs: Vec<_> = built
            .inputs
            .iter()
            .map(|i| {
                json!({
                    "txid": i.txid,
                    "vout": i.vout,
                    "value": i.value,
                    "confirmed": i.confirmed,
                })
            })
            .collect();

        Ok(TransferView::new(
            ChainKind::Btc,
            &self.network,
            Some(built.from.clone()),
            req.to,
            amount_sat as u128,
            Some(txid),
            !req.dry_run,
        )
        .with_extra(json!({
            "fee_sat": built.fee,
            "fee_rate_sat_vb": built.fee_rate,
            "vsize": built.vsize,
            "change_sat": built.change,
            "inputs": inputs,
            "raw_tx": built.raw_hex,
        })))
    }

    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        let raw = hexutil::decode_hex(pubkey)?;
        let pk = PublicKey::from_slice(&raw).map_err(|e| {
            SdkError::invalid_argument(format!(
                "非法 BTC 公钥（{e}）：需为 33 字节压缩格式（02/03 开头）或 65 字节未压缩格式的十六进制"
            ))
        })?;
        let compressed = CompressedPublicKey::try_from(pk).map_err(|_| {
            SdkError::invalid_argument(
                "BTC 需要压缩公钥（33 字节，02/03 开头）才能派生隔离见证地址；\
                 未压缩公钥请先压缩，或改用 P2PKH"
                    .to_string(),
            )
        })?;

        let network: Network = self.chain.network().network();
        let secp = Secp256k1::new();
        let compressed_bytes = compressed.to_bytes();
        let p2wpkh = Address::p2wpkh(&compressed, network);

        Ok(AddressView::new(
            ChainKind::Btc,
            &self.network,
            hexutil::encode_hex(&compressed_bytes),
            p2wpkh.to_string(),
            "p2wpkh",
            compressed_bytes.len(),
        )
        .with_extra(json!({
            "derivation": "hash160(compressed_pubkey) -> bech32/base58check",
        }))
        .with_alternatives(json!({
            "p2pkh": Address::p2pkh(pk.pubkey_hash(), network).to_string(),
            "p2sh_p2wpkh": Address::p2shwpkh(&compressed, network).to_string(),
            "p2tr": Address::p2tr(&secp, compressed.0.into(), None, network).to_string(),
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 私钥 0x0000...0001 对应的压缩公钥（bitcoin 测试向量）。
    const COMPRESSED: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const UNCOMPRESSED: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    fn derive(hex_pubkey: &str, network: Network) -> Result<AddressView, SdkError> {
        let raw = hexutil::decode_hex(hex_pubkey)?;
        let pk =
            PublicKey::from_slice(&raw).map_err(|e| SdkError::invalid_argument(e.to_string()))?;
        let compressed = CompressedPublicKey::try_from(pk)
            .map_err(|_| SdkError::invalid_argument("需要压缩公钥"))?;
        let secp = Secp256k1::new();
        let bytes = compressed.to_bytes();
        Ok(AddressView::new(
            ChainKind::Btc,
            "mainnet",
            hexutil::encode_hex(&bytes),
            Address::p2wpkh(&compressed, network).to_string(),
            "p2wpkh",
            bytes.len(),
        )
        .with_alternatives(json!({
            "p2pkh": Address::p2pkh(pk.pubkey_hash(), network).to_string(),
            "p2tr": Address::p2tr(&secp, compressed.0.into(), None, network).to_string(),
        })))
    }

    #[test]
    fn derives_known_mainnet_addresses() {
        let view = derive(COMPRESSED, Network::Bitcoin).unwrap();
        // 生成器点 G 的 P2WPKH 地址（mempool.space / bitcoin 库一致的输出）。
        assert_eq!(view.address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let alt = view.extra.get("alternatives").unwrap();
        assert_eq!(alt["p2pkh"], "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    #[test]
    fn testnet_uses_tb1_prefix() {
        let view = derive(COMPRESSED, Network::Testnet).unwrap();
        assert!(view.address.starts_with("tb1q"));
    }

    #[test]
    fn rejects_uncompressed_and_garbage() {
        assert!(derive(UNCOMPRESSED, Network::Bitcoin).is_err());
        assert!(derive("02abcd", Network::Bitcoin).is_err());
    }
}
