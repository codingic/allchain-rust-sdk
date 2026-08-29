//! 链上数据源：Esplora 索引器与 bitcoind JSON-RPC 的统一视图。
//!
//! 地址类查询（余额 / UTXO）必须有索引器，统一走 Esplora；
//! 节点类查询（链状态 / 区块 / 交易 / 费率 / 广播）在配置了 bitcoind 时优先走 RPC。

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use bitcoincore_rpc::{Auth, Client, RpcApi};

use crate::esplora::Esplora;
use crate::network::NetworkArg;

/// bitcoind 认证的两种来源。
#[derive(Debug, Clone)]
pub enum NodeAuth {
    UserPass { user: String, pass: String },
    Cookie(PathBuf),
}

/// bitcoind JSON-RPC 连接配置。
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub url: String,
    pub auth: NodeAuth,
}

impl NodeConfig {
    /// 建立连接（bitcoind RPC 是阻塞式调用，CLI 场景下直接使用）。
    pub fn connect(&self) -> Result<Client> {
        let auth = match &self.auth {
            NodeAuth::UserPass { user, pass } => Auth::UserPass(user.clone(), pass.clone()),
            NodeAuth::Cookie(path) => Auth::CookieFile(path.clone()),
        };
        Client::new(&self.url, auth).with_context(|| format!("连接 bitcoind 失败: {}", self.url))
    }
}

/// 统一的链上数据源。
pub struct Chain {
    network: NetworkArg,
    esplora: Esplora,
    node: Option<NodeConfig>,
}

impl Chain {
    pub fn new(network: NetworkArg, esplora_url: &str, node: Option<NodeConfig>) -> Result<Self> {
        Ok(Self {
            network,
            esplora: Esplora::new(esplora_url)?,
            node,
        })
    }

    pub fn network(&self) -> NetworkArg {
        self.network
    }

    /// 节点类查询当前实际使用的数据源。
    pub fn source(&self) -> &'static str {
        if self.node.is_some() {
            "bitcoind"
        } else {
            "esplora"
        }
    }

    /// 节点类查询当前实际访问的端点。
    pub fn endpoint(&self) -> String {
        match &self.node {
            Some(node) => node.url.clone(),
            None => self.esplora.base_url().to_string(),
        }
    }
}

/// 链状态视图。
#[derive(Debug, Clone)]
pub struct StatusView {
    pub source: String,
    pub endpoint: String,
    pub chain: String,
    pub blocks: u64,
    pub headers: Option<u64>,
    pub best_block_hash: String,
    pub difficulty: Option<f64>,
    pub verification_progress: Option<f64>,
    pub initial_block_download: Option<bool>,
    pub median_time: Option<u64>,
    pub mempool_txs: Option<u64>,
    pub mempool_bytes: Option<u64>,
}

/// 区块视图。
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BlockView {
    pub hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub tx_count: u64,
    pub size: Option<u64>,
    pub weight: Option<u64>,
    pub merkle_root: Option<String>,
    pub prev_hash: Option<String>,
    pub next_hash: Option<String>,
    pub nonce: Option<u64>,
    pub bits: Option<String>,
    pub difficulty: Option<f64>,
    pub median_time: Option<u64>,
    pub confirmations: Option<u64>,
}

/// 交易输入视图。
#[derive(Debug, Clone)]
pub struct TxInView {
    pub txid: String,
    pub vout: u32,
    pub value: Option<u64>,
    pub address: Option<String>,
    pub script_type: Option<String>,
    pub coinbase: bool,
}

/// 交易输出视图。
#[derive(Debug, Clone)]
pub struct TxOutView {
    pub index: u32,
    pub value: u64,
    pub address: Option<String>,
    pub script_type: Option<String>,
}

/// 交易视图。
#[derive(Debug, Clone)]
pub struct TxView {
    pub txid: String,
    pub version: i64,
    pub locktime: u64,
    pub size: Option<u64>,
    pub weight: Option<u64>,
    pub vsize: Option<u64>,
    pub fee: Option<u64>,
    pub confirmed: bool,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
    pub block_time: Option<u64>,
    pub confirmations: Option<u64>,
    pub inputs: Vec<TxInView>,
    pub outputs: Vec<TxOutView>,
}

/// UTXO 视图。
#[derive(Debug, Clone)]
pub struct UtxoView {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub confirmed: bool,
    pub block_height: Option<u64>,
    pub block_time: Option<u64>,
}

/// 地址视图。
#[derive(Debug, Clone)]
pub struct AddressView {
    pub address: String,
    pub confirmed_balance: u64,
    /// 未确认变动（正数为待入账，负数为待支出）。
    pub unconfirmed_balance: i64,
    pub tx_count: u64,
    pub funded_txo_count: u64,
    pub spent_txo_count: u64,
    pub total_received: u64,
    pub total_sent: u64,
}

impl Chain {
    /// 链状态：优先 bitcoind，回退 Esplora。
    pub async fn status(&self) -> Result<StatusView> {
        if let Some(node) = &self.node {
            let client = node.connect()?;
            let info = client
                .get_blockchain_info()
                .context("getblockchaininfo 失败")?;
            let mempool = client.get_mempool_info().ok();
            return Ok(StatusView {
                source: "bitcoind".to_string(),
                endpoint: node.url.clone(),
                chain: format!("{:?}", info.chain),
                blocks: info.blocks,
                headers: Some(info.headers),
                best_block_hash: info.best_block_hash.to_string(),
                difficulty: Some(info.difficulty),
                verification_progress: Some(info.verification_progress),
                initial_block_download: Some(info.initial_block_download),
                median_time: Some(info.median_time),
                mempool_txs: mempool.as_ref().map(|m| m.size as u64),
                mempool_bytes: mempool.as_ref().map(|m| m.bytes as u64),
            });
        }

        let (height, hash) = tokio::try_join!(self.esplora.tip_height(), self.esplora.tip_hash())?;
        Ok(StatusView {
            source: "esplora".to_string(),
            endpoint: self.esplora.base_url().to_string(),
            chain: self.network.as_str().to_string(),
            blocks: height,
            headers: None,
            best_block_hash: hash,
            difficulty: None,
            verification_progress: None,
            initial_block_download: None,
            median_time: None,
            mempool_txs: None,
            mempool_bytes: None,
        })
    }

    /// 区块查询：可传区块高度或哈希，缺省取链尖。
    pub async fn block(&self, reference: Option<&str>) -> Result<BlockView> {
        let reference = reference.map(str::trim).filter(|s| !s.is_empty());

        if let Some(node) = &self.node {
            let client = node.connect()?;
            let hash = match reference {
                None => client
                    .get_best_block_hash()
                    .context("getbestblockhash 失败")?,
                Some(r) if is_height(r) => {
                    let height: u64 = r.parse().context("区块高度超出范围")?;
                    client
                        .get_block_hash(height)
                        .with_context(|| format!("getblockhash {height} 失败"))?
                }
                Some(r) => r
                    .parse()
                    .map_err(|e| anyhow::anyhow!("非法区块哈希 {r}: {e}"))?,
            };
            let block = client
                .get_block_info(&hash)
                .with_context(|| format!("getblock {hash} 失败"))?;
            return Ok(BlockView {
                hash: block.hash.to_string(),
                height: block.height as u64,
                timestamp: block.time as u64,
                tx_count: block.n_tx as u64,
                size: Some(block.size as u64),
                weight: Some(block.weight as u64),
                merkle_root: Some(block.merkleroot.to_string()),
                prev_hash: block.previousblockhash.map(|h| h.to_string()),
                next_hash: block.nextblockhash.map(|h| h.to_string()),
                nonce: Some(block.nonce as u64),
                bits: Some(block.bits),
                difficulty: Some(block.difficulty),
                median_time: block.mediantime.map(|t| t as u64),
                confirmations: Some(block.confirmations.max(0) as u64),
            });
        }

        let hash = match reference {
            None => self.esplora.tip_hash().await?,
            Some(r) if is_height(r) => {
                let height: u64 = r.parse().context("区块高度超出范围")?;
                self.esplora.block_hash_at(height).await?
            }
            Some(r) => r.to_string(),
        };
        let block = self.esplora.block(&hash).await?;
        let tip = self.esplora.tip_height().await.ok();
        Ok(BlockView {
            hash: block.id,
            height: block.height,
            timestamp: block.timestamp,
            tx_count: block.tx_count,
            size: block.size,
            weight: block.weight,
            merkle_root: block.merkle_root,
            prev_hash: block.previousblockhash,
            next_hash: None,
            nonce: block.nonce,
            bits: block.bits.map(|b| format!("{b:08x}")),
            difficulty: block.difficulty,
            median_time: block.median_time,
            confirmations: tip.map(|tip| tip.saturating_sub(block.height) + 1),
        })
    }

    /// 交易查询：优先 bitcoind（详尽模式），回退 Esplora。
    pub async fn tx(&self, txid: &str) -> Result<TxView> {
        let txid: bitcoin::Txid = txid
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("非法交易哈希 {txid}: {e}"))?;

        if let Some(node) = &self.node {
            let client = node.connect()?;
            let info = client
                .get_raw_transaction_info(&txid, None)
                .with_context(|| format!("getrawtransaction {txid} 失败"))?;

            let mut inputs = Vec::with_capacity(info.vin.len());
            let mut input_sum: Option<u64> = Some(0);
            for vin in &info.vin {
                let (txid_in, vout) = match (vin.txid, vin.vout) {
                    (Some(t), Some(v)) => (t, v),
                    _ => {
                        inputs.push(TxInView {
                            txid: "coinbase".to_string(),
                            vout: 0,
                            value: None,
                            address: None,
                            script_type: None,
                            coinbase: true,
                        });
                        input_sum = None;
                        continue;
                    }
                };
                // 非 coinbase 输入需要回溯上一笔交易才能知道金额（节点需开启 txindex）。
                let value = prevout_value(&client, txid_in, vout);
                match (value, &mut input_sum) {
                    (Some(v), Some(sum)) => *sum += v,
                    (None, Some(_)) => input_sum = None,
                    _ => {}
                }
                inputs.push(TxInView {
                    txid: txid_in.to_string(),
                    vout,
                    value,
                    address: None,
                    script_type: None,
                    coinbase: false,
                });
            }

            let outputs: Vec<TxOutView> = info
                .vout
                .iter()
                .map(|vout| TxOutView {
                    index: vout.n,
                    value: vout.value.to_sat(),
                    address: vout
                        .script_pub_key
                        .address
                        .clone()
                        .or_else(|| vout.script_pub_key.addresses.first().cloned())
                        .map(|a| a.assume_checked().to_string()),
                    script_type: vout.script_pub_key.type_.as_ref().map(|t| format!("{t:?}")),
                })
                .collect();

            let output_sum: u64 = outputs.iter().map(|o| o.value).sum();
            let fee = input_sum.and_then(|sum| sum.checked_sub(output_sum));

            return Ok(TxView {
                txid: info.txid.to_string(),
                version: info.version as i64,
                locktime: info.locktime as u64,
                size: Some(info.size as u64),
                weight: None,
                vsize: Some(info.vsize as u64),
                fee,
                confirmed: info.confirmations.unwrap_or(0) > 0,
                block_height: None,
                block_hash: info.blockhash.map(|h| h.to_string()),
                block_time: info.blocktime.map(|t| t as u64),
                confirmations: info.confirmations.map(|c| c as u64),
                inputs,
                outputs,
            });
        }

        let tx = self.esplora.tx(&txid.to_string()).await?;
        let tip = self.esplora.tip_height().await.ok();
        Ok(TxView {
            txid: tx.txid,
            version: tx.version as i64,
            locktime: tx.locktime as u64,
            size: tx.size,
            weight: tx.weight,
            vsize: tx.weight.map(|w| w.div_ceil(4)),
            fee: tx.fee,
            confirmed: tx.status.confirmed,
            block_height: tx.status.block_height,
            block_hash: tx.status.block_hash,
            block_time: tx.status.block_time,
            confirmations: match (tx.status.block_height, tip) {
                (Some(h), Some(tip)) => Some(tip.saturating_sub(h) + 1),
                _ => None,
            },
            inputs: tx
                .vin
                .iter()
                .map(|vin| TxInView {
                    txid: vin.txid.clone(),
                    vout: vin.vout,
                    value: vin.prevout.as_ref().map(|p| p.value),
                    address: vin
                        .prevout
                        .as_ref()
                        .and_then(|p| p.scriptpubkey_address.clone()),
                    script_type: vin
                        .prevout
                        .as_ref()
                        .and_then(|p| p.scriptpubkey_type.clone()),
                    coinbase: vin.is_coinbase.unwrap_or(false),
                })
                .collect(),
            outputs: tx
                .vout
                .iter()
                .enumerate()
                .map(|(i, vout)| TxOutView {
                    index: i as u32,
                    value: vout.value,
                    address: vout.scriptpubkey_address.clone(),
                    script_type: vout.scriptpubkey_type.clone(),
                })
                .collect(),
        })
    }

    /// 原始交易 hex：优先 bitcoind，回退 Esplora。
    pub async fn tx_hex(&self, txid: &str) -> Result<String> {
        let parsed: bitcoin::Txid = txid
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("非法交易哈希 {txid}: {e}"))?;
        if let Some(node) = &self.node {
            let client = node.connect()?;
            return client
                .get_raw_transaction_hex(&parsed, None)
                .with_context(|| format!("getrawtransaction {parsed} 失败"));
        }
        self.esplora.tx_hex(&parsed.to_string()).await
    }

    /// 地址 UTXO 列表（需要索引器，bitcoind 全节点不提供地址索引）。
    pub async fn utxos(&self, address: &str) -> Result<Vec<UtxoView>> {
        let utxos = self
            .esplora
            .utxos(address)
            .await
            .with_context(|| format!("查询 {address} 的 UTXO 失败"))?;
        Ok(utxos
            .into_iter()
            .map(|u| UtxoView {
                txid: u.txid,
                vout: u.vout,
                value: u.value,
                confirmed: u.status.confirmed,
                block_height: u.status.block_height,
                block_time: u.status.block_time,
            })
            .collect())
    }

    /// 地址统计（余额 / 收发总额 / 交易数）。
    pub async fn address(&self, address: &str) -> Result<AddressView> {
        let stats = self
            .esplora
            .address(address)
            .await
            .with_context(|| format!("查询地址 {address} 失败"))?;
        let (confirmed_received, confirmed_sent) = (
            stats.chain_stats.funded_txo_sum,
            stats.chain_stats.spent_txo_sum,
        );
        let (pending_received, pending_sent) = (
            stats.mempool_stats.funded_txo_sum,
            stats.mempool_stats.spent_txo_sum,
        );
        Ok(AddressView {
            address: stats.address,
            confirmed_balance: confirmed_received.saturating_sub(confirmed_sent),
            unconfirmed_balance: pending_received as i64 - pending_sent as i64,
            tx_count: stats.chain_stats.tx_count + stats.mempool_stats.tx_count,
            funded_txo_count: stats.chain_stats.funded_txo_count
                + stats.mempool_stats.funded_txo_count,
            spent_txo_count: stats.chain_stats.spent_txo_count
                + stats.mempool_stats.spent_txo_count,
            total_received: confirmed_received + pending_received,
            total_sent: confirmed_sent + pending_sent,
        })
    }

    /// 费率估计：返回 (确认目标区块数, sat/vB) 列表。
    pub async fn fee_estimates(&self) -> Result<Vec<(u16, f64)>> {
        if let Some(node) = &self.node {
            let client = node.connect()?;
            let targets = [1u16, 3, 6, 12, 25, 144];
            let mut estimates = Vec::new();
            for target in targets {
                let rate = client
                    .estimate_smart_fee(
                        target,
                        Some(bitcoincore_rpc::json::EstimateMode::Conservative),
                    )
                    .ok()
                    .and_then(|result| result.fee_rate);
                if let Some(rate) = rate {
                    // RPC 返回 BTC/kB，换算成 sat/vB：to_sat() / 1000
                    estimates.push((target, rate.to_sat() as f64 / 1000.0));
                }
            }
            if !estimates.is_empty() {
                return Ok(estimates);
            }
        }
        self.esplora.fee_estimates().await
    }

    /// 广播原始交易：优先本节点 RPC，回退 Esplora。
    pub async fn broadcast(&self, raw_hex: &str) -> Result<String> {
        if let Some(node) = &self.node {
            let client = node.connect()?;
            let txid = client
                .send_raw_transaction(raw_hex)
                .context("sendrawtransaction 失败")?;
            return Ok(txid.to_string());
        }
        self.esplora.broadcast(raw_hex).await
    }
}

fn is_height(reference: &str) -> bool {
    !reference.is_empty() && reference.chars().all(|c| c.is_ascii_digit())
}

/// 回溯上一笔交易，取指定输出的金额；失败（未开 txindex）返回 None。
fn prevout_value(client: &Client, txid: bitcoin::Txid, vout: u32) -> Option<u64> {
    let info = client.get_raw_transaction_info(&txid, None).ok()?;
    info.vout
        .iter()
        .find(|v| v.n == vout)
        .map(|v| v.value.to_sat())
}

/// 由 CLI 参数构造节点配置；未给出 --node-url 时返回 None。
pub fn node_config(
    network: NetworkArg,
    url: Option<String>,
    user: Option<String>,
    pass: Option<String>,
    cookie: Option<PathBuf>,
) -> Result<Option<NodeConfig>> {
    let url = match url {
        Some(url) => url,
        None => return Ok(None),
    };

    let auth = match (user, pass) {
        (Some(user), Some(pass)) => NodeAuth::UserPass { user, pass },
        (Some(_), None) => bail!("已提供 --node-user 但缺少 --node-pass"),
        (None, Some(_)) => bail!("已提供 --node-pass 但缺少 --node-user"),
        (None, None) => {
            let path = cookie
                .or_else(|| network.default_cookie())
                .context("未找到 bitcoind cookie，请提供 --cookie 或 --node-user/--node-pass")?;
            NodeAuth::Cookie(path)
        }
    };

    Ok(Some(NodeConfig { url, auth }))
}
