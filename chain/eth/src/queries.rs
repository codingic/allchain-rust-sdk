//! 只读类 JSON-RPC 查询：status / account / balance / block / tx / call。

use alloy::consensus::Transaction as _;
use alloy::eips::BlockId;
use alloy::network::{ReceiptResponse, TransactionResponse};
use alloy::primitives::{Address, B256, TxKind, U256};
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::types::{Transaction, TransactionInput, TransactionReceipt, TransactionRequest};
use anyhow::{Context, Result, anyhow};

use crate::units::format_wei;

/// 解析用户输入的区块引用：空 -> 最新区块；纯数字 -> 高度；否则 -> 区块哈希。
pub fn parse_block_reference(reference: Option<&str>) -> Result<BlockId> {
    match reference.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(BlockId::latest()),
        Some(s) if s.chars().all(|c| c.is_ascii_digit()) => {
            Ok(BlockId::number(s.parse().context("区块高度超出范围")?))
        }
        Some(s) => Ok(BlockId::hash(
            s.parse().map_err(|e| anyhow!("非法区块哈希 {s}: {e}"))?,
        )),
    }
}

/// `web3_clientVersion` + `eth_chainId` + `eth_blockNumber` + `eth_gasPrice`。
pub async fn status(client: &RootProvider) -> Result<()> {
    let version = client
        .get_client_version()
        .await
        .context("查询客户端版本失败")?;
    let chain_id = client.get_chain_id().await.context("查询链 ID 失败")?;
    let block_number = client
        .get_block_number()
        .await
        .context("查询最新区块高度失败")?;
    let gas_price = client.get_gas_price().await.context("查询 gas 价格失败")?;

    println!("client_version : {version}");
    println!("chain_id       : {chain_id}");
    println!("block_number   : {block_number}");
    println!(
        "gas_price      : {} gwei ({} wei)",
        format_wei(U256::from(gas_price), 9),
        gas_price
    );
    Ok(())
}

/// 账户概览：余额、下一笔可用 nonce、合约代码大小。
pub async fn account(client: &RootProvider, address: Address) -> Result<()> {
    let balance = client
        .get_balance(address)
        .await
        .with_context(|| format!("查询余额失败: {address}"))?;
    let nonce = client
        .get_transaction_count(address)
        .await
        .with_context(|| format!("查询 nonce 失败: {address}"))?;
    let code = client
        .get_code_at(address)
        .await
        .with_context(|| format!("查询合约代码失败: {address}"))?;

    println!("address  : {address}");
    println!(
        "balance  : {} ETH ({} wei)",
        format_wei(balance, 18),
        balance
    );
    println!("nonce    : {nonce}");
    println!(
        "code     : {} bytes{}",
        code.len(),
        if code.is_empty() {
            "（EOA，非合约）"
        } else {
            "（合约）"
        }
    );
    Ok(())
}

/// 精简版：只输出余额。
pub async fn balance(client: &RootProvider, address: Address) -> Result<()> {
    let balance = client
        .get_balance(address)
        .await
        .with_context(|| format!("查询余额失败: {address}"))?;
    println!("{} ETH", format_wei(balance, 18));
    Ok(())
}

/// `eth_getBlockByNumber/Hash`：区块头摘要与交易数。
pub async fn get_block(client: &RootProvider, reference: Option<&str>) -> Result<()> {
    let block_id = parse_block_reference(reference)?;
    let block = client
        .get_block(block_id)
        .await
        .context("查询区块失败")?
        .context("节点未返回该区块（高度超前或不存在）")?;

    let header = &block.header;
    println!("number         : {}", header.number);
    println!("hash           : {}", header.hash);
    println!("parent_hash    : {}", header.parent_hash);
    println!("timestamp      : {}", header.timestamp);
    println!("miner          : {}", header.beneficiary);
    println!("gas_used       : {}", header.gas_used);
    println!("gas_limit      : {}", header.gas_limit);
    if let Some(base_fee) = header.base_fee_per_gas {
        println!(
            "base_fee       : {} gwei",
            format_wei(U256::from(base_fee), 9)
        );
    }
    println!("transactions   : {} 笔", block.transactions.len());
    Ok(())
}

/// `eth_getTransactionByHash` + `eth_getTransactionReceipt`：交易详情与执行结果。
pub async fn get_tx(client: &RootProvider, tx_hash: B256) -> Result<()> {
    let tx: Option<Transaction> = client
        .get_transaction_by_hash(tx_hash)
        .await
        .with_context(|| format!("查询交易 {tx_hash} 失败"))?;
    let tx =
        tx.with_context(|| format!("交易 {tx_hash} 不在该节点数据中。历史交易请使用归档节点端点"))?;

    println!("hash           : {tx_hash}");
    println!("from           : {}", tx.from());
    match tx.to() {
        Some(to) => println!("to             : {to}"),
        None => println!("to             : （合约创建交易）"),
    }
    println!("value          : {} ETH", format_wei(tx.value(), 18));
    println!("nonce          : {}", tx.nonce());
    println!("gas_limit      : {}", tx.gas_limit());
    println!("input          : {} bytes", tx.input().len());
    match tx.block_number() {
        Some(n) => println!("block_number   : {n}"),
        None => println!("block_number   : （仍在内存池中）"),
    }

    let receipt: Option<TransactionReceipt> = client
        .get_transaction_receipt(tx_hash)
        .await
        .with_context(|| format!("查询交易回执 {tx_hash} 失败"))?;
    match receipt {
        Some(receipt) => {
            println!(
                "status         : {}",
                if receipt.status() {
                    "success"
                } else {
                    "reverted"
                }
            );
            println!("gas_used       : {}", receipt.gas_used());
            println!(
                "gas_price_paid : {} gwei",
                format_wei(U256::from(receipt.effective_gas_price()), 9)
            );
            println!("logs           : {} 条", receipt.inner.logs().len());
        }
        None => println!("status         : （尚未入块，无回执）"),
    }
    Ok(())
}

/// `eth_call`：调用合约的只读方法（无需签名、不消耗 gas）。
pub async fn call(client: &RootProvider, to: Address, data: Vec<u8>) -> Result<()> {
    // alloy 2.x 的 TransactionRequest 不再提供 with_to/with_input 链式方法，
    // 直接构造结构体；`to` 的类型是 TxKind 而非裸地址。
    let request = TransactionRequest {
        to: Some(TxKind::Call(to)),
        input: TransactionInput::from(data.clone()),
        ..Default::default()
    };

    let output = client
        .call(request)
        .await
        .with_context(|| format!("eth_call {to} 执行失败（方法可能 revert 或参数错误）"))?;

    println!("to             : {to}");
    println!("input          : 0x{}", alloy::hex::encode(&data));
    println!("output (bytes) : {} bytes", output.len());
    println!("output (hex)   : 0x{}", alloy::hex::encode(&output));
    // 常见约定：返回值可能是 utf8 或 JSON，尝试给出可读版本。
    if let Ok(text) = std::str::from_utf8(&output) {
        let trimmed = text.trim();
        if !trimmed.is_empty() && trimmed.chars().all(|c| !c.is_control()) {
            println!("output (text)  : {trimmed}");
        }
    }
    Ok(())
}
