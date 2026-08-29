//! 交易构造、本地签名与广播（私钥不出本机）。

use std::str::FromStr;

use alloy::consensus::SignableTransaction;
use alloy::eips::eip2718::Encodable2718;
use alloy::network::{ReceiptResponse, TxSignerSync};
use alloy::primitives::{Address, B256, TxKind, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{TransactionInput, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};

use crate::units::{format_wei, parse_gas_limit};

/// 原生转账的默认 gas limit（普通转账固定 21000）。
pub const TRANSFER_GAS: u64 = 21_000;
/// 合约调用的默认 gas limit。
pub const CALL_GAS: u64 = 200_000;

/// 解析 `0x...` 或裸十六进制私钥为本地签名器。
pub fn parse_signer(raw: &str) -> Result<PrivateKeySigner> {
    PrivateKeySigner::from_str(raw.trim())
        .context("解析私钥失败（期望 32 字节十六进制，可带 0x 前缀）")
}

/// 构造带钱包的 Provider：自动填充 nonce / gas / chain id，并用钱包本地签名。
fn wallet_provider(rpc_url: &str, signer: PrivateKeySigner) -> Result<impl Provider> {
    let url = crate::network::parse_url(rpc_url)?;
    // 注意：alloy 2.x 的 `ProviderBuilder::new()` 内部已是
    // `default().with_recommended_fillers()`，再次调用反而会因类型不匹配而报错。
    Ok(alloy::providers::ProviderBuilder::new()
        .wallet(signer)
        .connect_http(url))
}

/// 发送交易并等待回执（入块），返回交易哈希。
async fn send_and_wait(provider: impl Provider, request: TransactionRequest) -> Result<B256> {
    let pending = provider
        .send_transaction(request)
        .await
        .context("广播交易失败")?;
    let tx_hash = *pending.tx_hash();
    println!("tx_hash      : {tx_hash}");
    let receipt = pending
        .get_receipt()
        .await
        .with_context(|| format!("等待交易 {tx_hash} 回执失败（超时或节点异常）"))?;
    println!(
        "status       : {}",
        if receipt.status() {
            "success"
        } else {
            "reverted"
        }
    );
    println!("block_number : {:?}", receipt.block_number());
    println!("gas_used     : {}", receipt.gas_used());
    println!(
        "gas_price    : {} gwei",
        format_wei(U256::from(receipt.effective_gas_price()), 9)
    );
    Ok(tx_hash)
}

/// 原生 ETH 转账，返回交易哈希。
pub async fn transfer(
    rpc_url: &str,
    signer: PrivateKeySigner,
    to: Address,
    value: U256,
) -> Result<B256> {
    let from = signer.address();
    println!("from         : {from}");
    println!("to           : {to}");
    println!("value        : {} ETH", format_wei(value, 18));

    let request = TransactionRequest {
        from: Some(from),
        to: Some(TxKind::Call(to)),
        value: Some(value),
        gas: Some(TRANSFER_GAS),
        ..Default::default()
    };

    send_and_wait(wallet_provider(rpc_url, signer)?, request).await
}

/// 调用合约（可选附带 value，data 为 ABI 编码后的调用数据），返回交易哈希。
pub async fn call_contract(
    rpc_url: &str,
    signer: PrivateKeySigner,
    to: Address,
    data: Vec<u8>,
    value: U256,
    gas: Option<&str>,
) -> Result<B256> {
    let from = signer.address();
    let gas_limit = parse_gas_limit(gas, CALL_GAS)?;
    println!("from         : {from}");
    println!("to           : {to}");
    println!("value        : {} ETH", format_wei(value, 18));
    println!("input        : 0x{}", alloy::hex::encode(&data));
    println!("gas_limit    : {gas_limit}");

    let request = TransactionRequest {
        from: Some(from),
        to: Some(TxKind::Call(to)),
        input: TransactionInput::from(data.clone()),
        value: Some(value),
        gas: Some(gas_limit),
        ..Default::default()
    };

    send_and_wait(wallet_provider(rpc_url, signer)?, request).await
}

/// 广播一笔原生转账并等待回执（不打印），供统一接口复用。
///
/// 返回 `(交易哈希, 是否成功, 区块号, gas_used)`。
pub async fn transfer_silent(
    rpc_url: &str,
    signer: PrivateKeySigner,
    to: Address,
    value: U256,
) -> Result<(B256, bool, Option<u64>, u64)> {
    let request = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(to)),
        value: Some(value),
        gas: Some(TRANSFER_GAS),
        ..Default::default()
    };

    let pending = wallet_provider(rpc_url, signer)?
        .send_transaction(request)
        .await
        .context("广播交易失败")?;
    let tx_hash = *pending.tx_hash();
    let receipt = pending
        .get_receipt()
        .await
        .with_context(|| format!("等待交易 {tx_hash} 回执失败"))?;
    Ok((
        tx_hash,
        receipt.status(),
        receipt.block_number(),
        receipt.gas_used(),
    ))
}

/// 离线构造并签名一笔 EIP-1559 原生转账（不广播），返回哈希与已签名 raw 编码。
pub struct SignedTransfer {
    pub tx_hash: B256,
    pub signed_raw: String,
    pub chain_id: u64,
    pub nonce: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

/// 本地签名（私钥不经过网络）并序列化为 raw 编码，供 dry-run 与人工广播使用。
pub async fn build_signed_transfer(
    rpc_url: &str,
    signer: &PrivateKeySigner,
    to: Address,
    value: U256,
) -> Result<SignedTransfer> {
    let client = crate::network::connect(rpc_url)?;
    let chain_id = client.get_chain_id().await.context("查询链 ID 失败")?;
    let nonce = client
        .get_transaction_count(signer.address())
        .await
        .context("查询 nonce 失败")?;
    let fees = client
        .estimate_eip1559_fees()
        .await
        .context("估算 gas 费用失败")?;

    let mut tx = alloy::consensus::TxEip1559 {
        chain_id,
        nonce,
        gas_limit: TRANSFER_GAS,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        to: TxKind::Call(to),
        value,
        input: Default::default(),
        access_list: Default::default(),
    };

    let signature = signer
        .sign_transaction_sync(&mut tx)
        .context("本地签名失败")?;
    let envelope = tx.into_signed(signature);
    let tx_hash = *envelope.hash();
    let signed_raw = format!("0x{}", alloy::hex::encode(envelope.encoded_2718()));

    Ok(SignedTransfer {
        tx_hash,
        signed_raw,
        chain_id,
        nonce,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
    })
}

/// 离线导出已签名交易（不广播）：用于硬件钱包之外的人工广播场景。
pub async fn sign_only(
    rpc_url: &str,
    signer: PrivateKeySigner,
    to: Address,
    value: U256,
) -> Result<()> {
    let signed = build_signed_transfer(rpc_url, &signer, to, value).await?;

    println!("from             : {}", signer.address());
    println!("to               : {to}");
    println!("chain_id         : {}", signed.chain_id);
    println!("nonce            : {}", signed.nonce);
    println!(
        "max_fee          : {} gwei",
        format_wei(U256::from(signed.max_fee_per_gas), 9)
    );
    println!(
        "priority_fee     : {} gwei",
        format_wei(U256::from(signed.max_priority_fee_per_gas), 9)
    );
    println!("gas_limit        : {TRANSFER_GAS}");
    println!("tx_hash          : {}", signed.tx_hash);
    println!("signed_raw       : {}", signed.signed_raw);
    Ok(())
}
