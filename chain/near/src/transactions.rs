//! 交易构造、离线签名与广播（broadcast_tx_commit）。

use std::str::FromStr;

use anyhow::{Context, Result};
use near_crypto::{InMemorySigner, SecretKey, Signer};
use near_jsonrpc_client::{JsonRpcClient, methods};
use near_primitives::action::{Action, FunctionCallAction, TransferAction};
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{SignedTransaction, Transaction, TransactionV0};
use near_primitives::types::{AccountId, Balance, Gas};

use crate::queries;

/// 解析 `ed25519:...` 形式的私钥。
pub fn parse_secret_key(raw: &str) -> Result<SecretKey> {
    SecretKey::from_str(raw.trim()).context("解析私钥失败（期望 ed25519:... 格式）")
}

/// 本地构造并签名后的交易（未广播）。
pub struct BuiltTx {
    pub tx_hash: CryptoHash,
    pub signed: SignedTransaction,
    pub signer_id: AccountId,
    pub receiver_id: AccountId,
    pub nonce: u64,
    pub block_hash: CryptoHash,
}

/// 通用的「取 nonce -> 取最新区块哈希 -> 本地签名」流程（不打印不广播）。
///
/// `nonce_override` 用于离线签名或联调：指定后跳过链上查询 nonce 这一步，
/// 直接以给定值构造交易（仍需自行保证该 nonce 未被使用）。
pub async fn build_signed(
    client: &JsonRpcClient,
    signer_id: &AccountId,
    secret_key: &SecretKey,
    receiver_id: &AccountId,
    actions: Vec<Action>,
    nonce_override: Option<u64>,
) -> Result<BuiltTx> {
    let signer: Signer = InMemorySigner::from_secret_key(signer_id.clone(), secret_key.clone());

    // 1) 默认以当前 nonce + 1 构造交易，避免并发交易相互覆盖。
    let nonce = match nonce_override {
        Some(nonce) => nonce,
        None => queries::view_access_key(client, signer_id, &signer.public_key()).await? + 1,
    };

    // 2) 交易必须锚定一个近期区块哈希（过旧会被节点拒绝）。
    let status = client
        .call(methods::status::RpcStatusRequest)
        .await
        .context("获取最新区块哈希失败")?;

    let unsigned = Transaction::V0(TransactionV0 {
        signer_id: signer_id.clone(),
        public_key: signer.public_key(),
        nonce,
        receiver_id: receiver_id.clone(),
        block_hash: status.sync_info.latest_block_hash,
        actions,
    });

    // 3) 本地离线签名：私钥不会离开本进程。
    let (tx_hash, _size) = unsigned.get_hash_and_size();
    let signed = SignedTransaction::new(signer.sign(tx_hash.as_ref()), unsigned);

    Ok(BuiltTx {
        tx_hash,
        signed,
        signer_id: signer_id.clone(),
        receiver_id: receiver_id.clone(),
        nonce,
        block_hash: status.sync_info.latest_block_hash,
    })
}

/// 通用的「取 nonce -> 取最新区块哈希 -> 本地签名 -> 广播并等待最终性」流程。
///
/// `nonce_override` 用于离线签名或联调：指定后跳过链上查询 nonce 这一步，
/// 直接以给定值构造交易（仍需自行保证该 nonce 未被使用）。
pub async fn send_tx(
    client: &JsonRpcClient,
    signer_id: &AccountId,
    secret_key: &SecretKey,
    receiver_id: &AccountId,
    actions: Vec<Action>,
    nonce_override: Option<u64>,
) -> Result<CryptoHash> {
    let built = build_signed(
        client,
        signer_id,
        secret_key,
        receiver_id,
        actions,
        nonce_override,
    )
    .await?;

    println!("tx_hash      : {}", built.tx_hash);
    println!("signer       : {}", built.signer_id);
    println!("receiver     : {}", built.receiver_id);
    println!("nonce        : {}", built.nonce);
    println!("block_hash   : {}", built.block_hash);

    // 4) 广播并等待交易达到最终性。
    let outcome = client
        .call(methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
            signed_transaction: built.signed,
        })
        .await
        .context("广播交易失败")?;

    println!("status       : {:#?}", outcome.status);
    println!(
        "gas_burnt    : {:.2} TGas",
        outcome.transaction_outcome.outcome.gas_burnt.as_gas() as f64 / 1e12
    );
    for (i, receipt) in outcome.receipts_outcome.iter().enumerate() {
        println!("receipt[{i}]   : {}", receipt.outcome.executor_id);
        println!("  status: {:?}", receipt.outcome.status);
        for line in &receipt.outcome.logs {
            println!("  log: {line}");
        }
    }
    Ok(built.tx_hash)
}

/// 原生 NEAR 转账。
pub async fn transfer(
    client: &JsonRpcClient,
    signer_id: &AccountId,
    secret_key: &SecretKey,
    receiver_id: &AccountId,
    deposit: u128,
    nonce_override: Option<u64>,
) -> Result<CryptoHash> {
    send_tx(
        client,
        signer_id,
        secret_key,
        receiver_id,
        vec![Action::Transfer(TransferAction {
            deposit: Balance::from_yoctonear(deposit),
        })],
        nonce_override,
    )
    .await
}

/// 调用合约的变更方法（会消耗 gas，需要签名）。
#[allow(clippy::too_many_arguments)]
pub async fn function_call(
    client: &JsonRpcClient,
    signer_id: &AccountId,
    secret_key: &SecretKey,
    contract_id: &AccountId,
    method_name: &str,
    args: Vec<u8>,
    gas: u64,
    deposit: u128,
    nonce_override: Option<u64>,
) -> Result<CryptoHash> {
    send_tx(
        client,
        signer_id,
        secret_key,
        contract_id,
        vec![Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: method_name.to_string(),
            args,
            gas: Gas::from_gas(gas),
            deposit: Balance::from_yoctonear(deposit),
        }))],
        nonce_override,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::units::parse_near;
    use near_crypto::KeyType;

    /// 离线验证 send_tx 的本地部分：构造 -> 签名 -> 哈希/签名校验，全程不触网。
    #[test]
    fn send_tx_signs_offline() {
        let secret_key = SecretKey::from_seed(KeyType::ED25519, "near-rpc-cli-test-seed");
        let signer_id: AccountId = "alice.near".parse().unwrap();
        let receiver_id: AccountId = "bob.near".parse().unwrap();

        let signer: Signer = InMemorySigner::from_secret_key(signer_id.clone(), secret_key);
        let unsigned = Transaction::V0(TransactionV0 {
            signer_id,
            public_key: signer.public_key(),
            nonce: 42,
            receiver_id,
            block_hash: Default::default(),
            actions: vec![Action::Transfer(TransferAction {
                deposit: Balance::from_yoctonear(parse_near("1.5").unwrap()),
            })],
        });

        let (tx_hash, size) = unsigned.get_hash_and_size();
        assert!(size > 0);

        let signed = SignedTransaction::new(signer.sign(tx_hash.as_ref()), unsigned);
        // 签名只追加签名字段，不改变交易体，因此哈希必须保持一致。
        assert_eq!(signed.get_hash(), tx_hash);
        assert!(
            signed
                .signature
                .verify(tx_hash.as_ref(), &signer.public_key())
        );
    }
}
