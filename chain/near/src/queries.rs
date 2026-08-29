//! 只读类 JSON-RPC 查询：status / view_account / view_access_key / block / tx / call_function。

use anyhow::{Context, Result, anyhow, bail};
use near_crypto::PublicKey;
use near_jsonrpc_client::{JsonRpcClient, methods};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_jsonrpc_primitives::types::transactions::TransactionInfo;
use near_primitives::types::{AccountId, BlockId, BlockReference, Finality, FunctionArgs};
use near_primitives::views::{QueryRequest, TxExecutionStatus};

use crate::units::format_near;

/// 解析用户输入的区块引用：空 -> 最新 final；纯数字 -> 高度；否则 -> 区块哈希。
pub fn parse_block_reference(reference: Option<&str>) -> Result<BlockReference> {
    match reference.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(BlockReference::Finality(Finality::Final)),
        Some(s) if s.chars().all(|c| c.is_ascii_digit()) => Ok(BlockReference::BlockId(
            BlockId::Height(s.parse().context("区块高度超出范围")?),
        )),
        Some(s) => Ok(BlockReference::BlockId(BlockId::Hash(
            s.parse().map_err(|e| anyhow!("非法区块哈希 {s}: {e}"))?,
        ))),
    }
}

/// `status`：节点同步状态、链 ID、最新区块。
pub async fn status(client: &JsonRpcClient) -> Result<()> {
    let status = client
        .call(methods::status::RpcStatusRequest)
        .await
        .context("查询节点状态失败")?;

    println!("chain_id           : {}", status.chain_id);
    println!("node_version       : {}", status.version.version);
    println!("protocol_version   : {}", status.protocol_version);
    println!(
        "latest_block_hash  : {}",
        status.sync_info.latest_block_hash
    );
    println!(
        "latest_block_height: {}",
        status.sync_info.latest_block_height
    );
    println!(
        "syncing            : {}",
        if status.sync_info.syncing {
            "yes"
        } else {
            "no"
        }
    );
    println!("validator_count    : {}", status.validators.len());
    Ok(())
}

/// `query / view_account`：账户余额、已占用存储、合约 code hash。
pub async fn fetch_account(
    client: &JsonRpcClient,
    account_id: &AccountId,
) -> Result<near_primitives::views::AccountView> {
    let response = client
        .call(methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::ViewAccount {
                account_id: account_id.clone(),
            },
        })
        .await
        .with_context(|| format!("查询账户失败: {account_id}"))?;

    match response.kind {
        QueryResponseKind::ViewAccount(view) => Ok(view),
        other => bail!("非预期的 RPC 响应类型: {other:?}"),
    }
}

pub async fn view_account(client: &JsonRpcClient, account_id: &AccountId) -> Result<()> {
    let account = fetch_account(client, account_id).await?;
    println!("account_id   : {account_id}");
    println!(
        "balance      : {} NEAR ({} yoctoNEAR)",
        format_near(account.amount.as_yoctonear()),
        account.amount.as_yoctonear()
    );
    println!(
        "locked       : {} NEAR ({} yoctoNEAR)",
        format_near(account.locked.as_yoctonear()),
        account.locked.as_yoctonear()
    );
    println!("storage_used : {} bytes", account.storage_usage);
    println!("code_hash    : {}", account.code_hash);
    if let Some(hash) = account.global_contract_hash {
        println!("global_code  : {hash}");
    }
    Ok(())
}

/// `query / view_account` 的精简版：只输出可用余额。
pub async fn balance(client: &JsonRpcClient, account_id: &AccountId) -> Result<()> {
    let account = fetch_account(client, account_id).await?;
    println!("{} NEAR", format_near(account.amount.as_yoctonear()));
    Ok(())
}

/// `query / view_access_key`：查询指定公钥的 nonce 与权限（转账前确认 key 有效）。
pub async fn view_access_key(
    client: &JsonRpcClient,
    account_id: &AccountId,
    public_key: &PublicKey,
) -> Result<u64> {
    let response = client
        .call(methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::ViewAccessKey {
                account_id: account_id.clone(),
                public_key: public_key.clone(),
            },
        })
        .await
        .with_context(|| format!("查询 access key 失败: {account_id} / {public_key}"))?;

    match response.kind {
        QueryResponseKind::AccessKey(view) => {
            println!("public_key   : {public_key}");
            println!("nonce        : {}", view.nonce);
            println!("permission   : {:?}", view.permission);
            println!("block_height : {}", response.block_height);
            Ok(view.nonce)
        }
        other => bail!("非预期的 RPC 响应类型: {other:?}"),
    }
}

/// `block`：查询区块头与 chunk 摘要。
pub async fn get_block(client: &JsonRpcClient, reference: Option<&str>) -> Result<()> {
    let block = client
        .call(methods::block::RpcBlockRequest {
            block_reference: parse_block_reference(reference)?,
        })
        .await
        .context("查询区块失败")?;

    println!("height       : {}", block.header.height);
    println!("hash         : {}", block.header.hash);
    println!("prev_hash    : {}", block.header.prev_hash);
    println!("timestamp    : {}", block.header.timestamp);
    println!("author       : {}", block.author);
    println!("chunks       : {} 个", block.chunks.len());
    Ok(())
}

/// `tx`：按交易哈希 + 发送者查询执行结果。
pub async fn get_tx(
    client: &JsonRpcClient,
    tx_hash: &str,
    sender: &AccountId,
    wait_until: TxExecutionStatus,
) -> Result<()> {
    let tx_hash = tx_hash
        .parse()
        .map_err(|e| anyhow!("非法交易哈希 {tx_hash}: {e}"))?;

    let response = client
        .call(methods::tx::RpcTransactionStatusRequest {
            transaction_info: TransactionInfo::TransactionId {
                tx_hash,
                sender_account_id: sender.clone(),
            },
            wait_until,
        })
        .await
        .with_context(|| {
            format!(
                "查询交易 {tx_hash} 失败：交易不在该节点数据中或尚未入块。\
                 历史交易请使用归档端点（如 https://archival-rpc.mainnet.near.org）"
            )
        })?;

    let outcome = response
        .final_execution_outcome
        .context("节点未返回执行结果（交易可能不存在或尚未入块）")?
        .into_outcome();

    println!("status       : {:#?}", outcome.status);
    println!("signer       : {}", outcome.transaction.signer_id);
    println!("receiver     : {}", outcome.transaction.receiver_id);
    println!("actions      : {} 个", outcome.transaction.actions.len());
    println!(
        "gas_burnt    : {:.2} TGas",
        outcome.transaction_outcome.outcome.gas_burnt.as_gas() as f64 / 1e12
    );
    println!("receipts     : {} 个", outcome.receipts_outcome.len());
    Ok(())
}

/// `query / call_function`：调用合约的只读方法（无需签名、不消耗 gas）。
pub async fn call_function(
    client: &JsonRpcClient,
    contract: &AccountId,
    method: &str,
    args: &[u8],
) -> Result<()> {
    let response = client
        .call(methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::CallFunction {
                account_id: contract.clone(),
                method_name: method.to_string(),
                args: FunctionArgs::from(args.to_vec()),
            },
        })
        .await
        .with_context(|| format!("调用 {contract}.{method} 失败"))?;

    match response.kind {
        QueryResponseKind::CallResult(result) => {
            println!("logs:");
            for line in &result.logs {
                println!("  {line}");
            }
            let json: serde_json::Value =
                serde_json::from_slice(&result.result).unwrap_or(serde_json::Value::Null);
            if json.is_null() {
                println!("result (raw) : {}", String::from_utf8_lossy(&result.result));
            } else {
                println!("result (json): {}", serde_json::to_string_pretty(&json)?);
            }
            println!("block_height : {}", response.block_height);
            Ok(())
        }
        other => bail!("非预期的 RPC 响应类型: {other:?}"),
    }
}
