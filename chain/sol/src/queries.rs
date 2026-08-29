//! 只读查询：status / get_block / get_tx / balance。

use anyhow::{Context, Result};
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_types::config::{RpcBlockConfig, RpcTransactionConfig};
use solana_transaction_status_client_types::{
    EncodedTransaction, UiMessage, UiTransactionEncoding, UiTransactionStatusMeta,
    option_serializer::OptionSerializer,
};

use crate::units::format_sol;

/// `getVersion` + `getSlot`：节点版本与当前 slot。
pub fn status(client: &RpcClient) -> Result<()> {
    let version = client.get_version().context("查询节点版本失败")?;
    let slot = client.get_slot().context("查询当前 slot 失败")?;
    let blockhash = client
        .get_latest_blockhash()
        .context("查询最新 blockhash 失败")?;

    println!("node_version     : {}", version.solana_core);
    println!("feature_set      : {:?}", version.feature_set);
    println!("slot             : {slot}");
    println!("latest_blockhash : {blockhash}");
    Ok(())
}

/// `getBlock`：按 slot 查询区块（公共节点通常只开放最近约 1-2 天的区块）。
pub fn get_block(client: &RpcClient, slot: u64) -> Result<()> {
    // 必须显式声明 maxSupportedTransactionVersion，否则含 v0 交易的区块会被节点拒绝。
    let config = RpcBlockConfig {
        encoding: Some(UiTransactionEncoding::Json),
        transaction_details: None,
        rewards: Some(false),
        commitment: None,
        max_supported_transaction_version: Some(0),
    };
    let block = client
        .get_block_with_config(slot, config)
        .with_context(|| format!("查询区块 {slot} 失败（公共节点可能只保留近期区块）"))?;

    println!("slot             : {slot}");
    println!("blockhash        : {}", block.blockhash);
    println!("previous_blockhash: {}", block.previous_blockhash);
    println!("parent_slot      : {}", block.parent_slot);
    println!("block_height     : {:?}", block.block_height);
    println!(
        "block_time       : {}",
        block
            .block_time
            .map(chrono_like)
            .unwrap_or_else(|| "n/a".to_string())
    );
    let txs = block.transactions.as_deref().unwrap_or_default();
    println!("transactions     : {} 笔", txs.len());
    println!(
        "rewards          : {} 条",
        block.rewards.as_ref().map(|r| r.len()).unwrap_or(0)
    );

    for (i, tx) in txs.iter().take(5).enumerate() {
        let signature = match &tx.transaction {
            EncodedTransaction::Json(ui) => ui.signatures.first().cloned().unwrap_or_default(),
            EncodedTransaction::LegacyBinary(_) | EncodedTransaction::Binary(_, _) => {
                "<binary 编码>".to_string()
            }
            EncodedTransaction::Accounts(_) => "<accounts 编码>".to_string(),
        };
        println!("  [{i}] {signature}");
    }
    Ok(())
}

/// `getTransaction`：按签名查询交易详情与执行元数据。
pub fn get_tx(client: &RpcClient, signature: &str) -> Result<()> {
    let signature = signature
        .parse()
        .with_context(|| format!("非法交易签名: {signature}"))?;

    let config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: None,
        max_supported_transaction_version: Some(0),
    };
    let tx = client
        .get_transaction_with_config(&signature, config)
        .context("查询交易失败（签名不存在或节点未保留该交易）")?;

    println!("slot             : {}", tx.slot);
    println!(
        "block_time       : {}",
        tx.block_time
            .map(chrono_like)
            .unwrap_or_else(|| "n/a".to_string())
    );
    if let Some(index) = tx.transaction_index {
        println!("tx_index         : {index}");
    }
    println!("version          : {:?}", tx.transaction.version);

    match &tx.transaction.transaction {
        EncodedTransaction::Json(ui) => {
            println!(
                "signature        : {}",
                ui.signatures.first().unwrap_or(&String::new())
            );
            let blockhash = match &ui.message {
                UiMessage::Parsed(msg) => Some(msg.recent_blockhash.as_str()),
                UiMessage::Raw(msg) => Some(msg.recent_blockhash.as_str()),
            };
            if let Some(recent) = blockhash {
                println!("recent_blockhash : {recent}");
            }
        }
        other => println!("transaction      : {other:?}"),
    }

    if let Some(meta) = tx.transaction.meta.as_ref() {
        print_meta(meta);
    } else {
        println!("meta             : <无>");
    }
    Ok(())
}

/// 输出交易执行结果：状态、手续费、日志、余额变化。
fn print_meta(meta: &UiTransactionStatusMeta) {
    match &meta.err {
        None => println!("status           : Success"),
        Some(err) => println!("status           : Failed ({err:?})"),
    }
    println!("fee              : {} lamports", meta.fee);
    if let OptionSerializer::Some(units) = meta.compute_units_consumed {
        println!("compute_units    : {units}");
    }
    println!(
        "balances         : pre {:?} -> post {:?}",
        meta.pre_balances, meta.post_balances
    );
    if let OptionSerializer::Some(logs) = &meta.log_messages {
        println!("logs             :");
        for line in logs.iter().take(12) {
            println!("  {line}");
        }
    }
}

/// `getBalance`：账户余额。
pub fn balance(client: &RpcClient, address: &str) -> Result<()> {
    let pubkey: Pubkey = address
        .parse()
        .with_context(|| format!("非法地址: {address}"))?;
    let lamports = client
        .get_balance(&pubkey)
        .with_context(|| format!("查询余额失败: {pubkey}"))?;
    println!("address          : {pubkey}");
    println!(
        "balance          : {} SOL ({} lamports)",
        format_sol(lamports),
        lamports
    );
    Ok(())
}

/// 把 Unix 时间戳格式化为可读时间（不引入额外时间库）。
fn chrono_like(timestamp: i64) -> String {
    let secs = timestamp.max(0) as u64;
    let days = secs / 86_400;
    let time = secs % 86_400;
    // 1970-01-01 起的天数换算为年月日（Civil from days 算法）。
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

/// Howard Hinnant 的 civil_from_days 算法，避免引入 chrono。
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_unix_timestamps() {
        assert_eq!(chrono_like(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(chrono_like(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn civil_conversion_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 1_700_000_000 秒 = 第 19675 天 = 2023-11-14
        assert_eq!(civil_from_days(19_675), (2023, 11, 14));
    }
}
