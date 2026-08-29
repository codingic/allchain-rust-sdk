//! 查询结果的格式化输出。

use std::str::FromStr;

use anyhow::{Context, Result};
use bitcoin::consensus::encode;
use bitcoin::{Address, Network, Transaction};

use crate::backend::{AddressView, BlockView, StatusView, TxView, UtxoView};
use crate::units::format_btc;

/// 解析并校验地址：必须与所选网络匹配。
pub fn parse_address(raw: &str, network: Network) -> Result<Address> {
    let unchecked =
        Address::from_str(raw.trim()).with_context(|| format!("非法比特币地址: {raw}"))?;
    unchecked
        .require_network(network)
        .with_context(|| format!("地址 {raw} 不属于当前网络"))
}

/// 把 `scriptPubKey` 反解为地址（非标准脚本返回 None）。
fn script_address(script: &bitcoin::ScriptBuf, network: Network) -> Option<String> {
    Address::from_script(script, network)
        .ok()
        .map(|a| a.to_string())
}

pub fn print_status(view: &StatusView, network: &str) {
    println!("network          : {network}");
    println!("source           : {} ({})", view.source, view.endpoint);
    println!("chain            : {}", view.chain);
    println!("blocks           : {}", view.blocks);
    if let Some(headers) = view.headers {
        println!("headers          : {headers}");
    }
    println!("best_block_hash  : {}", view.best_block_hash);
    if let Some(difficulty) = view.difficulty {
        println!("difficulty       : {difficulty:.0}");
    }
    if let Some(progress) = view.verification_progress {
        println!("sync_progress    : {:.4}%", progress * 100.0);
    }
    if let Some(ibd) = view.initial_block_download {
        println!("syncing          : {}", if ibd { "yes" } else { "no" });
    }
    if let Some(t) = view.median_time {
        println!("median_time      : {t}");
    }
    if let Some(txs) = view.mempool_txs {
        println!("mempool_txs      : {txs}");
    }
    if let Some(bytes) = view.mempool_bytes {
        println!("mempool_bytes    : {bytes}");
    }
}

pub fn print_block(view: &BlockView) {
    println!("hash             : {}", view.hash);
    println!("height           : {}", view.height);
    println!("timestamp        : {}", view.timestamp);
    println!("tx_count         : {}", view.tx_count);
    if let Some(size) = view.size {
        println!("size             : {size} bytes");
    }
    if let Some(weight) = view.weight {
        println!("weight           : {weight} WU");
    }
    if let Some(root) = &view.merkle_root {
        println!("merkle_root      : {root}");
    }
    if let Some(prev) = &view.prev_hash {
        println!("prev_hash        : {prev}");
    }
    if let Some(next) = &view.next_hash {
        println!("next_hash        : {next}");
    }
    if let Some(nonce) = view.nonce {
        println!("nonce            : {nonce}");
    }
    if let Some(bits) = &view.bits {
        println!("bits             : {bits}");
    }
    if let Some(difficulty) = view.difficulty {
        println!("difficulty       : {difficulty:.0}");
    }
    if let Some(t) = view.median_time {
        println!("median_time      : {t}");
    }
    if let Some(confirmations) = view.confirmations {
        println!("confirmations    : {confirmations}");
    }
}

pub fn print_tx(view: &TxView) {
    println!("txid             : {}", view.txid);
    println!(
        "status           : {}",
        if view.confirmed {
            "confirmed"
        } else {
            "unconfirmed"
        }
    );
    if let Some(h) = view.block_height {
        println!("block_height     : {h}");
    }
    if let Some(h) = &view.block_hash {
        println!("block_hash       : {h}");
    }
    if let Some(t) = view.block_time {
        println!("block_time       : {t}");
    }
    if let Some(c) = view.confirmations {
        println!("confirmations    : {c}");
    }
    println!("version          : {}", view.version);
    println!("locktime         : {}", view.locktime);
    if let Some(size) = view.size {
        println!("size             : {size} bytes");
    }
    if let Some(weight) = view.weight {
        println!("weight           : {weight} WU");
    }
    if let Some(vsize) = view.vsize {
        println!("vsize            : {vsize} vB");
    }
    if let Some(fee) = view.fee {
        println!("fee              : {} BTC ({} sat)", format_btc(fee), fee);
        if let Some(vsize) = view.vsize.filter(|v| *v > 0) {
            println!("fee_rate         : {:.2} sat/vB", fee as f64 / vsize as f64);
        }
    }

    println!("inputs           : {} 个", view.inputs.len());
    for (i, input) in view.inputs.iter().enumerate() {
        let value = input
            .value
            .map(|v| format!("{} BTC", format_btc(v)))
            .unwrap_or_else(|| "-".to_string());
        let addr = input.address.clone().unwrap_or_else(|| "-".to_string());
        let kind = input.script_type.clone().unwrap_or_default();
        println!(
            "  [{i}] {}:{}  {value}  {addr}  {kind}{}",
            input.txid,
            input.vout,
            if input.coinbase { "  (coinbase)" } else { "" }
        );
    }

    println!("outputs          : {} 个", view.outputs.len());
    for out in &view.outputs {
        let addr = out.address.clone().unwrap_or_else(|| "-".to_string());
        let kind = out.script_type.clone().unwrap_or_default();
        println!(
            "  [{}] {} BTC  {addr}  {kind}",
            out.index,
            format_btc(out.value)
        );
    }
}

pub fn print_address(view: &AddressView) {
    println!("address          : {}", view.address);
    println!(
        "balance          : {} BTC ({} sat)",
        format_btc(view.confirmed_balance),
        view.confirmed_balance
    );
    let pending = view.unconfirmed_balance;
    println!(
        "unconfirmed      : {}{} BTC ({:+})",
        if pending < 0 { "-" } else { "" },
        format_btc(pending.unsigned_abs()),
        pending
    );
    println!("total_received   : {} BTC", format_btc(view.total_received));
    println!("total_sent       : {} BTC", format_btc(view.total_sent));
    println!("tx_count         : {}", view.tx_count);
    println!(
        "utxo_count       : {}",
        view.funded_txo_count - view.spent_txo_count
    );
}

pub fn print_utxos(utxos: &[UtxoView]) {
    let total: u64 = utxos.iter().map(|u| u.value).sum();
    println!("utxos            : {} 个", utxos.len());
    for utxo in utxos {
        let height = utxo
            .block_height
            .map(|h| h.to_string())
            .unwrap_or_else(|| "-".to_string());
        let time = utxo
            .block_time
            .map(|t| t.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "  {}:{}  {} BTC  ({}{} sat)  block {height}  @ {time}",
            utxo.txid,
            utxo.vout,
            format_btc(utxo.value),
            if utxo.confirmed { "" } else { "unconfirmed, " },
            utxo.value
        );
    }
    println!(
        "total            : {} BTC ({} sat)",
        format_btc(total),
        total
    );
}

pub fn print_fees(estimates: &[(u16, f64)]) {
    println!("fee_estimates    : sat/vB");
    for (target, rate) in estimates {
        println!("  ~{target:>3} 区块确认 : {rate:.2}");
    }
}

/// 本地解析原始交易（不联网）。
pub fn decode_transaction(raw_hex: &str, network: Network) -> Result<Transaction> {
    let tx: Transaction = encode::deserialize_hex(raw_hex.trim())
        .with_context(|| "解析原始交易失败（期望 hex 字符串）")?;
    println!("txid             : {}", tx.compute_txid());
    println!("version          : {}", tx.version.0);
    println!("locktime         : {}", tx.lock_time.to_consensus_u32());
    println!("size             : {} bytes", tx.total_size());
    println!("weight           : {} WU", tx.weight().to_wu());
    println!("vsize            : {} vB", tx.vsize());
    println!("inputs           : {} 个", tx.input.len());
    for (i, input) in tx.input.iter().enumerate() {
        println!(
            "  [{i}] {}:{}  sequence {}",
            input.previous_output.txid, input.previous_output.vout, input.sequence
        );
    }
    println!("outputs          : {} 个", tx.output.len());
    for (i, output) in tx.output.iter().enumerate() {
        let address = script_address(&output.script_pubkey, network)
            .unwrap_or_else(|| "非标准脚本".to_string());
        println!(
            "  [{i}] {} BTC  {address}",
            format_btc(output.value.to_sat())
        );
    }
    Ok(tx)
}
