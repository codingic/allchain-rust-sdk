//! 查询结果的格式化输出。
//!
//! 与 ETH 的 queries.rs 同理：这里全是「拿到 View 直接 `println!`」的打印函数，
//! 服务于单链 CLI；统一门面走 `adapter.rs`，只取结构化数据不打印。

use std::str::FromStr;

use anyhow::{Context, Result};
// `encode` 模块提供比特币的自定义序列化格式（小端整数、VarInt 等），
// 与 JSON 无关，是链上字节级编码。
use bitcoin::consensus::encode;
use bitcoin::{Address, Network, Transaction};

use crate::backend::{AddressView, BlockView, StatusView, TxView, UtxoView};
use crate::units::format_btc;

/// 解析并校验地址：必须与所选网络匹配。
///
/// 领域说明：BTC 地址自带网络信息（bech32 的 hrp、base58 的版本字节），
/// 所以能在**本地**判断「这个地址属于哪个网络」——
/// 这正是防住「把主网币打到测试网地址」这类事故的关键一步。
pub fn parse_address(raw: &str, network: Network) -> Result<Address> {
    // `Address::from_str` 返回 `Address<NetworkUnchecked>`：
    // 只校验字符集与校验和，**不校验网络**。
    let unchecked =
        Address::from_str(raw.trim()).with_context(|| format!("非法比特币地址: {raw}"))?;
    // `require_network` 是第二道闸：确认地址的网络与当前客户端一致，
    // 返回 `Address<NetworkChecked>`——类型系统层面保证「已校验过网络」。
    unchecked
        .require_network(network)
        .with_context(|| format!("地址 {raw} 不属于当前网络"))
}

/// 把 `scriptPubKey` 反解为地址（非标准脚本返回 None）。
///
/// 领域说明：链上存的是**脚本**而不是地址，地址只是脚本的人类友好表示。
/// 像 OP_RETURN（存证）这类脚本根本没有对应地址，故返回 None。
fn script_address(script: &bitcoin::ScriptBuf, network: Network) -> Option<String> {
    // `.ok()`：`Result` → `Option`；`.map(..)`：有值才变换。
    Address::from_script(script, network)
        .ok()
        .map(|a| a.to_string())
}

/// 打印链状态。大量字段是 `Option`，打印前先判有无，避免输出一堆 `None`。
pub fn print_status(view: &StatusView, network: &str) {
    println!("network          : {network}");
    println!("source           : {} ({})", view.source, view.endpoint);
    println!("chain            : {}", view.chain);
    println!("blocks           : {}", view.blocks);
    // `if let Some(x) = option` 是处理「可能有值」最直接的写法。
    if let Some(headers) = view.headers {
        println!("headers          : {headers}");
    }
    println!("best_block_hash  : {}", view.best_block_hash);
    if let Some(difficulty) = view.difficulty {
        // `{difficulty:.0}` 指定小数位为 0：难度是个巨大的浮点数，小数部分无意义。
        println!("difficulty       : {difficulty:.0}");
    }
    if let Some(progress) = view.verification_progress {
        // `{:.4}%` 保留四位小数；`progress * 100.0` 把 0~1 的比例转成百分比。
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

/// 打印区块概览。
pub fn print_block(view: &BlockView) {
    println!("hash             : {}", view.hash);
    println!("height           : {}", view.height);
    println!("timestamp        : {}", view.timestamp);
    println!("tx_count         : {}", view.tx_count);
    if let Some(size) = view.size {
        println!("size             : {size} bytes");
    }
    if let Some(weight) = view.weight {
        // WU = weight unit，权重单位。
        println!("weight           : {weight} WU");
    }
    if let Some(root) = &view.merkle_root {
        // `&view.merkle_root` 借用：`String` 字段若直接 `if let Some(root) = view.merkle_root`
        // 会把字段移出 `&view`（不允许），加 `&` 得到 `&Option<String>`，
        // 与 `Some(root)` 匹配后 `root: &String`。
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

/// 打印交易详情。
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
        // vB = virtual byte，虚拟字节，手续费的结算单位。
        println!("vsize            : {vsize} vB");
    }
    if let Some(fee) = view.fee {
        println!("fee              : {} BTC ({} sat)", format_btc(fee), fee);
        // `Option::filter(闭包)`：有值**且**满足条件才保留。
        // 这里排除 vsize = 0，避免除零得到 inf。
        if let Some(vsize) = view.vsize.filter(|v| *v > 0) {
            // `*v`：`v` 是 `&u64`，解引用拿到值再与 0 比较。
            println!("fee_rate         : {:.2} sat/vB", fee as f64 / vsize as f64);
        }
    }

    println!("inputs           : {} 个", view.inputs.len());
    // `iter().enumerate()` 补上序号，供打印 `[0]` `[1]` 这样的前缀。
    for (i, input) in view.inputs.iter().enumerate() {
        let value = input
            .value
            .map(|v| format!("{} BTC", format_btc(v)))
            // `unwrap_or_else(闭包)`：为 None 时**才**调用闭包构造缺省值。
            .unwrap_or_else(|| "-".to_string());
        let addr = input.address.clone().unwrap_or_else(|| "-".to_string());
        let kind = input.script_type.clone().unwrap_or_default();
        println!(
            "  [{i}] {}:{}  {value}  {addr}  {kind}{}",
            input.txid,
            input.vout,
            // 格式化微语言里的**位置参数** `{0}` `{1}`，已由上面的顺序填好，
            // 这里最后一个 `{}` 按顺序取三元之后的第四项。
            if input.coinbase { "  (coinbase)" } else { "" }
        );
    }

    println!("outputs          : {} 个", view.outputs.len());
    // 不需要序号时用 `&view.outputs` 直接遍历（结构体里本身有 index 字段）。
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

/// 打印地址统计。
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
        // 负号要自己拼：`format_btc` 只处理无符号值。
        if pending < 0 { "-" } else { "" },
        // `unsigned_abs()`：取 **i64 的绝对值并以 u64 返回**。
        // 它比 `.abs()` 安全——`i64::MIN.abs()` 会溢出 panic，这个不会。
        format_btc(pending.unsigned_abs()),
        // `{:+}` 强制显示正负号。
        pending
    );
    println!("total_received   : {} BTC", format_btc(view.total_received));
    println!("total_sent       : {} BTC", format_btc(view.total_sent));
    println!("tx_count         : {}", view.tx_count);
    println!(
        "utxo_count       : {}",
        // 未花费 UTXO 数 = 曾收到数 − 已花掉数。这就是「余额」的另一种表达。
        view.funded_txo_count - view.spent_txo_count
    );
}

/// 打印 UTXO 列表与总额。
pub fn print_utxos(utxos: &[UtxoView]) {
    // 语法说明：`&[UtxoView]` 是**切片**：既能接 `Vec` 也能接数组，
    // 比写 `&Vec<UtxoView>` 更通用（后者要求实参一定是 Vec）。
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
            // 未确认的 UTXO 加个提示：花它会被下游（如交易所）延迟确认。
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

/// 打印费率估计表。
pub fn print_fees(estimates: &[(u16, f64)]) {
    println!("fee_estimates    : sat/vB");
    // 对 `&[(u16, f64)]` 迭代得到 `&(u16, f64)`，解构成 `(&u16, &f64)`。
    for (target, rate) in estimates {
        // `{target:>3}`：右对齐、最小宽度 3，让数字列对齐。
        println!("  ~{target:>3} 区块确认 : {rate:.2}");
    }
}

/// 本地解析原始交易（不联网）。
///
/// 领域说明：**反序列化就能算出 txid 与体积**，无需查询任何节点。
/// 这常用于审计「别人给我的这笔 raw 交易到底转多少钱给谁」——
/// 在签名之前核对，是硬件钱包工作流里的标准动作。
pub fn decode_transaction(raw_hex: &str, network: Network) -> Result<Transaction> {
    // `deserialize_hex` 会同时做格式校验：脚本是否合法、字段是否越界等。
    let tx: Transaction = encode::deserialize_hex(raw_hex.trim())
        .with_context(|| "解析原始交易失败（期望 hex 字符串）")?;
    // txid = 对**不含见证数据**的部分做两次 SHA256。
    // 这也是为什么同一笔 SegWit 交易有 txid 与 wtxid 两个不同的哈希。
    println!("txid             : {}", tx.compute_txid());
    // `version.0`：`Version` 是**新类型包装**（tuple struct），`.0` 取出内部的 i32。
    println!("version          : {}", tx.version.0);
    println!("locktime         : {}", tx.lock_time.to_consensus_u32());
    // `total_size()`：含见证数据的**完整**序列化字节数。
    println!("size             : {} bytes", tx.total_size());
    // `to_wu()`：Weight → u64（权重单位数）。
    println!("weight           : {} WU", tx.weight().to_wu());
    // `vsize()`：虚拟字节，手续费结算单位。
    println!("vsize            : {} vB", tx.vsize());
    println!("inputs           : {} 个", tx.input.len());
    for (i, input) in tx.input.iter().enumerate() {
        println!(
            "  [{i}] {}:{}  sequence {}",
            // `previous_output` 就是 `OutPoint`（txid + vout），即被花费的 UTXO。
            input.previous_output.txid, input.previous_output.vout, input.sequence
        );
    }
    println!("outputs          : {} 个", tx.output.len());
    for (i, output) in tx.output.iter().enumerate() {
        let address = script_address(&output.script_pubkey, network)
            // OP_RETURN 等非标准脚本没有地址，给个可读的占位。
            .unwrap_or_else(|| "非标准脚本".to_string());
        println!(
            "  [{i}] {} BTC  {address}",
            // `to_sat()`：Amount → u64。
            format_btc(output.value.to_sat())
        );
    }
    Ok(tx)
}
