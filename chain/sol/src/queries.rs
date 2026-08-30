//! 只读查询：status / get_block / get_tx / balance。
//!
//! ## 本模块的定位
//! 这里每个 `pub fn` 的返回值都是 `Result<()>`——**它们只负责打印，不返回结构化数据**。
//! 这是给 CLI 直调的一层薄封装；统一门面走的是 `adapter.rs`（那里返回各 `View`）。
//! 两者 intentionally 分开：打印逻辑（对齐、单位、截断）不该污染数据层。
//!
//! ## Solana 的两个关键坑
//! 1. **区块按 slot 索引，不是按高度**。slot 是「出块机会」的编号（约 400ms 一个），
//!    某个 slot 可能因为 leader 离线而**没有产生区块**（跳块）。
//!    因此 `slot >= block_height` 恒成立，只有全程不跳块时两者才相等。
//!    查区块必须用 slot，查到的 `block_height` 才是「第几个块」。
//! 2. **公共节点只保留最近 1-2 天的区块**。`getBlock` 一个稍旧的 slot 会直接报
//!    `BlockNotAvailable`，需要历史数据必须换归档节点（本 SDK 不提供）。
//!
//! ## 阻塞语义
//! 所有函数都接受 `&RpcClient`，而它是**同步阻塞**客户端，
//! 因此这些函数不能在 async 上下文里直接调用。

use anyhow::{Context, Result};
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
// 两个 config 结构体分别控制 `getBlock` / `getTransaction` 的返回细节。
// 它们都是 `Option` 字段的「builder 风格」结构：`None` 表示「用节点默认值」。
use solana_rpc_client_types::config::{RpcBlockConfig, RpcTransactionConfig};
// `EncodedTransaction`：节点返回交易时可能有多种编码（JSON / base64 binary / 仅账户列表），
// 这是它们的统一枚举。
// `UiMessage`：交易的 message 部分（Parsed = 节点已解析成结构化字段，Raw = 只给 base58 字符串）。
// `UiTransactionEncoding`：请求时声明希望的编码。
// `UiTransactionStatusMeta`：交易执行的元数据（手续费、日志、余额变化、错误信息）。
// `OptionSerializer`：见下方使用处的说明。
use solana_transaction_status_client_types::{
    EncodedTransaction, UiMessage, UiTransactionEncoding, UiTransactionStatusMeta,
    option_serializer::OptionSerializer,
};

use crate::units::format_sol;

/// `getVersion` + `getSlot`：节点版本与当前 slot。
///
/// 三个 RPC 调用串行发出（对应 `getVersion` / `getSlot` / `getLatestBlockhash`）。
/// 它们之间没有依赖，理论上可并发，但客户端是同步阻塞的，并发需要额外线程，
/// 对一次 CLI 调用而言不值得。
pub fn status(client: &RpcClient) -> Result<()> {
    // `.context("..")` 给错误附加静态文案；它要求错误类型实现了 `std::error::Error`。
    // `?` 是**提前返回运算符**：出错时直接把错误 `return` 出去（并自动做类型转换），
    // 成功时把 `Ok(T)` 里的 `T` 取出来继续往下走。
    let version = client.get_version().context("查询节点版本失败")?;
    let slot = client.get_slot().context("查询当前 slot 失败")?;
    // 注意这里取的是 **blockhash** 而不是「最新区块哈希」——
    // Solana 的交易锚定 blockhash，所以 CLI 展示它对调试交易过期问题更有用。
    let blockhash = client
        .get_latest_blockhash()
        .context("查询最新 blockhash 失败")?;

    // `{:?}` 走 `Debug` 格式化，`{}` 走 `Display`。
    // 下面几行在 `println!` 里**直接写变量名**（`{slot}`）是 Rust 2021 起的
    // 「内联格式参数」（captured identifiers），等价于 `println!("{}", slot)` 但更短。
    println!("node_version     : {}", version.solana_core);
    println!("feature_set      : {:?}", version.feature_set);
    println!("slot             : {slot}");
    println!("latest_blockhash : {blockhash}");
    // 返回 `Ok(())`：`()` 是**单元类型**，表示「没有有意义的返回值」。
    Ok(())
}

/// `getBlock`：按 slot 查询区块（公共节点通常只开放最近约 1-2 天的区块）。
pub fn get_block(client: &RpcClient, slot: u64) -> Result<()> {
    // 必须显式声明 maxSupportedTransactionVersion，否则含 v0 交易的区块会被节点拒绝。
    //
    // 展开说一下这个坑：Solana 自 2022 年起支持 **v0 交易**（带地址查找表 Address Lookup Table），
    // 节点默认只敢返回 legacy 交易。一旦目标区块里含 v0 交易，
    // 未声明该参数时节点会返回 JSON-RPC 错误 `-32015`
    // （"Transaction version (0) is not supported"）。
    // 传 `Some(0)` 即宣告「我支持最高 v0」，节点才会正常返回。
    // 将来若出现 v1，`max_supported_transaction_version` 就要相应调大。
    let config = RpcBlockConfig {
        // 请求 JSON 编码（人类可读），而不是 base64 的二进制编码。
        encoding: Some(UiTransactionEncoding::Json),
        // `None` = 用节点默认的详细程度（完整交易）。
        // 若设为 `Some(TransactionDetails::Signatures)` 则只返回签名列表，能大幅减少响应体积。
        transaction_details: None,
        // 不要奖励（出块奖励/stake 奖励）明细：体积大且这里不展示。
        rewards: Some(false),
        // `None` = 沿用客户端构造时的 commitment（本 SDK 固定为 confirmed）。
        commitment: None,
        max_supported_transaction_version: Some(0),
    };
    let block = client
        .get_block_with_config(slot, config)
        // `with_context` 是 `.context` 的**惰性**版本：参数是闭包，
        // 只有真出错时才执行 `format!`。这里要拼 slot，所以必须用闭包形式。
        .with_context(|| format!("查询区块 {slot} 失败（公共节点可能只保留近期区块）"))?;

    println!("slot             : {slot}");
    println!("blockhash        : {}", block.blockhash);
    println!("previous_blockhash: {}", block.previous_blockhash);
    // 父 slot 与父 blockhash 不一定连续：中间可能跳块，
    // 所以 `parent_slot` 常常比 `slot - 1` 小。
    println!("parent_slot      : {}", block.parent_slot);
    // `block_height` 是 `Option`：节点在某些配置下不回。
    // `{:?}` 打印 Option 会得到 `Some(123)` / `None`。
    println!("block_height     : {:?}", block.block_height);
    println!(
        "block_time       : {}",
        // `Option<i64>` 的组合子三连：
        // - `.map(chrono_like)`：有值时把 `i64` 交给 `chrono_like` 转成 `String`
        //   （这里传的是**函数指针**，不是闭包）；
        // - `.unwrap_or_else(|| "n/a".to_string())`：无值时用闭包造一个兜底串。
        //   用 `unwrap_or_else` 而非 `unwrap_or("n/a".to_string())` 的理由同上——惰性。
        block
            .block_time
            .map(chrono_like)
            .unwrap_or_else(|| "n/a".to_string())
    );
    // `block.transactions` 是 `Option<Vec<..>>`（节点可能不给交易列表）；
    // `.as_deref()` 把 `Option<Vec<T>>` 变成 `Option<&[T]>`（deref 强制转换），
    // 于是 `.unwrap_or_default()` 可以返回一个**空切片**作为默认值——
    // 对 `&[T]` 而言 `Default` 就是空切片，这样不会分配任何内存。
    // 若直接写 `.unwrap_or_default()` 在 `Option<Vec<T>>` 上，则会分配一个空 Vec。
    let txs = block.transactions.as_deref().unwrap_or_default();
    println!("transactions     : {} 笔", txs.len());
    println!(
        "rewards          : {} 条",
        // `.as_ref()` 把 `Option<Vec<T>>` 借成 `Option<&Vec<T>>`，避免移走所有权；
        // `.map(|r| r.len())` 得 `Option<usize>`；`.unwrap_or(0)` 给默认值。
        // 这里用 `unwrap_or`（非 `_else`）是因为 `0` 是 `Copy` 的常量，构造无成本。
        block.rewards.as_ref().map(|r| r.len()).unwrap_or(0)
    );

    // 只打印前 5 笔，避免刷屏（一个满块可能有上千笔交易）。
    // `.take(5)` 限制迭代数量，`.enumerate()` 附带下标 `i`。
    for (i, tx) in txs.iter().take(5).enumerate() {
        // 交易的编码形式取决于节点配置 + 交易版本，这里穷举处理。
        let signature = match &tx.transaction {
            // 我们请求了 JSON 编码，正常走这一支。
            EncodedTransaction::Json(ui) => ui.signatures.first().cloned().unwrap_or_default(),
            // 下面两支是二进制编码（base58 / base64），无法直接读出签名，
            // 只能给个占位说明。`|` 是**或模式**，二者共用同一个分支体。
            EncodedTransaction::LegacyBinary(_) | EncodedTransaction::Binary(_, _) => {
                "<binary 编码>".to_string()
            }
            // 只返回账户列表的精简编码，同样没有签名。
            EncodedTransaction::Accounts(_) => "<accounts 编码>".to_string(),
        };
        println!("  [{i}] {signature}");
    }
    Ok(())
}

/// `getTransaction`：按签名查询交易详情与执行元数据。
pub fn get_tx(client: &RpcClient, signature: &str) -> Result<()> {
    // `.parse()` 的目标类型由下一行的 `let tx_hash = ...` 用法推断为 `Signature`。
    // 这里**遮蔽**（shadowing）了参数 `signature`：同名变量被重新绑定为不同类型，
    // 之后代码里写 `signature` 指的就是解析后的 `Signature`（后面传给 RPC 的那个）。
    // 遮蔽是 Rust 的惯用手法——比另起 `signature_parsed` 这类名字更清爽。
    //
    // 注意 `with_context` 闭包里捕获的是**遮蔽前**的 `&str`（闭包在 `.parse()` 求值前创建，
    // 捕获的是外层那个字符串引用），所以报错信息里打印的是用户原始输入。
    let signature = signature
        .parse()
        .with_context(|| format!("非法交易签名: {signature}"))?;

    // 与 get_block 同理：必须声明 maxSupportedTransactionVersion，
    // 否则查询 v0 交易会被节点以 -32015 拒绝。
    let config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: None,
        max_supported_transaction_version: Some(0),
    };
    // Solana 里「交易签名」同时就是交易 ID（与 ETH 的 txid 地位相同）：
    // 查询不需要区块号，一个签名就够了——这与 NEAR「必须同时给发送者账户」形成对比。
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
    // 交易在区块内的序号，是 `Option`（未在区块中时为 None）。
    if let Some(index) = tx.transaction_index {
        println!("tx_index         : {index}");
    }
    // `version` 是枚举（Legacy / Number(0) …），用 `{:?}` 打印。
    println!("version          : {:?}", tx.transaction.version);

    match &tx.transaction.transaction {
        EncodedTransaction::Json(ui) => {
            println!(
                "signature        : {}",
                // `unwrap_or(&String::new())` 的取巧之处：
                // `.first()` 给的是 `Option<&String>`，而 `unwrap_or` 需要同类型的 `&String`，
                // 于是临时造一个空串的引用。因为它只在**没有签名**这一不可能分支被使用，
                // 这样写比 `map(String::as_str).unwrap_or("")` 更省一次分配。
                ui.signatures.first().unwrap_or(&String::new())
            );
            // message 有两种形态，取 recent_blockhash 的方式不同，但字段都在：
            // - Parsed：节点已把账户、指令解析成结构体；
            // - Raw：只给 base58 字符串和账户列表。
            let blockhash = match &ui.message {
                UiMessage::Parsed(msg) => Some(msg.recent_blockhash.as_str()),
                UiMessage::Raw(msg) => Some(msg.recent_blockhash.as_str()),
            };
            // `if let Some(recent) = blockhash`：只有 Some 才进分支，并把内部值绑定到 `recent`。
            if let Some(recent) = blockhash {
                println!("recent_blockhash : {recent}");
            }
        }
        // 其它编码（二进制 / 仅账户）无法展示细节，整体 Debug 打印一下。
        // `other` 绑定的是 `&EncodedTransaction`。
        other => println!("transaction      : {other:?}"),
    }

    // meta 是 `Option`：交易尚未执行（或节点未保留）时没有元数据。
    // `.as_ref()` 借出 `Option<&UiTransactionStatusMeta>`，避免把字段移走。
    if let Some(meta) = tx.transaction.meta.as_ref() {
        print_meta(meta);
    } else {
        println!("meta             : <无>");
    }
    Ok(())
}

/// 输出交易执行结果：状态、手续费、日志、余额变化。
///
/// 语法说明：参数 `&UiTransactionStatusMeta` 是不可变借用——只读打印，不需要所有权。
fn print_meta(meta: &UiTransactionStatusMeta) {
    match &meta.err {
        // `err` 为 `None` 即成功（Solana 用 `Option<TransactionError>` 表示，
        // 而不是一个 `bool` 或状态码）。
        None => println!("status           : Success"),
        Some(err) => println!("status           : Failed ({err:?})"),
    }
    println!("fee              : {} lamports", meta.fee);
    // `OptionSerializer<T>` 是 Solana SDK 自定义的「三态」枚举：
    // `Some(T)` / `None`（显式空）/ `Skip`（字段被省略，与 None 在 JSON 里表现不同）。
    // 因此这里**不能**用普通的 `if let Some(..)`，必须匹配 `OptionSerializer::Some`。
    //
    // `compute_units_consumed` 是 `OptionSerializer<u64>` 且 `u64: Copy`，
    // 所以 `match` 时直接绑定值（不加 `&`）。
    if let OptionSerializer::Some(units) = meta.compute_units_consumed {
        println!("compute_units    : {units}");
    }
    println!(
        "balances         : pre {:?} -> post {:?}",
        meta.pre_balances, meta.post_balances
    );
    // 日志是 `OptionSerializer<Vec<String>>`，不是 `Copy` 的，
    // 因此在 `&meta.log_messages` 上匹配，绑定出来的是 `&Vec<String>`。
    if let OptionSerializer::Some(logs) = &meta.log_messages {
        println!("logs             :");
        // 日志可能几十上百行，只打前 12 行避免刷屏。
        for line in logs.iter().take(12) {
            println!("  {line}");
        }
    }
}

/// `getBalance`：账户余额。
pub fn balance(client: &RpcClient, address: &str) -> Result<()> {
    // 变量标注 `let pubkey: Pubkey` 指定 `.parse()` 的目标类型
    // （`Pubkey` 实现了 `FromStr`）。
    let pubkey: Pubkey = address
        .parse()
        .with_context(|| format!("非法地址: {address}"))?;
    // Solana 的余额是 **u64 的 lamport**，`get_balance` 不需要任何 config——
    // 它默认按客户端的 commitment（本 SDK 为 confirmed）返回。
    //
    // 另一个坑：`getBalance` 对**不存在的账户**返回 0 而不是报错。
    // 「账户不存在」与「余额为零」在 Solana 上无法用这个接口区分，
    // 需要区分时得改用 `getAccountInfo`。
    let lamports = client
        .get_balance(&pubkey)
        .with_context(|| format!("查询余额失败: {pubkey}"))?;
    // `{pubkey}` 走 `Pubkey` 的 `Display`，即 base58 地址字符串。
    println!("address          : {pubkey}");
    println!(
        "balance          : {} SOL ({} lamports)",
        format_sol(lamports),
        lamports
    );
    Ok(())
}

/// 把 Unix 时间戳格式化为可读时间（不引入额外时间库）。
///
/// 只处理 **UTC** 且不含时区/闰秒——区块时间只是个参考值，精度到秒足够，
/// 为此引入 `chrono`（编译较慢、体积不小）并不划算。
fn chrono_like(timestamp: i64) -> String {
    // `.max(0)` 把负时间戳（1970 年之前，或异常数据）钳到 0，
    // 保证下面 `as u64` 的转换不会产生天文数字。
    // `as` 是显式 cast：`i64` → `u64`，已知非负所以安全。
    let secs = timestamp.max(0) as u64;
    // 拆成「自 epoch 起的天数」与「当天内的秒数」两部分，
    // 前者交给 civil_from_days 算年月日，后者直接做时分秒除法。
    let days = secs / 86_400;
    let time = secs % 86_400;
    // 1970-01-01 起的天数换算为年月日（Civil from days 算法）。
    let (y, m, d) = civil_from_days(days);
    // 格式化参数逐个看：
    //   `{y:04}` → 用**内联命名参数** y，宽度 4、左侧补零；
    //   `{:02}`  → 匿名位置参数，依次取后面的 `time / 3600` 等，宽度 2、左侧补零。
    // 注意命名参数与位置参数可以混用，位置参数从命名参数之后继续计数。
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

/// Howard Hinnant 的 civil_from_days 算法，避免引入 chrono。
///
/// 输入「自 1970-01-01 起的天数」，输出 `(年, 月, 日)`。
/// 该算法是**纯整数运算**的经典实现（见 Hinnant 的 `chrono`-compatible date algorithms），
/// 核心思路是先把日期平移到一个以 400 年为周期的「era」坐标系里，
/// 再用几个魔数常量做除法/取余，避开「逐月累加 + 逐闰年判断」的循环。
/// 返回元组 `(u64, u64, u64)` 而不是定义结构体，是因为它只在 [`chrono_like`] 里用一次。
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    // 把原点从 1970-01-01 平移到 0000-03-01：
    // 选 3 月开篇是为了把「闰日」放到一年的**最后**，
    // 于是闰年判断可以完全用整除表达，不需要分支。719_468 就是这个偏移量。
    let z = days + 719_468;
    // 146_097 = 一个 400 年周期的天数（格里高利历 400 年整循环）。
    let era = z / 146_097;
    let doe = z - era * 146_097; // day-of-era，周期内第几天
    // 由 doe 反推「年内第几年」（yoe = year-of-era）。
    // 三个除法依次补偿 4 年一闰、100 年不闰、400 年又闰。
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    // doy = day-of-year（年内第几天，从 0 起算）。
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    // 由 doy 反推月份：153 = 5 个月的平均天数 * 30.6 的定点近似。
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    // mp 以 3 月为 0，这里平移回「1 月为 1」的常规月份编号。
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    // 月份被归到 1、2 月时（原 3 月之前的部分在平移后属于下一年），年数要 +1。
    // 末行无分号 = 返回元组。
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 单元测试模块：`#[cfg(test)]` 保证只在 `cargo test` 时编译。
///
/// 这两个测试覆盖的是**纯算法**（时间格式化与日期换算），
/// 不需要网络，因此稳定且快。它们是 `civil_from_days` 那堆魔数唯一的防线——
/// 一旦有人改错常量，这两个断言会立刻失败。
#[cfg(test)]
mod tests {
    use super::*;

    /// Unix 时间戳 → 可读时间。
    #[test]
    fn formats_unix_timestamps() {
        assert_eq!(chrono_like(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(chrono_like(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }

    /// 天数 → 年月日，用已知日期做交叉验证。
    #[test]
    fn civil_conversion_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 1_700_000_000 秒 = 第 19675 天 = 2023-11-14
        assert_eq!(civil_from_days(19_675), (2023, 11, 14));
    }
}
