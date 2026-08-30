//! 只读类 JSON-RPC 查询：status / account / balance / block / tx / call。
//!
//! 本模块的每个函数都是「查完直接 `println!`」，返回 `Result<()>`——
//! 它服务于单链 CLI（`eth-rpc-cli`）。
//! 统一门面走的是 `adapter.rs`，那里只返回结构化数据、不做任何打印。
//! 两者刻意分开：打印逻辑与数据获取混在一起就无法被程序化复用。

// 语法说明：`use Trait as _;` 是「**匿名导入** trait」——
// 只把 trait 的**方法**引入作用域以便调用 `tx.value()` 这样的写法，
// 但不把 trait 的名字 `Transaction` 导入，避免与后面的
// `alloy::rpc::types::Transaction` 撞名。这是 Rust 里处理同名类型的惯用手法。
use alloy::consensus::Transaction as _;
// `BlockId` 是 alloy 对「区块引用」的统一抽象：可以是哈希、高度或 latest/safe/finalized 标签。
use alloy::eips::BlockId;
// `TransactionResponse` / `ReceiptResponse` 是 alloy 的**抽象层 trait**：
// 不同网络（ETH 主网、OP 栈等）的交易类型各不相同，但都实现这两个 trait，
// 于是下面的 `tx.from()` / `receipt.status()` 写法与具体类型解耦。
use alloy::network::{ReceiptResponse, TransactionResponse};
use alloy::primitives::{Address, B256, TxKind, U256};
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::types::{Transaction, TransactionInput, TransactionReceipt, TransactionRequest};
use anyhow::{Context, Result, anyhow};

use crate::units::format_wei;

/// 解析「命名标签」形式的区块引用：`latest` / `safe` / `finalized` / `earliest` / `pending`。
///
/// 领域说明：这五个是 JSON-RPC 规定的 **default block parameter**（EIP-1898 亦有涉及）。
/// 它们不指某个具体区块，而是「相对当前链头的一个位置」：
/// - `latest` —— 最新已出块（尚未最终确认，理论上可能回滚）；
/// - `safe` —— 已被多数验证者认可、回滚代价很高的块；
/// - `finalized` —— 完成最终性确认、不会回滚的块；
/// - `earliest` —— 创世块；
/// - `pending` —— 正在构造、尚未出块的区块。
///
/// 为什么单列一个函数：`parse_block_reference` 只认「空 / 纯数字 / 哈希」，
/// 把标签塞进去会让它同时承担「识别输入格式」与「映射到链上位置」两件事，
/// 而且 `latest` 会掉进「按哈希解析」的兜底分支，报出误导性的
/// 「非法区块哈希 latest」。拆开之后，一个函数只做一件事。
///
/// 返回值是 `Option` 而不是 `Result`：**不是标签并不算错误**，
/// 只是「本函数不负责」，由调用方继续尝试别的解析方式。
/// 用 `Option` 表达「不适用」比用错误码更准确。
pub fn parse_block_tag(reference: Option<&str>) -> Option<BlockId> {
    // 与 `parse_block_reference` 同样的归一化：先去首尾空白，再把空串折算成 `None`。
    // 末尾的 `?` 是 `Option` 的提前返回：为 `None` 时整个函数立即返回 `None`。
    let s = reference.map(str::trim).filter(|s| !s.is_empty())?;
    // `to_ascii_lowercase()` 生成一个新的 `String`（一次堆分配）。
    // 标签只有 5 个且很短，这点开销换来的可读性很划算；
    // 若这里是热路径，可改用 `eq_ignore_ascii_case` 逐项比较以避免分配。
    //
    // 语法说明：`match` 在 Rust 里是**表达式**，整个 `match` 的值就是命中分支的值，
    // 所以可以直接作为函数返回值（后面不写分号）。
    match s.to_ascii_lowercase().as_str() {
        "latest" => Some(BlockId::latest()),
        "safe" => Some(BlockId::safe()),
        "finalized" => Some(BlockId::finalized()),
        "earliest" => Some(BlockId::earliest()),
        "pending" => Some(BlockId::pending()),
        // 不是任何一个已知标签 → 本函数不负责，返回 `None`。
        _ => None,
    }
}

/// 解析区块引用：先试**命名标签**，未命中再回落到 `parse_block_reference`。
///
/// 顺序是关键：**必须先试标签**。否则 `latest` 会被当成区块哈希去解析并失败
/// （报出误导性的「非法区块哈希 latest」）——这正是当初要拆出
/// `parse_block_tag` 的直接原因。
pub fn parse_block_id(reference: Option<&str>) -> Result<BlockId> {
    // `if let Some(..)` 解构成功即命中标签，直接提前返回。
    // 这样写比 `parse_block_tag(..).map(Ok).unwrap_or_else(|| ..)?` 好读。
    if let Some(id) = parse_block_tag(reference) {
        return Ok(id);
    }
    parse_block_reference(reference)
}

/// 解析用户输入的区块引用：空 -> 最新区块；纯数字 -> 高度；否则 -> 区块哈希。
///
/// 判定顺序很关键：**先判数字再当哈希**。区块哈希是 0x 开头的 66 字符串，
/// 不含纯数字的可能，而高度本身就是纯数字，两者不会歧义。
///
/// 注意本函数**不处理** `latest` / `safe` 等命名标签——那是 `parse_block_tag` 的职责。
/// 需要「全形态支持」的调用方请用 `parse_block_id`。
pub fn parse_block_reference(reference: Option<&str>) -> Result<BlockId> {
    // 链式调用：`map(str::trim)` 去空白 → `filter(|s| !s.is_empty())` 把空串
    // 折算成 `None`。注意 `filter` 作用在 `Option` 上，不是迭代器上的那个。
    // 于是「没传」「传了空串」「传了一串空格」三种情况统一收敛为 `None`。
    match reference.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(BlockId::latest()),
        // **守卫分支**（match guard）：`Some(s) if 条件` 表示「解构成功且条件成立」。
        // 这里是「全是 ASCII 数字 → 当作高度」。
        Some(s) if s.chars().all(|c| c.is_ascii_digit()) => {
            // `context(..)` 给 `ParseIntError` 挂一句中文说明。
            // 注意 `context` 只接受**静态字符串**，要插值就得用下面的 `map_err`。
            Ok(BlockId::number(s.parse().context("区块高度超出范围")?))
        }
        // 走到这里说明既非空也非纯数字，按哈希解析；失败则报出原始输入。
        Some(s) => Ok(BlockId::hash(
            s.parse().map_err(|e| anyhow!("非法区块哈希 {s}: {e}"))?,
        )),
    }
}

/// `web3_clientVersion` + `eth_chainId` + `eth_blockNumber` + `eth_gasPrice`。
///
/// 领域说明：这四个 RPC 合起来能回答「连的是哪个节点、哪条链、同步到哪、行情多贵」，
/// 是排查「查不到数据」类问题的第一手信息——尤其是 chain id，
/// 它决定了后续签名的重放保护域，配错会直接导致交易被拒绝。
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
        // `U256::from(gas_price)`：RPC 返回的 gas 价格是 `u128`，
        // 而 `format_wei` 收的是 `U256`，用 `From` 做一次无损转换。
        format_wei(U256::from(gas_price), 9),
        gas_price
    );
    Ok(())
}

/// 账户概览：余额、下一笔可用 nonce、合约代码大小。
///
/// 领域说明：`code_size` 是区分 **EOA（外部账户）与合约**最廉价可靠的办法——
/// EOA 没有代码，返回空字节。这比查链上标签、比试调合约方法都稳。
pub async fn account(client: &RootProvider, address: Address) -> Result<()> {
    let balance = client
        .get_balance(address)
        .await
        // `with_context(|| format!(..))`：`Context` trait 的惰性版本，
        // 只在真的出错时才构造那段要插值的字符串。
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
        // `if / else` 是**表达式**，可以整体作为函数实参，不必先赋给临时变量。
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
    // 走 `parse_block_id` 而不是 `parse_block_reference`：前者额外支持
    // `latest` / `safe` / `finalized` 等命名标签。
    let block_id = parse_block_id(reference)?;
    let block = client
        .get_block(block_id)
        .await
        .context("查询区块失败")?
        // 连续两个 `?` 处理两层不同的失败：
        // 第一个是 **RPC 调用失败**（网络/节点错误），第二个是**节点返回了空**——
        // 即「查不到这个区块」。后者不是错误而是业务上的「不存在」，
        // 因此转成 `anyhow::Error` 而非 `None`。
        .context("节点未返回该区块（高度超前或不存在）")?;

    // `&block.header` 借用而非移动：下面还要用 `block.transactions`，
    // 若这里把 header 移出来（非 `Copy` 类型）就会部分移动导致后面不可用。
    let header = &block.header;
    println!("number         : {}", header.number);
    println!("hash           : {}", header.hash);
    println!("parent_hash    : {}", header.parent_hash);
    println!("timestamp      : {}", header.timestamp);
    println!("miner          : {}", header.beneficiary);
    println!("gas_used       : {}", header.gas_used);
    println!("gas_limit      : {}", header.gas_limit);
    // `base_fee_per_gas` 是 **EIP-1559**（伦敦升级）引入的每区块基础费，
    // 创世到伦敦之间的老区块没有这个字段，故为 `Option`。
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
///
/// 领域说明：**交易（Transaction）与回执（Receipt）是两个不同的对象**。
/// 交易里只有「意图」（发给谁、多少钱、gas limit），
/// 回执里才有「结果」（成功与否、实际用了多少 gas、日志）。
/// 一笔内存池里的交易能查到交易但查不到回执，因此下面对 `Option` 分别处理。
pub async fn get_tx(client: &RootProvider, tx_hash: B256) -> Result<()> {
    // 类型标注 `Option<Transaction>` 是必需的：`get_transaction_by_hash` 是泛型方法，
    // 需要靠标注确定反序列化成哪个具体交易类型。
    let tx: Option<Transaction> = client
        .get_transaction_by_hash(tx_hash)
        .await
        .with_context(|| format!("查询交易 {tx_hash} 失败"))?;
    let tx =
        tx.with_context(|| format!("交易 {tx_hash} 不在该节点数据中。历史交易请使用归档节点端点"))?;

    println!("hash           : {tx_hash}");
    println!("from           : {}", tx.from());
    // `tx.to()` 返回 `Option<Address>`：`None` 表示**合约创建交易**
    // （交易里只有 init code，没有接收地址）。这是 EVM 特有的语义，不能当错误处理。
    match tx.to() {
        Some(to) => println!("to             : {to}"),
        None => println!("to             : （合约创建交易）"),
    }
    println!("value          : {} ETH", format_wei(tx.value(), 18));
    println!("nonce          : {}", tx.nonce());
    println!("gas_limit      : {}", tx.gas_limit());
    // `input()` 是随交易携带的调用数据：普通转账为空，合约调用为 ABI 编码。
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
                    // 领域说明：回执 status = 0 表示**已上链但执行失败**（revert）。
                    // 它与「查不到」是两回事：失败的交易同样消耗 gas，且永久留痕。
                    "reverted"
                }
            );
            println!("gas_used       : {}", receipt.gas_used());
            println!(
                "gas_price_paid : {} gwei",
                // `effective_gas_price` 是**实际结算单价**。EIP-1559 下它等于
                // min(max_fee, base_fee + priority_fee)，与用户填的 max_fee 通常不相等，
                // 想算真实花费必须用这个而非 `gas_price` 字段。
                format_wei(U256::from(receipt.effective_gas_price()), 9)
            );
            println!("logs           : {} 条", receipt.inner.logs().len());
        }
        None => println!("status         : （尚未入块，无回执）"),
    }
    Ok(())
}

/// `eth_call`：调用合约的只读方法（无需签名、不消耗 gas）。
///
/// 领域说明：`eth_call` 在节点的**当前状态**上本地执行 EVM，不改变链上状态，
/// 因此不需要签名也不消耗 gas——它常被用来读 ERC-20 余额、模拟交易结果。
pub async fn call(client: &RootProvider, to: Address, data: Vec<u8>) -> Result<()> {
    // alloy 2.x 的 TransactionRequest 不再提供 with_to/with_input 链式方法，
    // 直接构造结构体；`to` 的类型是 TxKind 而非裸地址。
    //
    // 语法说明：`..Default::default()` 是**结构体更新语法**（struct update syntax）：
    // 显式列出关心的字段，其余用 `Default` 值补齐。这样将来 alloy 给结构体
    // 新增字段时，本处代码不会因缺字段而编译失败。
    // 注意它必须写在**最后**，且只能出现一次。
    let request = TransactionRequest {
        // `TxKind::Call(to)` 与 `TxKind::Create` 二选一：
        // 前者是「调用某地址」，后者是「部署新合约」（没有 to）。
        to: Some(TxKind::Call(to)),
        // `TransactionInput` 同时承载 input 与 data 两个历史别名字段，
        // 用 `From<Vec<u8>>` 转换。
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
    //
    // `from_utf8` 返回 `Result`，用 `if let Ok(..)` 而非 `unwrap`：
    // ABI 编码的二进制数据绝大多数不是合法 UTF-8，失败是**常态**而非异常。
    if let Ok(text) = std::str::from_utf8(&output) {
        let trimmed = text.trim();
        // 进一步过滤掉控制字符，避免把一段碰巧是合法 UTF-8 的二进制
        // 印到终端上造成乱码或终端控制序列注入。
        if !trimmed.is_empty() && trimmed.chars().all(|c| !c.is_control()) {
            println!("output (text)  : {trimmed}");
        }
    }
    Ok(())
}

/// 单元测试模块：`#[cfg(test)]` 保证只在 `cargo test` 时编译。
#[cfg(test)]
mod tests {
    use super::*;

    /// 五个命名标签都能识别。
    ///
    /// 断言用 alloy 自带的谓词（`is_latest()` 等）而不是比较枚举值：
    /// 这样即使日后 alloy 调整 `BlockId` 的内部结构，测试也不用跟着改。
    #[test]
    fn parses_all_named_tags() {
        assert!(parse_block_tag(Some("latest")).is_some_and(|id| id.is_latest()));
        assert!(parse_block_tag(Some("safe")).is_some_and(|id| id.is_safe()));
        assert!(parse_block_tag(Some("finalized")).is_some_and(|id| id.is_finalized()));
        assert!(parse_block_tag(Some("earliest")).is_some_and(|id| id.is_earliest()));
        assert!(parse_block_tag(Some("pending")).is_some_and(|id| id.is_pending()));
    }

    /// 大小写不敏感，且容忍首尾空白——命令行输入不该因为多敲一个空格就失败。
    #[test]
    fn tag_parsing_is_case_insensitive_and_trims() {
        for written in ["latest", "LATEST", "Latest", "  latest  "] {
            assert!(
                parse_block_tag(Some(written)).is_some_and(|id| id.is_latest()),
                "{written:?} 应被识别为 latest"
            );
        }
    }

    /// **不是**标签的输入必须返回 `None`，而不是报错——
    /// 这样调用方才能继续尝试其它解析方式。
    #[test]
    fn non_tag_inputs_return_none() {
        for input in [None, Some(""), Some("   "), Some("19000000"), Some("unknown")] {
            assert!(
                parse_block_tag(input).is_none(),
                "{input:?} 不应被当成标签"
            );
        }
        // 一个合法的区块哈希同样不是标签。
        let hash = "0x1c9b2f4b6e0d1a8c9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928";
        assert!(parse_block_tag(Some(hash)).is_none());
    }

    /// **回归测试**：`latest` 必须被解析成标签，而不是掉进「按哈希解析」的分支。
    ///
    /// 这是当初要拆出 `parse_block_tag` 的直接原因——修复前
    /// `acli block --reference latest` 会报「非法区块哈希 latest」。
    #[test]
    fn latest_is_a_tag_not_a_hash() {
        let id = parse_block_id(Some("latest")).expect("latest 必须解析成功");
        assert!(id.is_latest());
        assert!(!id.is_hash());
    }

    /// 统一入口 `parse_block_id`：标签 / 高度 / 哈希 / 缺省四种输入各得其所。
    #[test]
    fn parse_block_id_dispatches_every_form() {
        // 缺省 → 最新块。
        assert!(parse_block_id(None).unwrap().is_latest());
        // 标签 → 对应位置。
        assert!(parse_block_id(Some("finalized")).unwrap().is_finalized());
        // 纯数字 → 高度。
        assert!(parse_block_id(Some("19000000")).unwrap().is_number());
        // 十六进制 → 哈希。
        let hash = "0x1c9b2f4b6e0d1a8c9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928";
        assert!(parse_block_id(Some(hash)).unwrap().is_hash());
    }

    /// `parse_block_reference` 保持原职责：不认标签，遇到标签会按哈希解析并失败。
    ///
    /// 这条测试把「两个函数的分工」钉死，防止日后有人又把标签逻辑塞回去。
    #[test]
    fn parse_block_reference_still_rejects_tags() {
        assert!(parse_block_reference(Some("latest")).is_err());
        // 但它照常处理高度与缺省。
        assert!(parse_block_reference(Some("19000000")).unwrap().is_number());
        assert!(parse_block_reference(None).unwrap().is_latest());
    }
}
