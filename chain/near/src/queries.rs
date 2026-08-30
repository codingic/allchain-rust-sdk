//! 只读类 JSON-RPC 查询：status / view_account / view_access_key / block / tx / call_function。
//!
//! ## 本模块的定位
//! 与 SOL 那侧一样，这里分两类函数：
//! - `pub async fn xxx(..) -> Result<()>`：**CLI 直调**版，内部直接 `println!`；
//! - `pub async fn fetch_xxx(..) -> Result<T>`：**数据层**版，返回结构化数据给 adapter 用
//!   （目前只有 `fetch_account` 一个）。
//! 新增查询时请照这个模式来：打印逻辑不要混进数据函数里。
//!
//! ## NEAR 查询的两个要点
//! 1. **区块引用统一用 `BlockReference`**：它可以是「高度」「哈希」或「finality」三种之一，
//!    本模块里只读请求一律用 `Finality::Final`（等最终确认，保证读到的数据不会回滚）。
//! 2. **查交易必须同时给发送者账户**：NEAR 的交易 ID 是「(tx_hash, sender_account)」二元组，
//!    光有哈希节点无法定位（这与 ETH/SOL 只需一个哈希就够完全不同）。
//!    统一接口约定把它们用 `@` 拼成一个串，见 adapter.rs。

// anyhow 四件套：
// - `Result` → `Result<T, anyhow::Error>` 的别名；
// - `Context` → trait，提供 `.context(静态值)` 与 `.with_context(闭包)`；
// - `anyhow!` → 宏，就地构造一个 anyhow 错误；
// - `bail!`   → 宏，等价于 `return Err(anyhow!(..))`。
use anyhow::{Context, Result, anyhow, bail};
// `PublicKey` 是 NEAR 的公钥枚举（支持 ed25519 / secp256k1）。
use near_crypto::PublicKey;
// `methods` 模块下每个子模块对应一个 JSON-RPC 方法（如 `methods::status`），
// 里面各有 request / response 类型。这是 near-jsonrpc-client 的典型组织方式。
use near_jsonrpc_client::{JsonRpcClient, methods};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_jsonrpc_primitives::types::transactions::TransactionInfo;
// `BlockId` / `BlockReference` / `Finality` 三件套：描述「查哪个区块」；
// `FunctionArgs` 是合约调用参数的包装类型；`AccountId` 是**具名账户**的字符串包装。
use near_primitives::types::{AccountId, BlockId, BlockReference, Finality, FunctionArgs};
use near_primitives::views::{QueryRequest, TxExecutionStatus};

use crate::units::format_near;

/// 解析用户输入的区块引用：空 -> 最新 final；纯数字 -> 高度；否则 -> 区块哈希。
///
/// 这是**启发式**判定：NEAR 的区块哈希是 base58（长度 43-44、含大小写字母与数字），
/// 而高度是纯十进制数字，两者不会混淆，所以「全是数字就当高度」是安全的。
///
/// 注意缺省用的是 `Finality::Final` 而非 `Finality::Optimistic`：
/// 最终确认的区块不会回滚，对「查余额」「查状态」这类场景更合适，
/// 代价是数据比最新块滞后几秒。
pub fn parse_block_reference(reference: Option<&str>) -> Result<BlockReference> {
    match reference.map(str::trim).filter(|s| !s.is_empty()) {
        // 没给 / 空串 → 取最新最终确认块。
        None => Ok(BlockReference::Finality(Finality::Final)),
        // **带守卫的匹配臂**（match guard）：先匹配 `Some(s)`，再要求 `if` 条件成立。
        // 与 `Some(s) if ..` 相对的是「在分支体里再写 if」，前者的好处是
        // 条件不成立时会**继续往下匹配**其它分支，而不是直接进分支体。
        Some(s) if s.chars().all(|c| c.is_ascii_digit()) => Ok(BlockReference::BlockId(
            // `BlockReference::BlockId(BlockId::Height(..))` 是两层嵌套的枚举构造：
            // 外层区分「按 finality 还是按 block id」，内层区分「按高度还是按哈希」。
            BlockId::Height(s.parse().context("区块高度超出范围")?),
        )),
        // 其余一律按哈希解析；失败时给出带原始输入的错误。
        Some(s) => Ok(BlockReference::BlockId(BlockId::Hash(
            s.parse().map_err(|e| anyhow!("非法区块哈希 {s}: {e}"))?,
        ))),
    }
}

/// `status`：节点同步状态、链 ID、最新区块。
pub async fn status(client: &JsonRpcClient) -> Result<()> {
    // `.call(..)` 是 async 方法，返回 `Result<Response, JsonRpcError>`。
    // `methods::status::RpcStatusRequest` 是一个**无字段**的请求结构体（unit-like struct），
    // 因为 `status` 这个 RPC 方法本来就不需要任何参数。
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
        // `if 条件 { "a" } else { "b" }` 是**表达式**，可以直接作为函数参数。
        // 这是 Rust 没有三元运算符的原因之一——`if/else` 本身就返回值。
        if status.sync_info.syncing {
            "yes"
        } else {
            "no"
        }
    );
    // `.len()` 给出当前 epoch 的验证者数量；主网上约 100+。
    println!("validator_count    : {}", status.validators.len());
    Ok(())
}

/// `query / view_account`：账户余额、已占用存储、合约 code hash。
///
/// **本模块里的「数据层」函数**：不打印，直接返回结构化视图给 adapter 复用。
///
/// 语法说明：`&AccountId` 是**具名账户**的借用。NEAR 没有「地址」概念，
/// 账户就是一个人类可读的名字（`alice.near`），由链上按名字索引。
///
/// 返回类型写的是完整路径 `near_primitives::views::AccountView`
/// （而不是先 `use` 再写 `AccountView`），因为这个类型只在这里出现一次。
pub async fn fetch_account(
    client: &JsonRpcClient,
    account_id: &AccountId,
) -> Result<near_primitives::views::AccountView> {
    // NEAR 的 RPC 把「查账户」「查 access key」「调用合约只读方法」统一收敛到
    // 一个 `query` 方法上，靠 `request` 字段区分具体语义——
    // 这与 REST 风格「一个端点一个动作」的组织方式差别很大。
    let response = client
        .call(methods::query::RpcQueryRequest {
            // 在「最新最终确认块」的快照上查询，保证结果不会因短暂分叉而变。
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::ViewAccount {
                // `account_id.clone()`：结构体构造需要**取得所有权**，
                // 而我们只有 `&AccountId` 的借用，因此必须克隆一份。
                // 这是 Rust 里最常见的「借用来读、要存就得克隆」模式。
                account_id: account_id.clone(),
            },
        })
        .await
        // `with_context` 的闭包形式：出错时才执行 `format!`。
        // `{account_id}` 走 `AccountId` 的 `Display`，直接印出账户名。
        .with_context(|| format!("查询账户失败: {account_id}"))?;

    // `response.kind` 是一个枚举，标明响应体到底是哪一种查询结果。
    // 虽然我们请求的是 ViewAccount，但类型系统仍要求处理其它可能——
    // 这是「让非法状态无法被表示」的 Rust 风格的代价与收益。
    match response.kind {
        // 拿到账户视图，直接返回。
        QueryResponseKind::ViewAccount(view) => Ok(view),
        // 理论上不会发生；真发生了说明 SDK 版本与节点行为不一致，明确报错。
        // `bail!` = `return Err(anyhow!(..))`；`{other:?}` 用 Debug 打印整个枚举值。
        other => bail!("非预期的 RPC 响应类型: {other:?}"),
    }
}

/// `query / view_account` 的打印版：输出账户的完整信息。
pub async fn view_account(client: &JsonRpcClient, account_id: &AccountId) -> Result<()> {
    // 复用上面的数据层函数，避免把「取余额」的逻辑写两遍。
    let account = fetch_account(client, account_id).await?;
    println!("account_id   : {account_id}");
    println!(
        "balance      : {} NEAR ({} yoctoNEAR)",
        // `account.amount` 是 `Balance`（NEAR 的金额包装类型），
        // `.as_yoctonear()` 取出里面的 `u128`。包装类型的存在是为了
        // 避免把「金额」和「普通整数」混用。
        format_near(account.amount.as_yoctonear()),
        account.amount.as_yoctonear()
    );
    // `locked` 是**质押锁定**的余额：NEAR 的质押不会离开账户，
    // 只是被标记为锁定，因此「可用余额」与「总余额」是两个字段。
    println!(
        "locked       : {} NEAR ({} yoctoNEAR)",
        format_near(account.locked.as_yoctonear()),
        account.locked.as_yoctonear()
    );
    // 存储占用（字节数）。NEAR 要求账户为链上存储**质押**相应数量的 NEAR，
    // 这是它「存储租金」模型的一部分。
    println!("storage_used : {} bytes", account.storage_usage);
    // 合约账户才有 code；普通账户的 code_hash 是全零（11111111111111111111111111111111）。
    println!("code_hash    : {}", account.code_hash);
    // global contract 是较新的特性：多个账户共享同一份合约代码。
    // 它是 `Option`，旧节点或普通账户上没有。
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
///
/// 除了打印，它还**返回 nonce**——调用方（transactions.rs）要用「当前 nonce + 1」
/// 来构造下一笔交易。这是「一个函数兼顾展示与取值」的取舍：
/// 为了不再多一次 RPC 往返，就让打印与取值合并。
pub async fn view_access_key(
    client: &JsonRpcClient,
    account_id: &AccountId,
    public_key: &PublicKey,
) -> Result<u64> {
    let response = client
        .call(methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::ViewAccessKey {
                // 注意 key 是「账户 + 公钥」二元组：NEAR 的 nonce 是**每把 access key 独立**递增的，
                // 不是每个账户一个（这与 EVM 的账户 nonce 不同）。
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
            // `permission` 是枚举（FullAccess / FunctionCall），用 `{:?}` 打印。
            println!("permission   : {:?}", view.permission);
            // 响应里带回「这个快照对应的区块高度」，便于调用方知道 nonce 的时效。
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
            // 复用上面的解析逻辑；`?` 把 anyhow 错误直接抛给调用方。
            block_reference: parse_block_reference(reference)?,
        })
        .await
        .context("查询区块失败")?;

    // NEAR 的区块头字段与 EVM 区块类似，都是「高度 + 本块哈希 + 父哈希 + 时间戳」。
    println!("height       : {}", block.header.height);
    println!("hash         : {}", block.header.hash);
    println!("prev_hash    : {}", block.header.prev_hash);
    // 注意这是**纳秒**级时间戳（NEAR 内部用 u64 纳秒表示），
    // 与多数链的「Unix 秒」不同；adapter 里会把 `timestamp` 当场打印，
    // 若要换算成秒需要除以 1_000_000_000。
    println!("timestamp    : {}", block.header.timestamp);
    // 出块者（该高度上的 block producer）。
    println!("author       : {}", block.author);
    // NEAR 是**分片**链：一个区块由多个 chunk 组成，每个 shard 一个。
    // 这里的 `chunks` 只是 chunk 的**摘要**（chunk 正文需要单独查询）。
    println!("chunks       : {} 个", block.chunks.len());
    Ok(())
}

/// `tx`：按交易哈希 + 发送者查询执行结果。
///
/// ## 为什么要 `tx_hash + sender` 两个参数
/// NEAR 的交易 ID 是「(哈希, 发送者账户)」**二元组**，而不是一个单独的哈希。
/// 原因在于 NEAR 的分片架构：交易由发送者所在分片处理，
/// 节点需要知道去哪个分片查，光有哈希无法路由。
/// 这与 ETH / BTC / SOL「一个哈希走天下」的模型是根本性差异，
/// 也是统一门面里 NEAR 的交易参数要写成 `<tx_hash>@<sender.near>` 的原因。
pub async fn get_tx(
    client: &JsonRpcClient,
    tx_hash: &str,
    sender: &AccountId,
    wait_until: TxExecutionStatus,
) -> Result<()> {
    // 字符串哈希 → `CryptoHash`。`.parse()` 的目标类型由下面的赋值处推断。
    let tx_hash = tx_hash
        .parse()
        .map_err(|e| anyhow!("非法交易哈希 {tx_hash}: {e}"))?;

    let response = client
        .call(methods::tx::RpcTransactionStatusRequest {
            // `TransactionInfo` 枚举的 `TransactionId` 变体，正是「哈希 + 发送者」二元组。
            // （另一个变体是 `Transaction`（直接提交交易体），用于广播场景。）
            transaction_info: TransactionInfo::TransactionId {
                tx_hash,
                // `.clone()`：结构体要取得所有权，而我们只有借用。
                sender_account_id: sender.clone(),
            },
            // 等到哪个执行阶段才返回，由调用方决定（见 network.rs 的 WaitUntilArg）。
            wait_until,
        })
        .await
        // 错误信息里直接给出「换归档端点」的建议——这是 NEAR 最高频的困惑点，
        // 与其让用户去翻文档，不如在报错里说清楚。
        .with_context(|| {
            format!(
                "查询交易 {tx_hash} 失败：交易不在该节点数据中或尚未入块。\
                 历史交易请使用归档端点（如 https://archival-rpc.mainnet.near.org）"
            )
        })?;

    // `final_execution_outcome` 是 `Option`：只在交易已执行完（达到 wait_until 的阶段）才有值。
    // `.context(..)` 直接用在 `Option` 上（anyhow 为 `Option` 提供了 `Context` 实现），
    // 把 `None` 转成一条带说明的错误——比 `ok_or_else(..)` 更省事。
    let outcome = response
        .final_execution_outcome
        .context("节点未返回执行结果（交易可能不存在或尚未入块）")?
        // `into_outcome()` 把「带 RPC 包装的响应」拆成纯粹的执行结果结构。
        .into_outcome();

    // `{:#?}` 是 **pretty debug**：多行缩进打印枚举，比 `{:?}` 的一行更易读。
    println!("status       : {:#?}", outcome.status);
    println!("signer       : {}", outcome.transaction.signer_id);
    println!("receiver     : {}", outcome.transaction.receiver_id);
    println!("actions      : {} 个", outcome.transaction.actions.len());
    println!(
        "gas_burnt    : {:.2} TGas",
        // `as_gas()` 取出 gas unit（u64），`as f64 / 1e12` 换算成 TGas。
        // 这里用浮点是安全的：gas 是资源预算而非金额，精度不敏感。
        // `{:.2}` 是格式化微语言：保留 2 位小数。
        outcome.transaction_outcome.outcome.gas_burnt.as_gas() as f64 / 1e12
    );
    // receipts 是交易的「后续执行步骤」：跨合约调用、转账到账、退款都会各产生一个。
    println!("receipts     : {} 个", outcome.receipts_outcome.len());
    Ok(())
}

/// `query / call_function`：调用合约的只读方法（无需签名、不消耗 gas）。
///
/// 这是 NEAR 上的「view function」调用：只读、免费、立刻返回。
/// 与之相对的是 `transactions::function_call`（需要签名并消耗 gas 的变更调用）。
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
                // `method.to_string()`：`&str` → `String`，因为结构体字段拥有数据。
                method_name: method.to_string(),
                // 合约参数在 NEAR 上是一段**不透明的字节**（通常是 JSON 序列化后的结果）。
                // `FunctionArgs::from(args.to_vec())`：`&[u8]` → `Vec<u8>` → `FunctionArgs`。
                // `to_vec()` 是必须的——`from` 需要所有权，不能只借用。
                args: FunctionArgs::from(args.to_vec()),
            },
        })
        .await
        .with_context(|| format!("调用 {contract}.{method} 失败"))?;

    match response.kind {
        QueryResponseKind::CallResult(result) => {
            println!("logs:");
            // `&result.logs` 借用而非移走：下面还要用 `result.result`。
            for line in &result.logs {
                println!("  {line}");
            }
            // 合约返回值也是不透明字节。约定俗成是 JSON，所以这里尝试按 JSON 解析；
            // 解析失败（不是 JSON）时退回 `Value::Null`，下面再按原始文本打印。
            //
            // `unwrap_or(..)` 而不是 `unwrap_or_else(..)`：`Value::Null` 的构造成本极低。
            let json: serde_json::Value =
                serde_json::from_slice(&result.result).unwrap_or(serde_json::Value::Null);
            if json.is_null() {
                // `String::from_utf8_lossy` 是**有损但绝不失败**的 UTF-8 转换：
                // 非法字节会被替换成 U+FFFD，而不是返回 Err。
                // 用于打印场景正合适（打印不该因为编码问题而失败）。
                println!("result (raw) : {}", String::from_utf8_lossy(&result.result));
            } else {
                // `to_string_pretty(..)` 返回 `Result`（理论上不会失败），故用 `?`。
                println!("result (json): {}", serde_json::to_string_pretty(&json)?);
            }
            println!("block_height : {}", response.block_height);
            Ok(())
        }
        other => bail!("非预期的 RPC 响应类型: {other:?}"),
    }
}
