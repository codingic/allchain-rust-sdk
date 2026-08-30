//! near 链对统一 `ChainClient` 契约的实现。
//!
//! ## 与 SOL 那侧最大的不同：不需要 `spawn_blocking`
//! NEAR 官方的 `near-jsonrpc-client` **本身就是 async 的**（基于 reqwest 的异步客户端），
//! 所以这里可以直接 `.await`，没必要像 SOL 那样把同步调用包进阻塞线程池。
//! 对本文件而言，这意味着代码比 `chain/sol/src/adapter.rs` 简单不少——
//! 没有 `Arc<RpcClient>`，也没有那个泛型 `blocking()` 辅助函数。
//!
//! ## NEAR 的三个适配要点
//! 1. **账户即名字**：统一契约里的 `address` 参数，在 NEAR 上传的是**具名账户**
//!    （`alice.near`），不是公钥也不是哈希。账户名的合法性由 `AccountId::from_str` 校验
//!    （小写字母、数字、`-` / `_`、点分层级、长度 2-64）。
//! 2. **查交易必须带发送者**：NEAR 的交易 ID 是「(哈希, 发送者账户)」二元组。
//!    统一接口约定把它们拼成 `<tx_hash>@<sender.near>`，本文件负责拆分。
//! 3. **历史数据要换归档端点**：常规节点只保留近期数据，
//!    查老交易会得到含糊的 `UNKNOWN_TRANSACTION`，需在错误里提示用户换
//!    `https://archival-rpc.mainnet.near.org`。

// `FromStr` 必须引入作用域，才能调用 `AccountId::from_str(..)` / `.parse()`。
use std::str::FromStr;

// `#[async_trait]` 属性宏：把 trait 里的 `async fn` 改写成返回 `Pin<Box<dyn Future>>`
// 的普通 fn（稳定版 Rust 不支持在 trait 里直接写 async fn）。详见 core/src/traits.rs。
use async_trait::async_trait;
// NEAR 的公钥类型：`PublicKey` 是枚举（ED25519 / SECP256K1），
// 两个变体各自包装定长数组，因此从字节构造时长度必须精确匹配（32 / 64）。
use near_crypto::{ED25519PublicKey, PublicKey, Secp256K1PublicKey};
use near_jsonrpc_client::{JsonRpcClient, methods};
// `TransactionInfo` 描述「如何定位一笔交易」：
// 按 (哈希 + 发送者) 查询，或直接提交交易体。
use near_jsonrpc_primitives::types::transactions::TransactionInfo;
use near_primitives::action::{Action, TransferAction};
// `AccountId` 具名账户；`Balance` 金额包装（内部是 yoctoNEAR 的 u128）。
use near_primitives::types::{AccountId, Balance};
use near_primitives::views::{ActionView, FinalExecutionStatus, TxExecutionStatus};
// `json!` 宏：用字面量语法构造 `serde_json::Value`，用来填充各 View 的 `extra` 字段。
use serde_json::json;

use allchain_core::{
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, SdkError, StatusView,
    TransferRequest, TransferView, TxStatus, TxView, hexutil,
};

use crate::network::{self, NetworkArg};
use crate::queries::{fetch_account, parse_block_reference};

/// NEAR 客户端。
///
/// 字段都是私有的：外部只能通过 `ChainClient` trait 的方法访问，
/// 拿不到内部的 `JsonRpcClient`，于是「端点」无法被意外改动。
///
/// 与 SOL 那侧的 `SolClient` 对比：这里的 `client` **没有**包 `Arc`。
/// 因为 NEAR 的客户端是 async 的，不需要把所有权搬进 `spawn_blocking` 的闭包，
/// 直接放在结构体里借用即可。
pub struct NearClient {
    /// 网络名（`mainnet` / `testnet` / `localnet` / `custom`）。
    network: String,
    /// 实际连接的 RPC 端点。
    rpc_url: String,
    /// 底层的 async JSON-RPC 客户端。
    client: JsonRpcClient,
}

// 固有实现块：构造器 + 私有辅助方法。
impl NearClient {
    /// 构造客户端。
    ///
    /// 优先级：**显式 `rpc_url` > 网络名 > 默认 mainnet**。
    /// 给了 `rpc_url` 时网络名一律记为 `"custom"`——无法从 URL 反推它属于哪个网络，
    /// 与其猜错不如如实标注。
    ///
    /// 语法说明：两个参数都是 `Option<&str>`，`None` 表示「没给」。
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        // `Option` 组合子三连，把「可能没给、可能给了空串」归一化成一个 `Option<String>`：
        // - `.map(str::trim)`：`str::trim` 是**函数指针**（签名 `fn(&str) -> &str`），
        //   可直接对 `Option<&str>` map；
        // - `.filter(|s| !s.is_empty())`：把空串（含纯空白）筛成 `None`；
        // - `.map(str::to_string)`：`&str` → `String`，取得所有权以便存进结构体。
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        // `match` 两分支都返回 `(String, String)` 元组，再用 `let (a, b) = ..` **解构**。
        let (network_name, url) = match custom {
            Some(url) => ("custom".to_string(), url),
            None => {
                let net = parse_network(network)?;
                // `.as_str()` / `.rpc_url()` 都返回 `&'static str`，
                // `.to_string()` 转成 `String` 才能存进字段（字段类型是有所有权的 `String`）。
                (net.as_str().to_string(), net.rpc_url().to_string())
            }
        };

        let client = network::connect(&url);
        // 字段初始化简写：`client` 等价于 `client: client`。
        Ok(Self {
            network: network_name,
            rpc_url: url,
            client,
        })
    }

    /// 把底层错误统一归类成 `SdkError`。
    ///
    /// 语法说明：`impl std::fmt::Display` 是**参数位置**的 `impl Trait`，
    /// 等价于写成泛型 `fn fail<E: std::fmt::Display>(&self, context: &str, err: E)`
    /// ——前者更短，代价是调用方无法用 turbofish 指定具体类型（这里也不需要）。
    /// 用 `Display` 而不是具体的错误类型，是因为底层错误来自好几个不同 crate，
    /// 它们唯一的共同点就是「能被打印出来」。
    fn fail(&self, context: &str, err: impl std::fmt::Display) -> SdkError {
        // `classify` 按关键词把错误归类（超时 → NetworkError、not found → NotFound 等），
        // 于是各链的错误码风格统一，上层不必解析 NEAR 特有的错误文案。
        // `{}` 走 `Display`（不是 `{:?}`）——这里要的是干净的单行信息给 classify 匹配。
        allchain_core::error::classify(&format!("{context}: {err}"))
    }
}

/// 解析网络名；`None` 与空串都视为默认 **mainnet**（与其它链一致：默认主网）。
fn parse_network(raw: Option<&str>) -> Result<NetworkArg, SdkError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        // 没给 / 空串 → 默认主网。
        None => Ok(NetworkArg::Mainnet),
        Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("testnet") => Ok(NetworkArg::Testnet),
        Some("localnet") => Ok(NetworkArg::Localnet),
        // `other` 绑定剩余的所有 `&str`。错误信息里把可选值一并列出——
        // 与其让用户去翻文档，不如在报错里直接告诉他能填什么。
        Some(other) => Err(SdkError::invalid_argument(format!(
            "NEAR 不支持的网络: {other}（可选 mainnet / testnet / localnet）"
        ))),
    }
}

// 下面是** trait 实现块**（`impl Trait for Type`），为 `NearClient` 实现 core 的统一契约。
// 加上 `#[async_trait]` 后，块里的 `async fn` 会被改写成返回装箱 Future 的普通 fn，
// 于是 `NearClient` 能被装进 `Box<dyn ChainClient>` / `Arc<dyn ChainClient>`，
// 上层门面据此在运行期按链名分发（运行时多态）。
#[async_trait]
impl ChainClient for NearClient {
    /// 所属链，恒为 `ChainKind::Near`。
    fn kind(&self) -> ChainKind {
        ChainKind::Near
    }

    /// 网络名。`&self.network` 把 `String` **借成** `&str`（deref 强制转换），
    /// 零分配——调用方通常只是读一下。
    fn network(&self) -> &str {
        &self.network
    }

    /// 实际使用的 RPC 端点。
    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        // 直接 `.await`——NEAR 的客户端是 async 的，不需要阻塞线程池包装。
        // `RpcStatusRequest` 是无字段的请求结构体（该 RPC 方法没有参数）。
        let status = self
            .client
            .call(methods::status::RpcStatusRequest)
            .await
            // `.map_err(|e| self.fail(..))` 把底层错误交给统一的分类函数；
            // 这里用 `map_err` 而非 `?` + `with_context`，是因为 `fail` 返回 `SdkError`
            // 而不是 anyhow 的错误，类型不同，得显式转换。
            .map_err(|e| self.fail("查询节点状态失败", e))?;

        Ok(
            StatusView::new(ChainKind::Near, &self.network, &self.rpc_url)
                .with_height(status.sync_info.latest_block_height)
                .with_hash(status.sync_info.latest_block_hash.to_string())
                .with_version(status.version.version)
                // 下面四个是 NEAR 专有信息，放进 extra
                // （`#[serde(flatten)]` 会把它们平铺到 JSON 顶层，不破坏公共 schema）。
                .with_extra(json!({
                    // 链 ID（mainnet / testnet 字样），便于确认连对了网络。
                    "chain_id": status.chain_id,
                    // 协议版本号：NEAR 用协议版本而非区块高度来门控新特性。
                    "protocol_version": status.protocol_version,
                    // 节点是否还在追块。
                    "syncing": status.sync_info.syncing,
                    // 当前 epoch 的验证者数量，主网上约 100+。
                    "validator_count": status.validators.len(),
                })),
        )
    }

    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        // 统一契约的 `address` 在 NEAR 上是**具名账户**（`alice.near`），
        // 不是公钥也不是哈希。`parse_account` 负责校验其合法性。
        let account_id = parse_account(address)?;
        let account = fetch_account(&self.client, &account_id)
            .await
            .map_err(|e| self.fail("查询账户失败", e))?;

        // `account.amount` 是 NEAR 的 `Balance` 包装类型，
        // `.as_yoctonear()` 取出内部的 `u128`。
        // 注意统一契约用 `u128` 承载所有链的最小单位整数，正好匹配 NEAR 的 24 位小数。
        Ok(BalanceView::new(
            ChainKind::Near,
            &self.network,
            address,
            account.amount.as_yoctonear(),
        )
        .with_extra(json!({
            // 质押**锁定**的余额：NEAR 的质押不会离开账户，只是被标记为锁定，
            // 因此「可用余额」与「总余额」是两个不同的数——这是 NEAR 特有的概念。
            "locked": account.locked.as_yoctonear().to_string(),
            // 链上存储占用（字节）。NEAR 要求账户为存储质押相应数量的 NEAR，
            // 占用越多、被锁定的余额越多。
            "storage_usage": account.storage_usage,
            // 合约账户才有代码；普通账户的 code_hash 是全零。
            "code_hash": account.code_hash.to_string(),
        })))
    }



    /// 链头高度：最新区块高度（裸 `u64`）。
    async fn last_block_height(&self) -> Result<u64, SdkError> {
        let block_reference = parse_block_reference(None)
            .map_err(|e| SdkError::invalid_argument(e.to_string()))?;
        let block = self
            .client
            .call(methods::block::RpcBlockRequest { block_reference })
            .await
            .map_err(|e| self.fail("查询最新区块失败", e))?;
        Ok(block.header.height)
    }

    /// 按高度查询区块。
    async fn block_by_height(&self, height: u64) -> Result<BlockView, SdkError> {
        let block_reference = parse_block_reference(Some(&height.to_string()))
            .map_err(|e| SdkError::invalid_argument(e.to_string()))?;
        let block = self
            .client
            .call(methods::block::RpcBlockRequest { block_reference })
            .await
            .map_err(|e| self.fail("查询区块失败", e))?;
        Ok(BlockView::new(ChainKind::Near, &self.network, block.header.hash.to_string())
            .with_height(block.header.height)
            .with_parent(block.header.prev_hash.to_string())
            .with_timestamp(block.header.timestamp as i64)
            .with_extra(json!({
                "author": block.author.to_string(),
                "chunks": block.chunks.len(),
            })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        // NEAR 查询交易必须同时给出发送者账户，统一接口约定用 `@` 分隔。
        //
        // `split_once('@')` 按第一个 `@` 把字符串切成前后两半，返回 `Option<(&str, &str)>`。
        // 参数是**字符** `'@'`（单引号）而不是字符串 `"@"`。
        //
        // `.ok_or_else(|| ..)` 把 `None` 转成错误，且**惰性**构造错误对象
        // （对比 `.ok_or(..)` 会无条件构造）。
        let (tx_hash_str, sender_str) = hash.split_once('@').ok_or_else(|| {
            SdkError::invalid_argument(
                "NEAR 查询交易需要发送者账户，格式为 <tx_hash>@<sender.near>；\
                 历史交易请改用归档端点（如 https://archival-rpc.mainnet.near.org）",
            )
        })?;
        // 前半段解析成 `CryptoHash`。`.trim()` 去掉可能存在的空格。
        let tx_hash = tx_hash_str
            .trim()
            .parse()
            .map_err(|_| SdkError::invalid_argument(format!("非法交易哈希: {tx_hash_str}")))?;
        // 后半段解析成 `AccountId`。
        let sender = parse_account(sender_str)?;

        let response = self
            .client
            .call(methods::tx::RpcTransactionStatusRequest {
                // 「哈希 + 发送者」二元组——光有哈希节点无法定位交易（分片路由需要发送者）。
                transaction_info: TransactionInfo::TransactionId {
                    tx_hash,
                    // 按值移入（上面 `parse_account` 返回的是拥有所有权的 `AccountId`）。
                    sender_account_id: sender,
                },
                // 等到「所有 receipt 均已最终确认」才返回。
                // 这是最慢但信息最全的一档：能拿到完整的手续费、日志与最终状态。
                wait_until: TxExecutionStatus::Final,
            })
            .await
            .map_err(|e| self.fail("查询交易失败", e))?;

        // `final_execution_outcome` 是 `Option`：只有交易已执行完才有值。
        // `ok_or_else` 的闭包里构造一条 `not_found` 错误（而不是 InvalidArgument）——
        // 格式合法但查不到，语义上属于 NotFound。
        let outcome = response
            .final_execution_outcome
            .ok_or_else(|| {
                SdkError::not_found(
                    "节点未返回执行结果（交易可能不存在或尚未入块，历史交易请使用归档端点）",
                )
            })?
            // `into_outcome()` 把「带 RPC 包装的响应」拆成纯粹的执行结果结构。
            .into_outcome();

        // 把 NEAR 的 5 档执行状态映射到统一契约的 4 档。
        let status = match &outcome.status {
            // 成功，并带有返回值（可能为空字符串）。
            near_primitives::views::FinalExecutionStatus::SuccessValue(_) => TxStatus::Success,
            // 执行失败（合约 panic、余额不足等）。
            near_primitives::views::FinalExecutionStatus::Failure(_) => TxStatus::Failed,
            // 尚未开始 / 已开始但未完成 —— 都归为「待确认」。
            // `|` 是**或模式**：两个变体共用同一个分支体。
            near_primitives::views::FinalExecutionStatus::NotStarted
            | near_primitives::views::FinalExecutionStatus::Started => TxStatus::Pending,
        };

        // 手续费 = 交易本身 + 所有 receipt 燃烧的 token。
        //
        // NEAR 的手续费是**分阶段燃烧**的：交易执行烧一部分，
        // 每个 receipt（含跨合约调用与 gas 退款）又各烧一部分，必须累加才是真实总费用。
        // 只取 `transaction_outcome` 会显著低估。
        let mut fee = outcome
            .transaction_outcome
            .outcome
            .tokens_burnt
            .as_yoctonear();
        for receipt in &outcome.receipts_outcome {
            // `saturating_add` 是**饱和加法**：溢出时停在 `u128::MAX` 而不是 panic
            // （debug 下 panic、release 下回绕是 bug 温床）。
            // 手续费累加理论上不会溢出，但用饱和运算可以彻底排除这种可能。
            fee = fee.saturating_add(receipt.outcome.tokens_burnt.as_yoctonear());
        }

        // 转账金额从 Transfer action 累加。
        //
        // NEAR 一笔交易可以包含**多个** Action（比如「先创建账户、再转账、再调合约」），
        // 所以金额要遍历所有 Transfer action 累加，而不是取第一个。
        let mut amount: u128 = 0;
        // 用独立的 bool 记录「到底有没有 Transfer」：
        // 因为金额为 0 的转账也是合法的（amount 保持 0），
        // 仅凭 `amount > 0` 无法区分「没转账」与「转了 0」。
        let mut has_transfer = false;
        for action in &outcome.transaction.actions {
            // `if let` + **解构模式**：只在是 `ActionView::Transfer` 时进入分支，
            // 并把内部的 `deposit` 字段绑定到同名变量。
            if let ActionView::Transfer { deposit } = action {
                amount = amount.saturating_add(deposit.as_yoctonear());
                has_transfer = true;
            }
        }

        let mut view = TxView::new(ChainKind::Near, &self.network, tx_hash_str, status)
            // 注意 `hash` 字段填的是 `tx_hash_str`（**不带** `@sender` 后缀的原始哈希），
            // 保持与「交易哈希」这个概念一致；发送者单独放在 `from`。
            .with_from(outcome.transaction.signer_id.to_string())
            .with_to(outcome.transaction.receiver_id.to_string())
            .with_fee(fee);
        // 只有确实存在 Transfer action 时才填金额：
        // 否则 `amount_raw` / `amount_ui` 会是 `null`，表示「这笔交易不是转账」。
        // （若直接调用 `with_amount(0)`，调用方会误以为「转了 0 NEAR」。）
        if has_transfer {
            view = view.with_amount(amount);
        }

        Ok(view.with_extra(json!({
            // 燃烧的 gas（交易本身那一部分），单位 gas unit。
            "gas_burnt": outcome.transaction_outcome.outcome.gas_burnt.as_gas(),
            // receipt 数量：跨合约调用、转账到账、gas 退款都会各产生一个。
            "receipts": outcome.receipts_outcome.len(),
            // 交易包含的 action 数量（NEAR 一笔交易可含多个 action）。
            "actions": outcome.transaction.actions.len(),
        })))
    }

    async fn transfer(&self, req: TransferRequest) -> Result<TransferView, SdkError> {
        // 参数解析全部是**纯本地**计算，先做，让错误尽早、便宜地暴露。
        let secret_key = crate::transactions::parse_secret_key(&req.private_key)
            .map_err(|e| SdkError::invalid_argument(format!("非法私钥: {e}")))?;
        // 收款方是**具名账户**（不是地址也不是公钥），用 `AccountId` 解析。
        // `parse::<AccountId>()` 的 `::<>` 是 **turbofish**，显式指定泛型参数。
        let receiver = req
            .to
            .trim()
            .parse::<AccountId>()
            .map_err(|_| SdkError::invalid_argument(format!("非法 NEAR 账户名: {}", req.to)))?;

        // 付款账户：显式指定（命名账户），或从私钥派生隐式账户。
        //
        // NEAR 与 ETH/SOL 的关键差异：私钥**推不出**具名账户名
        // （`alice.near` 是注册出来的，与密钥无关），所以必须显式给出。
        // 只有在没给时，才退化成「隐式账户」——即公钥字节的十六进制。
        let from = match &req.from {
            // `&req.from` 是 `&Option<String>`，匹配 `Some(from)` 时
            // 因为**默认绑定模式**（match ergonomics），`from` 自动被借成 `&String`。
            Some(from) => parse_account(from)?,
            None => {
                // 派生隐式账户：公钥原始字节的十六进制。
                let public_key = secret_key.public_key();
                // `key_data()` 返回 `&[u8]`（ed25519 是 32 字节、secp256k1 是 64 字节），
                // `encode_hex` 得到不带 0x 前缀的十六进制串——
                // 这正是 NEAR 隐式账户的**精确**格式（不做任何哈希、不加前缀）。
                hexutil::encode_hex(public_key.key_data())
                    .parse::<AccountId>()
                    // 理论上不会失败（十六进制串长度 64/128、字符集合法），
                    // 但若将来支持了新的密钥类型导致长度超限，这里会兜住。
                    .map_err(|_| SdkError::invalid_argument("无法从私钥派生隐式账户".to_string()))?
            }
        };

        // 金额是**人类可读的 NEAR 字符串**（如 "1.5"），按 24 位小数换算成 yoctoNEAR。
        let amount = crate::units::parse_near(&req.amount)
            .map_err(|e| SdkError::invalid_argument(format!("非法金额: {e}")))?;

        // 构造 + 本地签名（内部会取 nonce 与近期区块哈希）。
        // 注意：这里**没有**检查 `dry_run`——构造与签名在两种模式下都要做。
        let built = crate::transactions::build_signed(
            &self.client,
            &from,
            &secret_key,
            &receiver,
            // 一个 Transfer action。即使 `amount` 为 0 也会构造（语义上是「转 0」）。
            vec![Action::Transfer(TransferAction {
                deposit: Balance::from_yoctonear(amount),
            })],
            // 不覆盖 nonce：走「查链上 nonce + 1」的正常路径。
            None,
        )
        .await
        .map_err(|e| self.fail("构造签名转账失败", e))?;

        // dry-run 时不广播，`success` 为 `None`（未广播即无从谈成功与否）；
        // 真发时广播，并把「是否最终成功」记录下来。
        //
        // 注意 `Option<bool>` 而不是 `bool`：三态（未广播 / 失败 / 成功）比二态更准确，
        // 序列化成 `null` / `false` / `true`。
        let success = if req.dry_run {
            None
        } else {
            let outcome = self
                .client
                .call(methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
                    // 按值移入已签名的交易（它会离开本进程发往节点）。
                    signed_transaction: built.signed,
                })
                .await
                .map_err(|e| self.fail("广播交易失败", e))?;
            // `matches!(值, 模式)` 是标准库宏，等价于
            // `match 值 { 模式 => true, _ => false }`，只是更短。
            // 末尾的 `!` 表示这是宏而非函数。
            Some(matches!(
                outcome.status,
                FinalExecutionStatus::SuccessValue(_)
            ))
        };

        Ok(TransferView::new(
            ChainKind::Near,
            &self.network,
            // `built.signer_id` 是 `AccountId`，`.to_string()` 转成 `String`。
            Some(built.signer_id.to_string()),
            // `req.to` 在此被 move（前面只用了它的借用）。
            req.to,
            amount,
            Some(built.tx_hash.to_string()),
            // `broadcast` 字段 = 是否真的广播了。
            !req.dry_run,
        )
        .with_extra(json!({
            // 本次使用的 nonce，便于调用方记录与排查「nonce 冲突」。
            "nonce": built.nonce,
            // 交易锚定的近期区块哈希。
            "block_hash": built.block_hash.to_string(),
            // `null` / `false` / `true` 三态，见上面的说明。
            "success": success,
        })))
    }

    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        // 解析成 NEAR 的 `PublicKey` 枚举（支持带类型前缀、裸 base58、十六进制三种写法）。
        let key = parse_public_key(pubkey)?;
        // `key_data()` 取出公钥的**原始字节**（ed25519 是 32 字节、secp256k1 是 64 字节）。
        let data = key.key_data();
        // NEAR 隐式账户 = 公钥原始字节的十六进制，不做任何哈希。
        //
        // 这是 NEAR 账户模型里最反直觉的一点：它与 ETH（keccak 取后 20 字节）、
        // BTC（哈希 + 校验和）都不同，**账户名就是公钥本身的十六进制**。
        // 这类账户叫「隐式账户」（implicit account），无需预先注册即可存在，
        // 但必须由某人发起一笔转账/创建交易把它**激活**后才能用。
        let account = hexutil::encode_hex(data);

        Ok(AddressView::new(
            ChainKind::Near,
            &self.network,
            // `pubkey` 字段填**规范化**形式，即 `ed25519:<base58>` —— 这是 NEAR 的规范表示。
            // 无论用户输入的是裸 base58 还是十六进制，输出都是同一个规范串，
            // 便于调用方做幂等比较。
            key.to_string(),
            // `account.clone()`：这个串下面还要在 extra 里再放一次，故克隆一份。
            account.clone(),
            "implicit",
            // 公钥字节长度（32 或 64），回显出来便于调用方核对输入是否被正确解析。
            data.len(),
        )
        .with_extra(json!({
            "account_id": account,
            // 密钥类型（`ed25519` / `secp256k1`）。
            "key_type": key.key_type().to_string(),
            // 写明派生方式，让「账户名就是公钥的十六进制」这件事在输出里自解释。
            "derivation": "hex(public_key_bytes)",
        })))
    }
}

/// 解析 NEAR 公钥。
///
/// 接受三种写法：
/// - 规范形式 `ed25519:<base58>` / `secp256k1:<base58>`；
/// - 裸 base58（按字节长度判定：32 字节为 ed25519，64 字节为 secp256k1）；
/// - 十六进制（建议带 `0x` 前缀，长度同上）。
fn parse_public_key(raw: &str) -> Result<PublicKey, SdkError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(SdkError::invalid_argument("NEAR 公钥不能为空"));
    }

    // 含 `:` 的一定是规范形式 `ed25519:<base58>` / `secp256k1:<base58>`——
    // 因为 base58 与十六进制字符表里都没有冒号，这个判断**无歧义**，
    // 比「先试 base58、失败再试十六进制」更可靠。
    if trimmed.contains(':') {
        // 交给官方解析器：它会校验类型前缀是否合法（只有 ed25519 / secp256k1 两种）。
        return trimmed.parse::<PublicKey>().map_err(|e| {
            SdkError::invalid_argument(format!(
                "非法 NEAR 公钥: {raw}（期望 ed25519:<base58> 或 secp256k1:<base58>；{e}）"
            ))
        });
    }

    // 没有冒号时，判断是否为十六进制：
    // 1) 显式带 `0x` / `0X` 前缀 → 一定按十六进制处理；
    // 2) 长度恰好 64（32 字节 ed25519）或 128（64 字节 secp256k1）
    //    **且**全是十六进制字符 → 按十六进制处理。
    //
    // 为什么用长度判定：NEAR 的两种公钥长度差异极大（32 vs 64 字节），
    // 二者的 base58 串长度也差很多（43-44 vs 87-88），不会与 64/128 位的十六进制串混淆。
    let is_hex = trimmed.starts_with("0x")
        || trimmed.starts_with("0X")
        || ((trimmed.len() == 64 || trimmed.len() == 128)
            && trimmed.chars().all(|c| c.is_ascii_hexdigit()));

    // `if / else` 是**表达式**，两个分支类型相同即可整体赋值。
    let bytes: Vec<u8> = if is_hex {
        hexutil::decode_hex(trimmed)?
    } else {
        // 走 `bs58` crate（NEAR 一侧直接引了外部依赖，与 SOL 那侧手写实现不同）。
        // `.into_vec()` 把 decode 结果转成 `Vec<u8>`。
        bs58::decode(trimmed)
            .into_vec()
            .map_err(|e| SdkError::invalid_argument(format!("非法 base58 公钥: {e}")))?
    };

    // 按字节长度决定密钥类型。
    from_bytes(&bytes)
}

/// 由原始字节构造 `PublicKey`，**按长度判定密钥类型**。
///
/// 这是本文件的关键约定：
/// - 32 字节 → ed25519；
/// - 64 字节 → secp256k1（**未压缩**公钥，即 X||Y 两个坐标各 32 字节）。
///
/// 注意 secp256k1 在其它链上常见的「压缩公钥」是 33 字节，
/// 与 NEAR 的 64 字节未压缩形式**不兼容**，跨链复用公钥时要留意。
fn from_bytes(bytes: &[u8]) -> Result<PublicKey, SdkError> {
    // 语法说明：`&[u8]` 是**字节切片**：`Vec<u8>`、`[u8; N]` 都能自动强制转换成它，
    // 所以这里能直接接受上面的 `Vec<u8>` 而无需转换。
    match bytes.len() {
        // ed25519：`bytes.try_into()` 把 `&[u8]` 转成 `[u8; 32]`。
        // 这里是**可失败**转换（`TryInto`），长度不对返回 Err——
        // 但外层已经确认了长度是 32，所以 `map_err` 只是形式上的兜底。
        32 => Ok(PublicKey::ED25519(ED25519PublicKey(
            bytes
                .try_into()
                .map_err(|_| SdkError::invalid_argument("ed25519 公钥长度异常"))?,
        ))),
        // secp256k1：官方提供了 `TryFrom<&[u8]>`，内部还会校验点是否在曲线上，
        // 因此这里的错误可能来自「长度不符」之外的合法性检查。
        64 => Secp256K1PublicKey::try_from(bytes)
            // `.map(PublicKey::SECP256K1)`：把 `Secp256K1PublicKey` 包成 `PublicKey` 枚举。
            // 传的是**枚举变体构造函数**（函数指针），比写 `|k| PublicKey::SECP256K1(k)` 更简洁。
            .map(PublicKey::SECP256K1)
            .map_err(|e| SdkError::invalid_argument(format!("构造 secp256k1 公钥失败: {e}"))),
        // `other` 绑定的是 `usize`（`.len()` 的结果）。
        other => Err(SdkError::invalid_argument(format!(
            "NEAR 公钥需为 32 字节（ed25519）或 64 字节（secp256k1），实际 {other} 字节"
        ))),
    }
}

/// 解析 NEAR **具名账户**。
///
/// `AccountId::from_str` 会校验账户名的全部规则：
/// 只允许小写字母、数字、`-` 与 `_`，以 `.` 分层，总长 2-64 字符。
/// 所以 `Alice.near`（含大写）、`a.near`（太短）、`a..b`（空段）都会被拒绝。
fn parse_account(raw: &str) -> Result<AccountId, SdkError> {
    // `.trim()` 去首尾空白；`map_err(|_| ..)` 丢弃底层细节，
    // 换成带原始输入的中文提示（底层只说 "invalid account id"，不够用）。
    AccountId::from_str(raw.trim())
        .map_err(|_| SdkError::invalid_argument(format!("非法 NEAR 账户名: {raw}")))
}

/// 单元测试模块：`#[cfg(test)]` 保证只在 `cargo test` 时编译。
///
/// 这里只测**纯本地**逻辑（公钥解析），不碰网络——
/// 联网测试会因公共节点限流而变得不稳定（flaky），且拖慢 CI。
#[cfg(test)]
mod tests {
    use super::*;

    // sha256("allchain-near-test-vector") 的 32 字节，base58 编码后作为 ed25519 公钥。
    //
    // 语法说明：这几个是 `&'static str` 常量。用**固定测试向量**而不是随机生成，
    // 是为了让测试可复现、且能与链上/其它 SDK 的结果交叉比对。
    const ED25519_B58: &str = "Ea7rnrasYTNEJ74iGP3AGwvRLMiw1MpBBqLVRnyQDkih";
    // 同一把公钥的十六进制形式（64 个字符 = 32 字节）。
    const ED25519_HEX: &str = "c9a3da0428ef24d1dbc5f7fcc83d2c9de0edf20666b880cae7b96c4d5c1eef0e";
    // secp256k1 公钥（64 字节未压缩），base58 后是 87-88 个字符。
    const SECP_B58: &str =
        "6qGGJ2rJRXhivSFLNT5FUwPvjZaEBkkqbmuj8TMizuAenNf4n163CxG8y1Nkdt5wX1beMJys6jMVfzVAnDnBQpr";

    /// 规范形式 `ed25519:<base58>` 应能被正确解析，且往返输出保持一致。
    #[test]
    fn parses_canonical_form() {
        // `format!` 里直接用内联命名参数拼出 "ed25519:xxx"。
        let key = parse_public_key(&format!("ed25519:{ED25519_B58}")).unwrap();
        assert_eq!(key.key_type().to_string(), "ed25519");
        assert_eq!(key.key_data().len(), 32);
        // 往返验证：解析 → 重新格式化，应还原成同一个规范串。
        assert_eq!(key.to_string(), format!("ed25519:{ED25519_B58}"));
    }

    /// 裸 base58、裸十六进制、带 `0x` 前缀的十六进制 —— 三种写法应得到**同一把**公钥。
    #[test]
    fn bare_base58_and_hex_agree() {
        let key = parse_public_key(ED25519_B58).unwrap();
        assert_eq!(hexutil::encode_hex(key.key_data()), ED25519_HEX);
        let from_hex = parse_public_key(ED25519_HEX).unwrap();
        let from_prefixed = parse_public_key(&format!("0x{ED25519_HEX}")).unwrap();
        // `PublicKey` 实现了 `PartialEq`，可直接比较两个枚举值。
        assert_eq!(from_hex, key);
        assert_eq!(from_prefixed, key);
    }

    /// secp256k1 公钥是 **64 字节**（未压缩），不是 BTC 上常见的 33 字节压缩形式。
    #[test]
    fn secp256k1_key_is_64_bytes() {
        let key = parse_public_key(SECP_B58).unwrap();
        assert_eq!(key.key_type().to_string(), "secp256k1");
        assert_eq!(key.key_data().len(), 64);
        // 64 字节 → 128 个十六进制字符。
        assert_eq!(hexutil::encode_hex(key.key_data()).len(), 128);
    }

    /// 隐式账户 = 公钥字节的十六进制，长度必为 64 个字符（32 字节 ed25519）。
    #[test]
    fn implicit_account_is_hex_of_key_bytes() {
        let key = parse_public_key(ED25519_B58).unwrap();
        assert_eq!(hexutil::encode_hex(key.key_data()).len(), 64);
    }

    /// 未知密钥类型、空串、错误长度都必须报错。
    #[test]
    fn rejects_unknown_type_and_bad_length() {
        // 类型前缀不合法（NEAR 只认 ed25519 / secp256k1）。
        assert!(parse_public_key("ecdsa:abc").is_err());
        // 空串。
        assert!(parse_public_key("").is_err());
        // `"ab".repeat(16)` = 32 个 'a'/'b'：全是十六进制字符，
        // 但长度 32 既不是 64 也不是 128，因此**不会**被判为 hex，
        // 走 base58 分支解码后得到 23 字节左右 → 长度不匹配 → 报错。
        assert!(parse_public_key(&"ab".repeat(16)).is_err());
    }
}
