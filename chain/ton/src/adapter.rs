//! TON 链对统一 `ChainClient` 契约的实现（toncenter REST v2）。
//!
//! 与 EVM / UTXO 类链的**结构性差异**，是本适配器几乎所有特殊处理的来源：
//! 1. TON 是**多链（shardchain）架构**：一个 workchain 下还有大量 shard，
//!    只有 **masterchain**（workchain = -1）有全局连续的区块序号。
//!    因此本适配器查区块时**固定**取 masterchain，不支持按 shard 查；
//! 2. 定位一笔交易需要**三元组** `(tx_hash, lt, account)`，仅凭哈希查不到
//!    （toncenter 没有「按哈希直达」的接口）。本 SDK 约定用
//!    `<tx_hash>:<lt>@<address>` 这样一个字符串承载，见 `parse_tx_locator`；
//! 3. TON 的**失败交易不会上链**，节点能返回就说明执行成功，
//!    所以 `TxView::status` 恒为 `Success`（见 `tx` 里的说明）；
//! 4. toncenter 免费档限速约 1 req/s，客户端内置**串行节流**（见 `throttle`）。
//!
//! 本适配器**只提供只读查询**：既不实现 `transfer`，也不实现 `address_from_pubkey`。
//! 两者的原因相同——TON 地址依赖钱包合约的 StateInit，无法仅由公钥确定。

// `async_trait` 属性宏：稳定版 Rust 不允许 trait 里直接写 `async fn`，
// 它把 `async fn` 改写成返回装箱 Future 的普通 `fn`，
// 于是 `Box<dyn ChainClient>` 依然可用，上层才能在运行期按链名分发。
use async_trait::async_trait;
use serde_json::{Value, json};
// **tokio** 的异步 Mutex（不是 `std::sync::Mutex`）：它的 `.lock()` 返回 Future，
// 可以跨 `.await` 持有锁而不会阻塞线程。用错成 std 版本会在编译期就被
// 「不能在持锁时 await」的检查挡住（或引发死锁）。
use tokio::sync::Mutex;
// `Instant` 是 tokio 的**单调时钟**包装（用于计时），`sleep` 是异步休眠。
// 用 tokio 版本而非 `std::thread::sleep`：后者会阻塞整个线程，
// 在异步运行时里是严重错误。
use tokio::time::{Instant, sleep};

// 注意导入列表里**没有** `AddressView`：本适配器不实现 `address_from_pubkey`，
// 多导入反而会触发「未使用导入」警告。
use allchain_core::{
    BalanceView, BlockView, ChainClient, ChainKind, ErrorCode, SdkError, StatusView, TxStatus,
    TxView,
};
// `url_encode` 在这里很关键：TON 的用户友好地址含 `+` 与 `/`，
// 放进 query 前必须转义，否则 `+` 会被服务端解成空格。
use chain_rpcutil::{Http, field_u64, loose_u128, url_encode};

use crate::network;

/// 主链（masterchain）固定 workchain / shard。
///
/// TON 的 workchain 编号：`-1` 是 masterchain，`0` 是基础工作链。
/// masterchain 的区块序号全局唯一且连续，是唯一适合映射到
/// 统一模型 `BlockView::height` 的东西。
const MASTER_WORKCHAIN: i32 = -1;
/// masterchain 的 shard 标识，即 `i64::MIN`。
///
/// 这个值代表「整个 workchain」（shard 前缀为空、覆盖全范围）。
/// 写成字符串常量是因为它要直接拼进 URL，而 `i64::MIN` 的字面量
/// 在格式化里容易写错符号。
const MASTER_SHARD: &str = "-9223372036854775808";

/// toncenter 免费档约 1 req/s，客户端内串行节流，避免 429。
///
/// 取 1100 毫秒而不是 1000，是留出余量：客户端与服务端对「一秒」的
/// 计时窗口不会完全对齐，正好卡在 1000ms 仍可能偶发 429。
const MIN_CALL_GAP_MS: u64 = 1100;

/// TON 适配器。构造后不可变字段，但 `last_call` 需要内部可变性。
pub struct TonClient {
    /// 网络名（`mainnet` / `testnet` / `localnet` / `custom`）。
    network: String,
    /// 实际端点，回显到各 View 的 `rpc_url` 字段。
    rpc_url: String,
    /// 可选 API key（toncenter 免费档限速，key 通过 query 传递）。
    api_key: Option<String>,
    /// 共用 HTTP 客户端（内含连接池）。
    http: Http,
    /// 上一次发起请求的时刻，用于串行节流。
    ///
    /// 语法说明：`Mutex<Option<Instant>>` 提供了**内部可变性**——
    /// `throttle` 只拿到 `&self`（不可变借用），但通过 Mutex 仍能修改里面的值。
    /// 这正是 Rust 里「逻辑上只读、内部需要记账」的标准解法。
    /// 初值为 `None` 表示「还没发过请求」。
    last_call: Mutex<Option<Instant>>,
}

impl TonClient {
    /// 构造客户端。`rpc_url` 优先于 `network`：显式给了 URL 就以它为准，
    /// 网络名记为 `custom`。
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        // `map(str::trim)` 只在 Some 时生效；`filter` 把空串也折成 None；
        // 最后 `.map(str::to_string)` 把 `Option<&str>` 变成 `Option<String>`。
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let (network_name, url) = match custom {
            Some(url) => ("custom".to_string(), url),
            None => {
                // 走内置网络表，`?` 在网络名非法时返回 `INVALID_ARGUMENT`。
                let net = network::parse(network)?;
                (net.as_str().to_string(), net.api_url().to_string())
            }
        };
        // 允许通过环境变量传入 toncenter API key，缺省走免费档。
        //
        // 语法说明：`std::env::var` 返回 `Result<String, VarError>`，
        // `.ok()` 把它折成 `Option`（变量不存在或不是合法 Unicode 都算「没配」），
        // 再 `.filter(|s| !s.is_empty())` 把「配了空串」也当成没配——
        // 空 key 传上去反而会让服务端报错。
        let api_key = std::env::var("TONCENTER_API_KEY")
            .ok()
            .filter(|s| !s.is_empty());
        let http = Http::new(&url)?;
        Ok(Self {
            network: network_name,
            rpc_url: url,
            api_key,
            http,
            // `Mutex::new(..)` 是**同步**构造（tokio 的 Mutex 只有 `.lock()` 是异步的）。
            last_call: Mutex::new(None),
        })
    }

    /// 拼接带可选 api_key 的查询路径。
    ///
    /// 语法说明：参数是 `String`（**按值接收**），因为调用方都是刚 `format!` 出来的
    /// 临时值，直接交出所有权可以避免一次克隆。
    ///
    /// 注意用 `&` 拼接而非 `?`：这里假设 `path` 里**已经含有** `?`
    /// （所有调用点传进来的路径都带查询参数），因此用 `&` 追加第二个参数。
    fn with_key(&self, path: String) -> String {
        // `match &self.api_key` 借出 `Option<&String>`，
        // 这样不会把 `self.api_key` 的所有权转移走。
        match &self.api_key {
            Some(key) => format!("{path}&api_key={key}"),
            // 没配 key 就原样返回（toncenter 允许匿名访问，只是限额低）。
            None => path,
        }
    }

    /// 串行节流：保证相邻请求至少间隔 MIN_CALL_GAP_MS。
    ///
    /// 为什么是「串行」而不是「并发 + 令牌桶」：toncenter 免费档的限制是
    /// **全局**的（按 IP 计），并发数再多也只会更快触发 429。
    /// 串行节流让所有调用共享一个节奏，代价是吞吐低，但对只读查询场景足够。
    async fn throttle(&self) {
        // `.lock().await`：异步获取锁，等待期间让出线程。
        // `mut` 是因为下面要改写 `*last`。
        let mut last = self.last_call.lock().await;
        // `*last` 是**解引用**：从 `MutexGuard` 里取出 `Option<Instant>`。
        // 用 `if let Some(prev) = *last` 而不是 `*last.as_ref()`，
        // 是因为 `Instant` 是 `Copy` 的，可以直接复制出来。
        if let Some(prev) = *last {
            // `prev.elapsed()` 返回从那个时刻到现在经过的 `Duration`。
            // tokio 的 `Instant` 基于**单调时钟**，不受系统时间调整影响。
            let elapsed = prev.elapsed();
            if elapsed < std::time::Duration::from_millis(MIN_CALL_GAP_MS) {
                // 补睡差值：距离最小间隔还差多久就睡多久。
                // `Duration` 的减法在这里安全——上一行已确保被减数更大。
                sleep(std::time::Duration::from_millis(MIN_CALL_GAP_MS) - elapsed).await;
            }
        }
        // 更新时刻。注意锁**一直持有到函数结束**才释放：
        // 这保证「检查间隔 → 睡眠 → 记录时刻」是原子的，
        // 两个并发任务不会同时通过检查。
        *last = Some(Instant::now());
    }

    /// toncenter 统一信封：`{ok, result}`，ok=false 时映射错误。
    ///
    /// 这是本适配器最重要的一层封装，它替上层收敛了三件事：
    /// 1. 节流（先 `throttle` 再发请求）；
    /// 2. API key 注入（`with_key`）；
    /// 3. 错误归一（toncenter 的 `ok:false` 信封 → 统一 `SdkError`）。
    ///
    /// 语法说明：参数 `path` 是按值接收的 `String`（调用方直接交出所有权）。
    async fn call(&self, path: String) -> Result<Value, SdkError> {
        self.throttle().await;
        // `&self.with_key(path)`：临时 `String` 的借用，正好匹配 `&str` 参数。
        let value = self.http.get_value(&self.with_key(path)).await?;
        // toncenter 的业务错误**不通过 HTTP 状态码**表达
        // （HTTP 仍是 200），而是响应体里的 `ok: false` + `error` + `code`。
        // 这里用 `== Some(false)` 而非 `matches!`：
        // `as_bool()` 返回 `Option<bool>`，与 `Some(false)` 直接比较最直白。
        // 注意不能写成 `!= Some(true)`——`ok` 字段缺失时两者行为不同。
        if value.get("ok").and_then(Value::as_bool) == Some(false) {
            let message = value
                .get("error")
                .and_then(Value::as_str)
                // `error` 字段可能缺失或不是字符串，兜底一句通用说明。
                .unwrap_or("toncenter 返回 ok=false")
                // `.to_string()` 把借用的 `&str` 变成自有 `String`：
                // 因为 `value` 是局部变量，借出来的引用不能跟着 `Err` 返回出去。
                .to_string();
            let code = value.get("code").and_then(Value::as_i64);
            return Err(match code {
                // 404 / 422：账号或区块不存在，确定性结果，**不可重试**。
                Some(404) | Some(422) => SdkError::not_found(message),
                // 429：限流。虽然节流已尽力避免，付费 key 超额、或与其它进程
                // 共享同一个 IP 时仍可能触发。标为 RpcError（可重试），
                // 但额外加一句中文说明，便于调用方排查。
                Some(429) => {
                    SdkError::new(ErrorCode::RpcError, format!("toncenter 限流: {message}"))
                }
                // 其余一律 RpcError。
                _ => SdkError::new(ErrorCode::RpcError, message),
            });
        }
        value
            .get("result")
            // `.cloned()`：把 `Option<&Value>` 变成 `Option<Value>`，
            // 因为要把值返回出去，借用引用活不过本函数。
            .cloned()
            .ok_or_else(|| SdkError::new(ErrorCode::RpcError, "响应缺少 result 字段"))
    }
}

// `#[async_trait]` 写在 `impl` 块**正上方**，作用于块内所有 `async fn`。
#[async_trait]
impl ChainClient for TonClient {
    /// 所属链。同步方法：值在构造时就已确定，无需 IO。
    fn kind(&self) -> ChainKind {
        ChainKind::Ton
    }

    /// 网络名。返回 `&str` 借用的是 `self.network`，
    /// 生命周期由编译器自动绑到 `&self`（生命周期省略规则）。
    fn network(&self) -> &str {
        &self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// 链与节点状态：取 masterchain 的最新区块。
    async fn status(&self) -> Result<StatusView, SdkError> {
        // `getMasterchainInfo` 无参数，直接传空路径。
        // `.to_string()` 是因为 `call` 按值接收 `String`。
        let info = self.call("/getMasterchainInfo".to_string()).await?;
        // 返回结构是 `{last: {workchain, shard, seqno, root_hash, file_hash}, ...}`。
        // `last` 是核心，缺了就报错。
        let last = info
            .get("last")
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "缺少 last 块信息"))?;
        let mut view = StatusView::new(ChainKind::Ton, &self.network, &self.rpc_url);
        // masterchain 的 seqno 就是「链高度」。
        if let Ok(seq) = field_u64(last, "seqno") {
            view = view.with_height(seq);
        }
        // TON 的区块标识是 `root_hash`（区块头的哈希）；
        // 另有 `file_hash` 是区块数据的哈希，两者不同，不要混用。
        if let Some(hash) = last.get("root_hash").and_then(Value::as_str) {
            view = view.with_hash(hash);
        }
        // TON 的 REST 不暴露节点版本号，`node_version` 保持 `None`。
        Ok(view.with_extra(json!({
            "workchain": last.get("workchain").cloned().unwrap_or(Value::Null),
            "shard": last.get("shard").cloned().unwrap_or(Value::Null),
            "file_hash": last.get("file_hash").cloned().unwrap_or(Value::Null),
            // 这两个是整条链的初始状态哈希，可用来区分「连的是主网还是测试网」。
            "state_root_hash": info.get("state_root_hash").cloned().unwrap_or(Value::Null),
            "init_file_hash": info.get("init_file_hash").cloned().unwrap_or(Value::Null),
        })))
    }

    /// 查询地址余额（nanoton，精度 9）。
    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        validate_address(address)?;
        // **必须** `url_encode`：TON 的用户友好地址含 `+` 与 `/`，
        // 其中 `+` 在 query string 里会被解成空格，不转义就查不到。
        let path = format!("/getAddressBalance?address={}", url_encode(address.trim()));
        let result = self.call(path).await?;
        // result 是 nanoton 十进制字符串。
        let raw = match result {
            // 正常路径：形如 `"1234567890"` 的十进制字符串。
            // 用 u128 而非 u64：nanoton 精度 9，余额轻易超过 u64 的一半量级。
            Value::String(s) => s.parse::<u128>().map_err(|_| {
                SdkError::new(ErrorCode::ParseError, format!("非法 nanoton 余额: {s}"))
            })?,
            // 兜底：某些版本/网关会返回 JSON number，交给宽松解析器处理
            // （它能同时吃下数字、十进制串与 `0x` 十六进制串）。
            other => loose_u128(&other)?,
        };
        // 注意：未激活的账户 toncenter 也返回 `"0"` 而不是报错，
        // 所以「查不到」与「余额为零」在这里是同一回事。
        Ok(BalanceView::new(
            ChainKind::Ton,
            &self.network,
            address,
            raw,
        ))
    }


    /// 查询一笔交易。
    ///
    /// **入参格式特殊**：必须是 `<tx_hash>:<lt>@<address>`，而不是单纯的哈希。
    /// 原因见文件末尾 `parse_tx_locator` 的说明。
    /// 链头高度：最新主链区块序号（裸 `u64`）。
    async fn last_block_height(&self) -> Result<u64, SdkError> {
        let info = self.call("/getMasterchainInfo".to_string()).await?;
        field_u64(
            info.get("last")
                .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "缺少 last 块信息"))?,
            "seqno",
        )
    }

    /// 按主链序号查询区块。
    async fn block_by_height(&self, height: u64) -> Result<BlockView, SdkError> {
        let seqno = height;
        let path = format!(
            "/getBlockHeader?workchain={MASTER_WORKCHAIN}&shard={MASTER_SHARD}&seqno={seqno}"
        );
        let header = self.call(path).await?;
        let id = header
            .get("id")
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "block header 缺少 id"))?;
        let hash = id
            .get("root_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "block id 缺少 root_hash"))?
            .to_string();
        let mut view = BlockView::new(ChainKind::Ton, &self.network, hash).with_height(seqno);
        if let Some(utime) = header.get("gen_utime").and_then(Value::as_i64) {
            view = view.with_timestamp(utime);
        }
        let mut parent_seqno = Value::Null;
        if let Some(prev) = header
            .get("prev_blocks")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
        {
            parent_seqno = prev.get("seqno").cloned().unwrap_or(Value::Null);
            if let Some(rh) = prev.get("root_hash").and_then(Value::as_str) {
                view = view.with_parent(rh);
            }
        }
        let tx_path = format!(
            "/getBlockTransactions?workchain={MASTER_WORKCHAIN}&shard={MASTER_SHARD}&seqno={seqno}&count=1000"
        );
        if let Ok(txs) = self.call(tx_path).await
            && let Some(list) = txs.get("transactions").and_then(Value::as_array)
        {
            view = view.with_tx_count(list.len() as u64);
        }
        Ok(view.with_extra(json!({
            "workchain": id.get("workchain").cloned().unwrap_or(Value::Null),
            "shard": id.get("shard").cloned().unwrap_or(Value::Null),
            "file_hash": id.get("file_hash").cloned().unwrap_or(Value::Null),
            "is_key_block": header.get("is_key_block").cloned().unwrap_or(Value::Null),
            "global_id": header.get("global_id").cloned().unwrap_or(Value::Null),
            "parent_seqno": parent_seqno,
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        // TON 定位一笔交易需要 (hash, lt, account)，统一约定引用格式：
        // `<tx_hash_base64>:<lt>@<address>`。
        let (tx_hash, lt, address) = parse_tx_locator(hash)?;
        // 用 `lt`（逻辑时间）与 `hash` 精确定位，`limit=1` 只要一条。
        // 两个参数都要转义：tx_hash 是 base64，可能含 `+` `/` `=`。
        let path = format!(
            "/getTransactions?address={}&limit=1&lt={lt}&hash={}",
            url_encode(&address),
            url_encode(&tx_hash)
        );
        let result = self.call(path).await?;
        let item = result
            .as_array()
            // 返回的是**数组**（即使 limit=1），取第一个元素。
            .and_then(|a| a.first())
            // 空数组 = 该账户下没有匹配的交易。
            .ok_or_else(|| SdkError::not_found(format!("未找到 TON 交易: {hash}")))?;

        // 交易可被节点返回即代表已执行（失败交易会被链丢弃）。
        //
        // 这是 TON 与 EVM 的重要差异：EVM 会把失败交易也记进回执（`status = 0`），
        // 而 TON 的失败交易在**执行阶段**就被丢弃，根本不会出现在链上。
        // 所以 `TxStatus` 恒为 Success，不存在 Failed 或 Pending 两种取值。
        let mut view = TxView::new(ChainKind::Ton, &self.network, &tx_hash, TxStatus::Success);
        // `utime` 是交易时间（Unix 秒）。注意它不等于区块的 `gen_utime`，
        // 两者可能略有差异（同块内多笔交易的 utime 可以相同也可以不同）。
        if let Some(utime) = item.get("utime").and_then(Value::as_i64) {
            view = view.with_timestamp(utime);
        }
        // TON 的交易金额在 **in_msg**（入站消息）里，交易本身没有 amount 字段。
        if let Some(in_msg) = item.get("in_msg") {
            // `source` 为空表示这是外部消息（来自链下的钱包），
            // 因此空字符串不能当成发送方填进去，必须过滤掉。
            if let Some(source) = in_msg.get("source").and_then(Value::as_str)
                && !source.is_empty()
            {
                view = view.with_from(source);
            }
            if let Some(dest) = in_msg.get("destination").and_then(Value::as_str) {
                view = view.with_to(dest);
            }
            if let Some(value) = in_msg.get("value").and_then(Value::as_str)
                && let Ok(amount) = value.parse::<u128>()
            {
                view = view.with_amount(amount);
            }
        }
        // `fee` 是总手续费（nanoton）。注意它**已包含**下面 extra 里的
        // storage_fee 与 other_fee，不要重复相加。
        let fee = item
            .get("fee")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u128>().ok());
        if let Some(fee) = fee {
            view = view.with_fee(fee);
        }
        // 出站消息数：一笔 TON 交易可能触发多条出账（如合约批量转账），
        // 这个数字能提示调用方「别只看出账金额」。
        let out_count = item
            .get("out_msgs")
            .and_then(Value::as_array)
            .map(|m| m.len());
        Ok(view.with_extra(json!({
            // `lt` 优先取交易自身的值，取不到就用调用方传入的那个兜底。
            "lt": item.pointer("/transaction_id/lt").cloned().unwrap_or(json!(lt)),
            "account": address,
            "storage_fee": item.get("storage_fee").cloned().unwrap_or(Value::Null),
            "other_fee": item.get("other_fee").cloned().unwrap_or(Value::Null),
            "out_message_count": out_count,
        })))
    }

    // 不实现 address_from_pubkey：TON 地址是钱包合约 StateInit 的哈希，
    // 依赖具体钱包合约版本（V3/V4R2/W5…），无法仅由公钥唯一确定，使用 trait 默认 UNSUPPORTED。
    //
    // 同理也不实现 `transfer`：构造外部消息需要知道钱包合约版本与 seqno，
    // 这属于「钱包」而非「查询 SDK」的职责。
}

/// 解析交易定位符 `<hash>:<lt>@<address>`。
///
/// 为什么 TON 不能只用哈希：toncenter 的 `getTransactions` 是
/// **按账户列交易**的接口，必须先给出账户地址；而 `lt`（logical time）与 `hash`
/// 一起才能在该账户的交易列表里唯一定位一条记录
/// （同一账户内可以有多条 `lt` 相同但哈希不同的交易）。
/// 因此本 SDK 约定把三元组拼成一个字符串，让上层仍能用「一个哈希」调用统一接口。
///
/// 语法说明：返回 `Result<(String, String, String), SdkError>`——
/// 元组适合表达「固定个数、类型各异」的一组返回值，
/// 比为此专门定义一个结构体轻量得多。
fn parse_tx_locator(raw: &str) -> Result<(String, String, String), SdkError> {
    // 先用 `@` 切出地址（地址本身不含 `@`，所以用 `split_once` 取第一个即可）。
    // `split_once` 返回 `Option<(&str, &str)>`。
    let (left, address) = raw.trim().split_once('@').ok_or_else(|| {
        SdkError::invalid_argument(
            "TON 交易引用格式应为 <tx_hash>:<lt>@<address>（地址用于定位账户交易列表）",
        )
    })?;
    // 再从左边切出 hash 与 lt。
    let (tx_hash, lt) = left
        .split_once(':')
        .ok_or_else(|| SdkError::invalid_argument("TON 交易引用缺少 :<lt> 部分"))?;
    // 三段都非空才合法（缺任何一段都会让查询语义不明确）。
    if tx_hash.is_empty() || lt.is_empty() || address.is_empty() {
        return Err(SdkError::invalid_argument("TON 交易引用存在空字段"));
    }
    // 地址会被拼进 URL，这里复用同一套校验。
    validate_address(address)?;
    // 三段 `.to_string()`：把借来的切片变成自有 String 交出去，
    // 因为它们是从 `raw`（参数借用）里切出来的，活不过本函数。
    Ok((tx_hash.to_string(), lt.to_string(), address.to_string()))
}

/// 宽松校验 TON 地址：raw 形式 `wc:64hex` 或用户友好形式（base64url，约 48 字符）。
///
/// 两种形式的区别：
/// - **raw**：`workchain:32字节账户哈希的十六进制`，如 `-1:3333...`，
///   只出现在内部系统与节点日志里；
/// - **用户友好**（friendly）：base64url 编码，带 CRC16 校验与 bounceable 标志，
///   就是我们常见到的 `EQ...` / `UQ...` 形态。
///
/// **已知限制（务必留意）**：本函数对用户友好地址只做「长度 + 字符集」检查，
/// **不验证 CRC16 校验和**，也不区分 bounceable / non-bounceable。
/// 也就是说，一个手滑打错一位的 `EQ...` 地址能通过本地校验，
/// 但会在节点侧表现为「账户不存在」。补齐校验需要实现 TON 的 CRC16-CCITT，
/// 对只读查询 SDK 收益有限，故暂不做。
fn validate_address(raw: &str) -> Result<(), SdkError> {
    let t = raw.trim();
    // 含 `:` 就按 raw 形式解析。
    if let Some((wc, hex_part)) = t.split_once(':') {
        let workchain: i32 = wc
            .parse()
            .map_err(|_| SdkError::invalid_argument(format!("非法 workchain: {wc}")))?;
        // TON 的 workchain 编号是 **i32**，但实际使用范围是 -128..=127
        // （-1 是 masterchain，0 是基础工作链，其余为预留）。
        //
        // 语法说明：`(-128..=127).contains(&workchain)` 里取的是**引用**——
        // `RangeInclusive::contains` 的签名接受 `&T`，漏写 `&` 会编译失败。
        if !(-128..=127).contains(&workchain) {
            return Err(SdkError::invalid_argument(format!(
                "workchain 越界: {workchain}"
            )));
        }
        // 账户哈希恒为 32 字节 = 64 位十六进制，不多不少。
        if hex_part.len() != 64 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SdkError::invalid_argument(format!(
                "raw 地址账户哈希需为 64 位十六进制: {t}"
            )));
        }
        return Ok(());
    }
    // 用户友好地址：base64/base64url，44~48 字符。
    //
    // 长度区间的由来：48 字符 = 36 字节的 base64（无填充）——
    // 1 字节标志 + 1 字节 workchain + 32 字节账户哈希 + 2 字节 CRC16。
    // 44 字符对应带填充或短形态的变体。
    let ok_len = (44..=48).contains(&t.len());
    // 字符集覆盖标准 base64（含 `+` `/`）与 URL 安全变体（`-` `_`），再加填充符 `=`。
    //
    // 语法说明：`matches!(b, b'-' | b'_' | ..)` 里的 `b'-'` 是 **u8 字节字面量**
    // （前缀 `b`），与外层迭代变量 `b` 同名但不冲突——这是 Rust 里常见的写法。
    let ok_charset = t
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'+' | b'/' | b'='));
    if !ok_len || !ok_charset {
        return Err(SdkError::invalid_argument(format!(
            "非法 TON 地址: {t}（应为 wc:hex 或 EQ/UQ 开头的用户友好地址）"
        )));
    }
    Ok(())
}

/// 单元测试模块：只测纯函数，网络行为靠集成测试或手工验证。
#[cfg(test)]
mod tests {
    // `use super::*` 把父模块所有条目（含私有函数）导入，于是可直接写 `parse_tx_locator`。
    use super::*;

    /// 交易定位符的正反用例：合法三元组要能被正确拆出三段，
    /// 缺 `@` 或缺 `:` 都要被拒。
    #[test]
    fn parses_tx_locator() {
        let (h, lt, addr) = parse_tx_locator(
            "01KYvC3KxWaVwycwdrlAGB8fSiyY183v9DNRATm5Rww=:63489315000007@EQAvDfWFG0oYX19jwNDNBBL1rKNT9XfaGP9HyTb5nb2Eml6y",
        )
        .unwrap();
        // 注意 tx_hash 是 **base64**（含 `=` 填充），不是十六进制。
        assert_eq!(h, "01KYvC3KxWaVwycwdrlAGB8fSiyY183v9DNRATm5Rww=");
        assert_eq!(lt, "63489315000007");
        assert!(addr.starts_with("EQ"));
        // 缺 `@`：整体不合法。
        assert!(parse_tx_locator("onlyhash").is_err());
        // 有 `@` 但缺 `:`：地址部分虽然存在，仍然不合法。
        assert!(parse_tx_locator("h:1@no-at").is_err());
    }

    /// 地址校验：raw 与用户友好两种形式都要通过，越界与非法字符要被拒。
    #[test]
    fn validates_raw_and_friendly_addresses() {
        // masterchain 的 raw 地址：`-1` + 64 位十六进制。
        assert!(
            validate_address("-1:3333333333333333333333333333333333333333333333333333333333333333")
                .is_ok()
        );
        // 48 字符的用户友好地址。
        assert!(validate_address("EQAvDfWFG0oYX19jwNDNBBL1rKNT9XfaGP9HyTb5nb2Eml6y").is_ok());
        // raw 形式但哈希长度不足。
        assert!(validate_address("0:short").is_err());
        // 含空格：既不是 raw 也不满足 base64 字符集。
        assert!(validate_address("bad address").is_err());
        // workchain 999 超出 i32 的合法使用范围 -128..=127。
        assert!(
            validate_address(
                "999:3333333333333333333333333333333333333333333333333333333333333333"
            )
            .is_err()
        );
    }
}
