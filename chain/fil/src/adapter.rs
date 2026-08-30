//! Filecoin 链对统一 `ChainClient` 契约的实现（Lotus JSON-RPC）。
//!
//! 与 EVM 类链的**结构性差异**，是本适配器所有特殊处理的总根源：
//! 1. Filecoin 的出块单位是 **tipset**（同一高度上可能有多个区块），
//!    而统一模型 `BlockView` 只有单个「区块」概念。本实现的取舍是：
//!    用 tipset 的**第一个区块**代表整个 tipset，其余区块的统计信息放进 `extra`；
//! 2. Filecoin 的最小可查询对象是 **message**（消息），不是「交易」。
//!    一笔 message 可以调用合约（Method != 0），此时 `Value` 字段没有金额语义；
//! 3. 区块引用既可以是高度也可以是 **CID**（内容寻址标识符），
//!    且 CID 在 JSON 里被 Lotus 表示成 `{" / ": "bafy..."}` 这种 IPLD 链接形式，
//!    取值时必须用 JSON Pointer 的 `~1` 转义（见 `status` 里的注释）。
//!
//! 本适配器**只提供只读查询 + 本地地址派生**，不实现 `transfer`。

// `async_trait` 属性宏：把 trait 里的 `async fn` 改写成返回装箱 Future 的普通 fn。
// 稳定版 Rust 目前不允许 trait 里直接写 `async fn`（会破坏对象安全），
// 有了它才能写出 `impl ChainClient for FilClient`，并让上层用 `Box<dyn ChainClient>`
// 在运行期按链名分发。
use async_trait::async_trait;
// `Value` 是任意 JSON 值；`json!` 是用字面量语法构造 `Value` 的宏。
use serde_json::{Value, json};

use allchain_core::{
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, ErrorCode, SdkError, StatusView,
    TxStatus, TxView, hexutil,
};
// `chain_rpcutil` 是被各新链共用的 HTTP/JSON-RPC 工具层。
// 这里只取用三个：`Http`（客户端）、`field_u64`（取 u64 字段）、`loose_u128`（宽松解析大整数）。
use chain_rpcutil::{Http, field_u64, loose_u128};

use crate::address;
// `network::{self, NetworkArg}`：`self` 表示同时把 `network` **模块本身**引入作用域，
// 于是既能写 `network::parse(...)`，也能直接写 `NetworkArg::Mainnet`。
use crate::network::{self, NetworkArg};

/// Filecoin 适配器。构造后不可变，可在多线程/多任务间共享。
///
/// 语法说明：这里**没有** `#[derive(Clone)]`。
/// `Http` 本身是可廉价克隆的（内部是 `Arc`），若将来需要就让调用方包 `Arc<FilClient>`，
/// 不必在这里预设。
pub struct FilClient {
    /// 网络名（`mainnet` / `calibration` / `localnet` / `custom`）。
    network: String,
    /// 实际 RPC 端点，回显到各 View 的 `rpc_url` 字段。
    rpc_url: String,
    /// 是否主网。决定地址派生的前缀是 `f` 还是 `t`（见 `network::NetworkArg::address_prefix`）。
    ///
    /// 注意：使用**自定义 RPC URL** 时这个值被硬编码为 `true`（见 `new`），
    /// 因为无法从 URL 反推目标网络。若用自定义 URL 连测试网，派生出的地址前缀会不对。
    is_mainnet: bool,
    /// 共用的 HTTP 客户端（内含连接池）。
    http: Http,
}

impl FilClient {
    /// 构造客户端。`rpc_url` 优先于 `network`：显式给了 URL 就以它为准，
    /// 网络名记为 `custom`。
    ///
    /// 这个「URL 优先」的约定对**自建节点 / 付费节点**场景很关键：
    /// 调用方不该为了指向自己的节点，而被迫选一个不匹配的内置网络名。
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        // 三步链式处理把「没传 / 传空串」统一折叠成 `None`，
        // 最后 `.map(str::to_string)` 把 `Option<&str>` 变成 `Option<String>`。
        // 这里把 `str::to_string` 当函数值直接传给 `map`——
        // 它的方法签名是 `fn(&str) -> String`，正好匹配，不必写闭包。
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let (network_name, url, is_mainnet) = match custom {
            // 自定义 URL：网络名固定为 `custom`，主网标志按主网处理（见字段注释）。
            Some(url) => ("custom".to_string(), url, true),
            None => {
                // 走内置网络表。`?` 在网络名非法时直接返回 `INVALID_ARGUMENT`。
                let net = network::parse(network)?;
                (
                    // `as_str()` 返回 `&'static str`，`.to_string()` 复制一份自有 String。
                    net.as_str().to_string(),
                    net.rpc_url().to_string(),
                    // `==` 能直接用是因为 `NetworkArg` 派生了 `PartialEq`。
                    net == NetworkArg::Mainnet,
                )
            }
        };
        let http = Http::new(&url)?;
        // 字段初始化简写：`network` 等价于 `network: network`。
        Ok(Self {
            network: network_name,
            rpc_url: url,
            is_mainnet,
            http,
        })
    }

    /// 把 CID 包成 Lotus 的 IPLD 引用形式 `{"/": cid}`。
    ///
    /// 为什么必须这样包：Lotus 的 JSON-RPC 用 **IPLD 链接**表示 CID，
    /// 即一个只含 `/` 键的对象。直接把 CID 字符串传给
    /// `ChainGetTipSet` / `ChainGetMessage` 会被拒绝或返回 null。
    ///
    /// 语法说明：**关联函数**（没有 `self` 参数），调用时写作 `Self::cid_ref(cid)`
    /// 或 `FilClient::cid_ref(cid)`。等价于其它语言的静态方法。
    fn cid_ref(cid: &str) -> Value {
        // 键名是单个斜杠字符 `/`，在 JSON 里完全合法。
        json!({ "/": cid })
    }
}

// `#[async_trait]` 必须写在 `impl` 块**外面**（正上方），
// 它会改写块内所有 `async fn` 的签名。
#[async_trait]
impl ChainClient for FilClient {
    /// 所属链。同步方法：值在构造时就确定，无需 IO。
    fn kind(&self) -> ChainKind {
        ChainKind::Fil
    }

    /// 网络名。`&str` 返回值借用的是 `self.network`，
    /// 生命周期被编译器自动绑定到 `&self`（生命周期省略规则）。
    fn network(&self) -> &str {
        &self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// 链与节点状态：取最新 tipset + 节点版本。
    async fn status(&self) -> Result<StatusView, SdkError> {
        // `Filecoin.ChainHead` 的参数是空数组：`json!([])` 造一个空 JSON 数组。
        // Lotus 的 JSON-RPC 一律用**位置参数数组**，即使没有参数也要给 `[]`。
        let head = self.http.jsonrpc("Filecoin.ChainHead", json!([])).await?;
        // 版本查询是附加信息，失败不该让整个 status 挂掉，
        // 所以 `.await.ok()` 把 `Result<Value, SdkError>` 转成 `Option<Value>`，丢弃错误。
        let version = self.http.jsonrpc("Filecoin.Version", json!([])).await.ok();
        let mut view = StatusView::new(ChainKind::Fil, &self.network, &self.rpc_url);
        // 下面三个 `if let Some(..)` 是同一套路：字段能拿到就填，拿不到就留 `None`。
        // 这样上游结构微调时不会整个接口失败，只会少几个字段——
        // 这是本 SDK 面对「上游字段不稳定」时的统一策略。
        if let Ok(h) = field_u64(&head, "Height") {
            view = view.with_height(h);
        }
        // **JSON Pointer 的重点**：`"/Cids/0/~1"` 读作
        //   根 → `Cids` 键 → 数组第 0 项 → 键名为 `/` 的字段。
        // 因为 `/` 在 JSON Pointer 里是路径分隔符，要表示**字面量的斜杠键**
        // 必须转义成 `~1`（对应的 `~` 要写成 `~0`）。
        // 这正是上面 `cid_ref` 造出的 `{"/": cid}` 结构。
        if let Some(cid) = head.pointer("/Cids/0/~1").and_then(Value::as_str) {
            view = view.with_hash(cid);
        }
        // `version` 是 `Option<Value>`，不能直接 `.get(..)`，
        // 所以先 `.as_ref()` 借出 `Option<&Value>`，再用 `and_then` 串联。
        // `Value::as_str` 作为函数值传入，签名是 `fn(&Value) -> Option<&str>`。
        if let Some(v) = version
            .as_ref()
            .and_then(|v| v.get("Version"))
            .and_then(Value::as_str)
        {
            view = view.with_version(v);
        }
        // 链专有字段进 `extra`：`json!` 宏直接构造，
        // 取不到的一律给 `Value::Null`（**不能**给 `Value::Null` 以外的值，
        // 但也不能省略，因为 flatten 需要 key 存在）。
        Ok(view.with_extra(json!({
            "blocks_count": head.get("Blocks").and_then(Value::as_array).map(|b| b.len()),
            // tipset 里可能有多个区块，这里只回显第一个（代表块）的矿工。
            "miner": head.pointer("/Blocks/0/Miner").cloned().unwrap_or(Value::Null),
            "parent_base_fee": head.pointer("/Blocks/0/ParentBaseFee").cloned().unwrap_or(Value::Null),
            // Filecoin tipset 的 `Timestamp` 是 **Unix 秒**（整数），不是 RFC3339。
            "timestamp": head.pointer("/Blocks/0/Timestamp").cloned().unwrap_or(Value::Null),
        })))
    }

    /// 查询地址余额（attoFIL）。
    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        // 先用本地校验把明显非法的地址挡掉，避免白跑一次 RPC。
        // `inspect` 返回三元组，这里只需要协议号，故用 `_` 忽略后两项。
        let (protocol, _, _) = address::inspect(address)?;
        let result = self
            .http
            // WalletBalance 对**未创建过**的账户也返回字符串 "0"，
            // 所以查不到与余额为零在这里是同一回事，不报 NotFound。
            .jsonrpc("Filecoin.WalletBalance", json!([address.trim()]))
            .await?;
        let raw = match result.as_str() {
            // attoFIL 的位数可能远超 u64，且 Lotus 一律用**十进制字符串**表示大整数
            // （避免 JSON number 在 JavaScript 里丢精度），所以这里直接 parse 成 u128。
            Some(s) => s.parse::<u128>().map_err(|_| {
                SdkError::new(ErrorCode::ParseError, format!("非法 attoFIL 余额: {s}"))
            })?,
            // result 为 null（少数节点的行为）：按 0 处理而不是报错，
            // 与 Lotus 对未知账户返回 "0" 的语义保持一致。
            None => 0,
        };
        Ok(
            BalanceView::new(ChainKind::Fil, &self.network, address, raw).with_extra(json!({
                "protocol": protocol,
            })),
        )
    }


    /// 查询一条 message（Filecoin 语境下的「交易」）。
    /// 链头高度：最新 tipset 高度（裸 `u64`）。
    async fn last_block_height(&self) -> Result<u64, SdkError> {
        let tipset = self.http.jsonrpc("Filecoin.ChainHead", json!([])).await?;
        field_u64(&tipset, "Height")
    }

    /// 按高度查询 tipset（区块）。
    async fn block_by_height(&self, height: u64) -> Result<BlockView, SdkError> {
        let tipset = self
            .http
            .jsonrpc("Filecoin.ChainGetTipSetByHeight", json!([height, Value::Null]))
            .await?;
        if tipset.is_null() {
            return Err(SdkError::not_found("指定的 tipset 不存在"));
        }
        let hash = tipset
            .pointer("/Cids/0/~1")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "tipset 缺少 Cids"))?
            .to_string();
        let height_v = field_u64(&tipset, "Height").ok();
        let blocks = tipset.get("Blocks").and_then(Value::as_array);
        let timestamp = blocks
            .and_then(|b| b.first())
            .and_then(|b| b.get("Timestamp"))
            .and_then(Value::as_i64);
        let parent = blocks
            .and_then(|b| b.first())
            .and_then(|b| b.pointer("/Parents/0/~1"))
            .and_then(Value::as_str);
        let miner = blocks
            .and_then(|b| b.first())
            .and_then(|b| b.get("Miner"))
            .and_then(Value::as_str);
        let mut tx_count = 0u64;
        if let Some(cid) = tipset.pointer("/Cids/0/~1").and_then(Value::as_str)
            && let Ok(msgs) = self
                .http
                .jsonrpc("Filecoin.ChainGetBlockMessages", json!([Self::cid_ref(cid)]))
                .await
        {
            let bls = msgs
                .get("BlsMessages")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0);
            let secp = msgs
                .get("SecpkMessages")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0);
            tx_count = (bls + secp) as u64;
        }
        let mut view = BlockView::new(ChainKind::Fil, &self.network, hash).with_tx_count(tx_count);
        if let Some(h) = height_v { view = view.with_height(h); }
        if let Some(ts) = timestamp { view = view.with_timestamp(ts); }
        if let Some(p) = parent { view = view.with_parent(p); }
        Ok(view.with_extra(json!({
            "blocks_in_tipset": blocks.map(|b| b.len()),
            "miner": miner,
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        validate_cid(hash)?;
        let id = hash.trim();
        let message = self
            .http
            .jsonrpc("Filecoin.ChainGetMessage", json!([Self::cid_ref(id)]))
            .await?;
        if message.is_null() {
            return Err(SdkError::not_found(format!("FIL 消息不存在: {id}")));
        }
        // Glif 公共节点不提供 ChainGetReceipt，改用 StateSearchMsg 拿执行回执与上链高度；
        // 返回 null 表示消息尚未上链（mempool / 等待打包）。
        //
        // `StateSearchMsg` 的四个参数依次是：
        //   [0] tipset key —— `null` 表示「从最新主链往回搜」；
        //   [1] 消息 CID；
        //   [2] lookback limit —— `-1` 表示不限，一直回溯到找到为止；
        //   [3] allowReplaced —— `false` 表示不匹配被替换掉的消息。
        //
        // 语法说明：`.await.ok()` 把 Result 降级成 Option——搜索失败不代表消息不存在，
        // 可能只是节点回溯深度不够。`.filter(|v| !v.is_null())` 再把
        // 「找到了但结果是 null」也折成 None。两个情况统一按「未上链」处理。
        let search = self
            .http
            .jsonrpc(
                "Filecoin.StateSearchMsg",
                json!([Value::Null, Self::cid_ref(id), -1, false]),
            )
            .await
            .ok()
            .filter(|v| !v.is_null());
        let receipt = search.as_ref().and_then(|s| s.get("Receipt"));

        // ExitCode 是 Filecoin 的执行结果码：`0` 成功，其余皆失败。
        // 取不到（消息还在内存池）时判为 Pending。
        //
        // 注意与 EVM 的区别：EVM 的 `status` 是 1/0，Filecoin 是 0/非 0，方向正好相反。
        let status = match receipt
            .and_then(|r| r.get("ExitCode"))
            .and_then(Value::as_i64)
        {
            None => TxStatus::Pending,
            Some(0) => TxStatus::Success,
            Some(_) => TxStatus::Failed,
        };

        let mut view = TxView::new(ChainKind::Fil, &self.network, id, status);
        if let Some(h) = search
            .as_ref()
            .and_then(|s| s.get("Height"))
            .and_then(Value::as_u64)
        {
            view = view.with_height(h);
        }
        if let Some(from) = message.get("From").and_then(Value::as_str) {
            view = view.with_from(from);
        }
        if let Some(to) = message.get("To").and_then(Value::as_str) {
            view = view.with_to(to);
        }
        // Method=0 是原生 FIL 转账，Value 才有金额语义。
        //
        // 为什么必须判 Method：Filecoin 的 message 只有一个 `Value` 字段，
        // Method != 0 时它表示「随调用一起转给合约的钱」，
        // 把它当成交易金额会严重误导（比如调用存储合约时 Value 可能是 0）。
        let method = message.get("Method").and_then(Value::as_u64).unwrap_or(0);
        // let 链 + 自定义解析函数 `loose_str_u128`（见文件末尾）。
        if method == 0
            && let Some(value) = message.get("Value").and_then(loose_str_u128)
        {
            view = view.with_amount(value);
        }
        // 手续费 = GasUsed × GasPremium（attoFIL）。
        //
        // 这是**近似值**：Filecoin 的实际扣费是
        // `min(GasFeeCap, GasPremium + BaseFee) × GasUsed`，
        // 而 BaseFee 要回到父 tipset 去取（即 `ParentBaseFee`）。
        // 这里只用 GasPremium 是因为拿 BaseFee 需要再发一次 RPC，
        // 对「概览展示」不值得。精确计费请用 extra 里的原始字段自行计算。
        let gas_used = receipt
            .and_then(|r| r.get("GasUsed"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as u128;
        let gas_premium = message
            .get("GasPremium")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        // `saturating_mul` 是**饱和**乘法：溢出时停在 u128::MAX 而不是 panic
        // （debug 构建下普通 `*` 溢出会 panic，release 下会静默回绕，两者都不可接受）。
        let fee = gas_used.saturating_mul(gas_premium);
        // 只在算得出有效手续费时才填，拿不到就留 null（而不是填 0 假装知道）。
        if fee != 0 {
            view = view.with_fee(fee);
        }

        // 原始 gas 三元组全部透出，调用方需要精确计费时可自行处理。
        Ok(view.with_extra(json!({
            "method": method,
            "nonce": message.get("Nonce").cloned().unwrap_or(Value::Null),
            "gas_limit": message.get("GasLimit").cloned().unwrap_or(Value::Null),
            "gas_fee_cap": message.get("GasFeeCap").cloned().unwrap_or(Value::Null),
            "gas_premium": message.get("GasPremium").cloned().unwrap_or(Value::Null),
            "gas_used": receipt.and_then(|r| r.get("GasUsed")).cloned().unwrap_or(Value::Null),
            "exit_code": receipt.and_then(|r| r.get("ExitCode")).cloned().unwrap_or(Value::Null),
        })))
    }

    /// 由 65 字节未压缩 secp256k1 公钥派生 f1/t1 地址。**纯本地计算**，不发 RPC。
    ///
    /// 为什么 Filecoin 能支持这一项：f1 地址就是公钥的 blake2b-160 哈希加校验和，
    /// 不涉及任何链上状态，因此无需与节点交互。
    /// （对比 TON：它的地址依赖钱包合约 StateInit，无法由公钥确定，故不实现。）
    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        // 先解一次是为了拿到字节长度填 `pubkey_bytes`（并顺带校验 hex 合法性）；
        // `f1_from_pubkey` 内部还会再解一次，这里多一次解析的代价可以接受，
        // 换取「长度校验」与「地址派生」两件事各自独立、错误文案互不干扰。
        let bytes = hexutil::decode_hex(pubkey)?;
        let address = address::f1_from_pubkey(pubkey, self.is_mainnet)?;
        Ok(AddressView::new(
            ChainKind::Fil,
            &self.network,
            // 规范化回显：统一小写 + `0x` 前缀，便于调用方核对输入。
            hexutil::encode_hex_prefixed(&bytes),
            address,
            "f1-secp256k1",
            bytes.len(),
        )
        .with_extra(json!({
            "protocol": 1,
            "derivation": "blake2b160(uncompressed_pubkey) + blake2b checksum + base32",
        })))
    }
    // 语法说明：这里**没有** `transfer` 方法。
    // 它走 `ChainClient` trait 的默认实现，返回 `UNSUPPORTED`。
    // 这正是 trait 默认方法的价值：新链接入只需实现自己真正支持的能力。
}

/// 宽松解析 u128：优先按「十进制字符串」解析，失败再退回 `loose_u128`。
///
/// 为什么先试字符串：Lotus 的大整数几乎总是十进制字符串，走这条路最省；
/// 但不同版本/不同节点也可能给 JSON number，所以保留兜底。
///
/// 语法说明：`.or_else(闭包)` 只在 `Option` 为 `None`（这里是 `.and_then` 结果为 None）时
/// 才调用闭包，属于**惰性**求值——成功路径上不会白跑一次 `loose_u128`。
fn loose_str_u128(v: &Value) -> Option<u128> {
    v.as_str()
        .and_then(|s| s.parse::<u128>().ok())
        // `loose_u128(v).ok()` 把 `Result` 折成 `Option`，丢弃具体的错误文案
        // ——本函数返回 `Option`，语义是「解析不出来」，不需要解释原因。
        .or_else(|| loose_u128(v).ok())
}

/// 粗校验 Filecoin 消息 CID。
///
/// 刻意**只做格式粗校验**（长度 + 字符集），不解 CID 的版本与多哈希前缀：
/// 真正的有效性由节点在 `ChainGetMessage` 里判定，本 SDK 没必要实现
/// 一整套 CID 解析（那会引入 cid/multihash 依赖）。
fn validate_cid(raw: &str) -> Result<(), SdkError> {
    let t = raw.trim();
    // Filecoin CID v1 以 bafy/bafk 等开头，长度通常 50+。
    //
    // 长度下限取 40：CIDv1 的 base32 编码最短也要 40 字符上下的量级，
    // 这里只用于挡住「用户把 txid 或地址传进来了」这类明显误用。
    // 字符集要求是字母数字加 `-`（base32 里没有 `-`，但有的 CID 表示法会有）。
    if t.len() < 40 || !t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(SdkError::invalid_argument(format!(
            "非法 FIL 消息 CID: {raw}"
        )));
    }
    Ok(())
}

/// 单元测试模块：只测**纯函数**（不依赖网络），
/// 网络相关的行为靠集成测试或手工验证。
#[cfg(test)]
mod tests {
    use super::*;

    /// CID 校验：真实 CID 通过，明显过短的字符串被拒。
    #[test]
    fn validates_cids() {
        assert!(
            validate_cid("bafy2bzacectcjfi3cux3kxb4c2vdgwzdd3ikdqdflhstslyqnthtbaub6ubge").is_ok()
        );
        assert!(validate_cid("short").is_err());
    }

    /// 字符串与 JSON number 两种形态都要能解析。
    #[test]
    fn parses_str_u128() {
        // 这个数超过 u64 上限的五倍，用来验证走的是 u128 路径。
        assert_eq!(
            loose_str_u128(&json!("123456789012345678901")).unwrap(),
            123_456_789_012_345_678_901
        );
        assert_eq!(loose_str_u128(&json!(42)).unwrap(), 42);
    }
}
