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
//! 本适配器提供只读查询 + 本地地址派生 + **原生转账**：
//! `transfer` 在本地构造 `fvm_shared::Message`，计算消息 CID（DAG-CBOR + blake2b-256），
//! 对 `blake2b-256(消息CID)` 做 secp256k1 可恢复签名，dry-run 直接返回签名结果，
//! 广播则组装 Lotus 形态的 `SignedMessage` JSON 走 `Filecoin.MpoolPush`。

// `async_trait` 属性宏：把 trait 里的 `async fn` 改写成返回装箱 Future 的普通 fn。
// 稳定版 Rust 目前不允许 trait 里直接写 `async fn`（会破坏对象安全），
// 有了它才能写出 `impl ChainClient for FilClient`，并让上层用 `Box<dyn ChainClient>`
// 在运行期按链名分发。
use async_trait::async_trait;
// `Value` 是任意 JSON 值；`json!` 是用字面量语法构造 `Value` 的宏。
use serde_json::{Value, json};

use allchain_core::{
    AddressView, BalanceView, BlockView, BuildTransferRequest, BuildTransferView, ChainClient,
    ChainKind, ErrorCode, SdkError, StatusView, SubmitRequest, SubmitView, TransferRequest,
    TransferView, TxStatus, TxView, hexutil, parse_units,
};
// `chain_rpcutil` 是被各新链共用的 HTTP/JSON-RPC 工具层。
// 这里只取用四个：`Http`（客户端）、`field_u64`（取 u64 字段）、`loose_u128`/`loose_u64`（宽松解析大整数）。
use chain_rpcutil::{Http, field_u64, loose_u128, loose_u64};

// FIL 原生转账依赖 fvm_shared 的数据模型与签名类型：
// - `Address`：f0/f1/f2/f3/f4 全协议地址，含 `new_secp256k1` 与 `FromStr`；
// - `Message`：无签名消息；`Signature`：65 字节可恢复签名；`TokenAmount`：attoFIL 金额；
// - `RawBytes`：空 params；`to_vec`：DAG-CBOR 编码（消息 CID 的数据源）。
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
// base64 0.22 的 `encode` 需经 `Engine` trait：`STANDARD.encode(...)`。
use base64::Engine as _;
use fvm_shared::message::Message;
use fvm_ipld_encoding::{RawBytes, to_vec};
// 构造消息 CID：DAG-CBOR codec = 0x71，multihash 用 blake2b-256（code 0xb220）。
use cid::Cid;
use multihash::Multihash;

// k256：secp256k1 可恢复签名。`SigningKey` 用于离线签名，
// 其 `verifying_key().to_encoded_point(false)` 把验证密钥展开成 65 字节未压缩公钥以派生 f1 地址。
use k256::ecdsa::SigningKey;

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
    /// 原生 FIL 转账：本地构造并签名 `Message`，dry-run 返回签名、广播走 `MpoolPush`。
    ///
    /// 签名约定（与 `fvm_shared::crypto::signature` 的 verify 完全对称）：
    /// 1. 对 CBOR 编码后的 `Message` 取 blake2b-256，构造 DAG-CBOR + blake2b-256 的 CID；
    /// 2. 对 `blake2b-256(消息CID)` 的 32 字节摘要做 secp256k1 可恢复签名；
    /// 3. 签名 = `r(32) || s(32) || recovery_id(1)`，recovery_id 用 `k256` 原生字节
    ///    （0..=3，**不**加 27，与 Lotus / fvm_shared 一致）。
    ///
    /// 私钥格式：32 字节 hex（可选 `0x` 前缀）的 secp256k1 原始私钥；
    /// 发送方地址由该私钥的公钥经 `Address::new_secp256k1` 派生，故 `req.from` 被忽略。
    async fn transfer(&self, req: TransferRequest) -> Result<TransferView, SdkError> {
        // 1. 解析私钥 → 签名密钥 + 发送方地址。
        let (signing_key, from_addr) = derive_secp256k1_key(&req.private_key)?;
        let from_str = from_addr.to_string();

        // 2. 解析收款地址：fvm_shared 的 `FromStr` 支持 f0/f1/f2/f3/f4 全协议。
        let to_addr: Address = req
            .to
            .trim()
            .parse()
            .map_err(|e| SdkError::invalid_argument(format!("非法 FIL 收款地址 {}: {}", req.to, e)))?;

        // 3. 金额：人类可读 → attoFIL（18 位小数）。
        let amount_raw = parse_units(&req.amount, self.kind().decimals())?;

        // 4. 取发送方 nonce。
        let nonce = get_nonce(&self.http, &from_str).await?;

        // 5. 构造未签名消息（gas 先留 0，交给节点估算）。
        let mut msg = Message {
            version: 0,
            from: from_addr,
            to: to_addr,
            sequence: nonce,
            value: TokenAmount::from_atto(amount_raw),
            method_num: 0,
            params: RawBytes::new(Vec::new()),
            gas_limit: 0,
            gas_fee_cap: TokenAmount::from_atto(0u128),
            gas_premium: TokenAmount::from_atto(0u128),
        };

        // 6. 估算 gas（失败则用保守默认，dry_run / 广播都尽量可用）。
        let gas_estimated = estimate_gas(&self.http, &mut msg).await;

        // 7. 计算消息 CID：CBOR → blake2b-256 → DAG-CBOR multihash。
        let bz = to_vec(&msg)
            .map_err(|e| SdkError::new(ErrorCode::ParseError, format!("CBOR 编码消息失败: {e}")))?;
        let digest = blake2b_256(&bz);
        let mh = Multihash::<64>::wrap(0xb220, &digest).map_err(|e| {
            SdkError::new(ErrorCode::ParseError, format!("构造 multihash 失败: {e}"))
        })?;
        let cid = Cid::new_v1(0x71, mh);
        let cid_bytes = cid.to_bytes();

        // 8. 对 `blake2b-256(消息CID)` 做 secp256k1 可恢复签名（65 字节）。
        let sign_digest = blake2b_256(&cid_bytes);
        let sig_65 = sign_digest_recoverable(&signing_key, &sign_digest)?;

        let cid_str = cid.to_string();

        // dry-run：只返回本地签名结果，不广播。
        if req.dry_run {
            return Ok(TransferView::new(
                ChainKind::Fil,
                &self.network,
                Some(from_str),
                req.to,
                amount_raw,
                Some(cid_str.clone()),
                false,
            )
            .with_extra(json!({
                "cid": cid_str,
                "signature": hex::encode(sig_65),
                "gas_estimated": gas_estimated,
                "note": "本地已完成 secp256k1 签名（blake2b-256(消息CID) 的 65 字节可恢复签名），未广播",
            })));
        }

        // 9. 广播：组装 Lotus 形态的 SignedMessage JSON，调用 MpoolPush。
        let signed_json = json!({
            "Message": message_to_lotus_json(&msg),
            "Signature": { "Type": 1, "Data": base64::engine::general_purpose::STANDARD.encode(sig_65) },
        });
        let resp = self
            .http
            .jsonrpc("Filecoin.MpoolPush", json!([signed_json]))
            .await?;
        // Lotus 把返回的消息 CID 序列化成 IPLD 链接 `{ " / ": "bafy..." }`；
        // 本地已算出相同的 CID，下列仅作回显佐证，tx_hash 统一用本地 CID。
        let node_cid = resp.get("/").and_then(Value::as_str).map(|s| s.to_string());
        Ok(TransferView::new(
            ChainKind::Fil,
            &self.network,
            Some(from_str),
            req.to,
            amount_raw,
            Some(cid_str.clone()),
            true,
        )
        .with_extra(json!({
            "cid": cid_str,
            "node_cid": node_cid,
            "gas_estimated": gas_estimated,
        })))
    }

    /// **无私钥**构造转账：取 nonce → 估 gas → 算 CID 与待签摘要 → 交回调用方。
    ///
    /// 与 [`Self::transfer`] 的分工：
    /// - `transfer` 是**一体式**——私钥进 SDK，签名与广播都在 SDK 内完成；
    /// - `build_transfer` 是**两段式**的第一段——SDK 只负责构造，
    ///   签名交给调用方（agent）用自己的私钥做，私钥从不进入本进程。
    ///
    /// 领域说明——为什么 FIL **不需要** `public_key`：
    /// 账户地址就是公钥的哈希，但构造消息时**用不到公钥**——
    /// 消息里只放地址，公钥由签名携带（recovery id 反推）。
    /// 于是这里只校验 `from` 是合法地址，至于调用方是否真的拥有它，
    /// 留到广播阶段由 [`crate::tx::verify_signature`] 用签名证明。
    /// 这与 BTC 不同：BTC 的见证里必须显式放公钥，所以那边必填。
    async fn build_transfer(&self, req: BuildTransferRequest) -> Result<BuildTransferView, SdkError> {
        // 金额：人类可读 FIL → attoFIL（18 位小数）。
        let amount_raw = parse_units(&req.amount, self.kind().decimals())?;

        let built =
            crate::tx::assemble_unsigned(&self.http, &req.from, &req.to, amount_raw).await?;

        let context = crate::tx::build_context(&self.network, &built.message)?;

        Ok(BuildTransferView::new(
            ChainKind::Fil,
            &self.network,
            req.from,
            req.to,
            amount_raw,
            // 未签名消息体（DAG-CBOR 字节）的十六进制。
            crate::tx::encode_message(&built.message)?,
            // **真正要签的是 32 字节摘要**，不是上面的消息字节、也不是 CID 字符串。
            hexutil::encode_hex_prefixed(&built.signing_digest),
            "secp256k1",
            // payload 已经是最终摘要（blake2b-256 的结果），不要再哈希。
            "none",
        )
        .with_extra(json!({
            "cid": built.cid,
            "nonce": built.nonce,
            "gas_estimated": built.gas_estimated,
            "gas_limit": built.message.gas_limit,
            "gas_fee_cap": built.message.gas_fee_cap.atto().to_string(),
            "gas_premium": built.message.gas_premium.atto().to_string(),
            // —— 调用方指引 ——
            "signature_encoding": "recoverable-rs-hex",
            "signature_length": crate::tx::SIGNATURE_LEN,
            "recovery_id_range": "0..=3（Filecoin 不加 27）",
            "sighash_algorithm": "blake2b-256(cid_bytes_of_dagcbor_message)",
            "message_hex_encoding": "dag-cbor",
            // —— 广播阶段要原样回传 ——
            "submit_context": context,
            "note": "请用 secp256k1 对 signing_payload_hex 做**可恢复**签名，产出 65 字节 r||s||v；\
                     把签名放进 SubmitRequest.signatures[0]，并把 submit_context 原样放进 SubmitRequest.context，\
                     再调用 submit_tx。signed_tx_hex 在 FIL 上不使用（留空即可）。",
            "next": "submit_tx",
        })))
    }

    /// 广播已签名交易。FIL 收的是**单个签名 + 上下文**，不是拼好的交易字节。
    ///
    /// 领域说明——为什么不让 agent 直接拼 `SignedMessage` JSON：
    /// 让它自己组装，就得把 Lotus 的字段命名（首字母大写）、
    /// 金额的字符串化、签名的 base64 编码全抄一遍。
    /// 任一处出错，节点返回的是 `invalid signature` 或 `malformed message`，
    /// 不会指出具体哪个字段。所以这里只收 65 字节签名，由 SDK 组装并验签。
    ///
    /// 参数约定：
    /// - `signatures`：**恰好一个** 65 字节可恢复签名（十六进制），`v` 取 0..=3；
    /// - `context`：`build_transfer` 下发的 `extra.submit_context`，原样回传；
    /// - `signed_tx_hex`：FIL **不使用**（设为 `""` 即可）——最终消息由 SDK 组装。
    async fn submit_tx(&self, req: SubmitRequest) -> Result<SubmitView, SdkError> {
        let encoding = req
            .encoding
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("hex");
        if encoding != "hex" {
            return Err(SdkError::invalid_argument(format!(
                "FIL 签名只接受 hex 编码，收到 {encoding}"
            )));
        }

        let context_value = req.context.ok_or_else(|| {
            SdkError::invalid_argument(
                "FIL 广播必须回传 build_transfer 下发的 extra.submit_context：\
                 消息体（含 gas 三元组与 nonce）不在签名里，缺了它无法重组 SignedMessage",
            )
        })?;
        let context: crate::tx::SubmitContext = serde_json::from_value(context_value)
            .map_err(|e| SdkError::invalid_argument(format!("submit_context 解析失败: {e}")))?;

        // 跨网护栏：主网与测试网的地址前缀不同（f / t），
        // 但**同一份字节在两条链上都能验签通过**——
        // 链本身不校验网络，所以这一步必须在广播前由 SDK 拦住。
        if context.network != self.network {
            return Err(SdkError::invalid_argument(format!(
                "网络不匹配：该上下文是在 {} 构造的，当前客户端是 {}",
                context.network, self.network
            )));
        }

        let raw_signatures = req.signatures.ok_or_else(|| {
            SdkError::invalid_argument(
                "FIL 广播需要 signatures 数组：请放入一个 65 字节可恢复签名（r||s||v，v 取 0..=3）",
            )
        })?;
        if raw_signatures.len() != 1 {
            return Err(SdkError::invalid_argument(format!(
                "FIL 一笔交易只需一个签名，收到 {} 个",
                raw_signatures.len()
            )));
        }
        let signature = crate::tx::parse_signature(&raw_signatures[0])?;

        // 重建消息（内含 CID 自检），再验签（恢复公钥 → 派生地址 → 与 from 比对）。
        let message = crate::tx::rebuild_message(&context)?;
        let recovered = crate::tx::verify_signature(&context, &signature)?;
        let signed_json = crate::tx::signed_message_json(&message, &signature);

        // 广播是唯一**不可逆**的操作，前面所有校验都是为了走到这里时已万无一失。
        let resp = self
            .http
            .jsonrpc("Filecoin.MpoolPush", json!([signed_json]))
            .await
            .map_err(|e| SdkError::new(ErrorCode::RpcError, format!("广播 FIL 交易失败: {e}")))?;

        // Lotus 把返回的消息 CID 序列化成 IPLD 链接 `{"/": "bafy..."}`。
        // 本地已算出相同的 CID，取回的那个仅作回显佐证。
        let node_cid: Option<String> = resp.get("/").and_then(Value::as_str).map(str::to_string);
        let cid = crate::tx::message_cid(&message)?.to_string();

        Ok(SubmitView::new(ChainKind::Fil, &self.network, cid.clone()).with_extra(json!({
            "broadcast": true,
            "cid": cid,
            "node_cid": node_cid,
            // 节点返回的 CID 应与本地算出的一致；不一致说明数据源做了非预期处理。
            "cid_matches_local": node_cid.as_deref() == Some(cid.as_str()),
            "from": recovered,
            "to": context.to,
            "quantity_atto": context.quantity_atto,
            "nonce": context.nonce,
            "gas_limit": context.gas_limit,
        })))
    }
}

/// 由 32 字节 hex 私钥派生 secp256k1 签名密钥与 f1 发送方地址。
///
/// FIL 的发送方完全由私钥决定（只能对持有的密钥签名），故 `req.from` 在 FIL 上被忽略。
fn derive_secp256k1_key(private_key: &str) -> Result<(SigningKey, Address), SdkError> {
    let bytes = hexutil::decode_hex(private_key)?;
    if bytes.len() != 32 {
        return Err(SdkError::invalid_argument(format!(
            "FIL 私钥需为 32 字节（64 hex 字符），实际 {} 字节",
            bytes.len()
        )));
    }
    let signing_key = SigningKey::from_slice(&bytes).map_err(|e| {
        SdkError::new(ErrorCode::Internal, format!("构造签名密钥失败: {e}"))
    })?;
    let verifying_key = signing_key.verifying_key();
    let pub_point = verifying_key.to_encoded_point(false);
    let addr = Address::new_secp256k1(pub_point.as_bytes()).map_err(|e| {
        SdkError::new(ErrorCode::InvalidArgument, format!("派生 f1 地址失败: {e}"))
    })?;
    Ok((signing_key, addr))
}

/// 对 32 字节预哈希做 secp256k1 可恢复签名，输出 65 字节 `r||s||recovery_id`。
fn sign_digest_recoverable(signing_key: &SigningKey, prehash: &[u8; 32]) -> Result<[u8; 65], SdkError> {
    let (sig, recid) = signing_key.sign_prehash_recoverable(prehash).map_err(|e| {
        SdkError::new(ErrorCode::Internal, format!("secp256k1 签名失败: {e}"))
    })?;
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(sig.to_bytes().as_slice());
    out[64] = recid.to_byte();
    Ok(out)
}

/// blake2b-256（32 字节输出）：FIL 消息 CID 与签名摘要都用到它。
///
/// 特意用可变输出长度的 `Blake2bVar`（而非固定 32 字节的 `Blake2b`），
/// 与 `chain/fil/src/address.rs` 里地址派生的 blake2b 用法保持一致。
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    use blake2::digest::{Update, VariableOutput};
    let mut h = blake2::Blake2bVar::new(32).expect("blake2b-256 长度合法");
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("输出缓冲长度匹配");
    out
}

/// 取发送方下一笔消息的 nonce（`MpoolGetNonce`）。
///
/// 声明为 `pub(crate)` 供 `crate::tx` 的两段式构造复用——
/// nonce 是链上状态，两段式与一体式必须取到同一个值，
/// 让两者共用这一个函数比各写一份更可靠。
pub(crate) async fn get_nonce(http: &Http, from: &str) -> Result<u64, SdkError> {
    let v = http.jsonrpc("Filecoin.MpoolGetNonce", json!([from])).await?;
    loose_u64(&v)
        .map_err(|_| SdkError::new(ErrorCode::ParseError, format!("解析 nonce 失败: {v}")))
}

/// 估算 gas：把 gas 全置 0 的模板消息交给 `GasEstimateMessageGas`，
/// 取回填充好的 `GasLimit` / `GasFeeCap` / `GasPremium`。
///
/// 声明为 `pub(crate)` 的理由同 `get_nonce`：gas 三元组直接参与 CID，
/// 两条路径若用了不同的估算逻辑，同一笔转账会算出两份不同的字节。
pub(crate) async fn estimate_gas(http: &Http, msg: &mut Message) -> bool {
    let template = message_to_lotus_json(msg);
    match http
        .jsonrpc(
            "Filecoin.GasEstimateMessageGas",
            json!([template, Value::Null, Value::Null]),
        )
        .await
    {
        Ok(est) => {
            if let Some(gl) = est.get("GasLimit").and_then(Value::as_u64) {
                msg.gas_limit = gl;
            }
            if let Some(fc) = est
                .get("GasFeeCap")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<u128>().ok())
            {
                msg.gas_fee_cap = TokenAmount::from_atto(fc);
            }
            if let Some(gp) = est
                .get("GasPremium")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<u128>().ok())
            {
                msg.gas_premium = TokenAmount::from_atto(gp);
            }
            true
        }
        Err(_) => {
            msg.gas_limit = 2_000_000;
            false
        }
    }
}

/// 构造 Lotus JSON-RPC 接受的 Message JSON 形态（字段名首字母大写，金额/Params 为字符串/base64）。
fn message_to_lotus_json(msg: &Message) -> Value {
    json!({
        "Version": msg.version,
        "To": msg.to.to_string(),
        "From": msg.from.to_string(),
        "Nonce": msg.sequence,
        "Value": msg.value.to_string(),
        "GasLimit": msg.gas_limit,
        "GasFeeCap": msg.gas_fee_cap.to_string(),
        "GasPremium": msg.gas_premium.to_string(),
        "Method": msg.method_num,
        "Params": base64::engine::general_purpose::STANDARD.encode(msg.params.bytes()),
    })
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

    /// 转账签名的端到端正确性（不依赖网络）。
    ///
    /// 用 k256 从「预哈希 + 65 字节签名」恢复公钥，再经 `Address::new_secp256k1`
    /// 派生地址，必须回推出 `derive_secp256k1_key` 得到的发送方地址。
    /// 这与 `fvm_shared::crypto::signature::verify` 的内部恢复路径完全一致
    /// （fvm_shared 的 verify 同样用 k256 的 `recover_from_prehash`），
    /// 因此该测试等价于「签名能被链上校验通过」的离线证明，
    /// 唯一前提是签名预哈希 = `blake2b-256(消息CID)`（与 `transfer` 实现一致）。
    #[test]
    fn transfer_sign_verify_roundtrip() {
        use k256::ecdsa::{RecoveryId as KRecId, Signature as KSig, VerifyingKey};

        // 任意 32 字节私钥（非真实资金），仅用于验证签名/恢复闭环。
        let priv_hex = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let (sk, from_addr) = derive_secp256k1_key(priv_hex).unwrap();

        // 取一段「伪消息 CID 字节」作为签名对象；
        // 真实路径里这里是 `Cid::new_v1(DagCBOR, blake2b-256(CBOR)).to_bytes()`。
        let cid_bytes = b"bafy2bzacaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let pre = blake2b_256(cid_bytes);

        let sig_65 = sign_digest_recoverable(&sk, &pre).unwrap();
        assert_eq!(sig_65.len(), 65, "FIL secp256k1 签名必须是 65 字节");

        // 用 k256 恢复公钥，并要求派生地址与发送方一致。
        let sig = KSig::from_slice(&sig_65[..64]).expect("r||s 应为 64 字节");
        let rec_id = KRecId::from_byte(sig_65[64]).expect("recovery id 合法");
        let vk = VerifyingKey::recover_from_prehash(&pre, &sig, rec_id)
            .expect("应能由签名恢复出公钥");
        let pt = vk.to_encoded_point(false);
        let rec_addr = Address::new_secp256k1(pt.as_bytes()).expect("派生 f1 地址");
        assert_eq!(rec_addr, from_addr, "恢复的地址必须等于发送方地址");
    }
}
