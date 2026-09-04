//! Sui 链对统一 `ChainClient` 契约的实现（官方 GraphQL）。
//!
//! 与 EVM / UTXO 类链的**结构性差异**，决定了本适配器的三处特殊处理：
//! 1. Sui 是基于**对象**（object）的链，没有传统意义上的「区块高度」。
//!    本实现用 **checkpoint**（检查点）充当 `BlockView`：它有序号、摘要、时间戳，
//!    是唯一与「区块」可比的概念；
//! 2. 一笔 Sui 交易是**可编程交易块**（PTB），可能涉及多个输入对象与多个接收方，
//!    因此 `TxView::to` 通常为空——真实去向要看 `extra.balance_changes`；
//! 3. 余额按 **coin type** 区分，`0x2::sui::SUI` 才是原生币，
//!    其它一切（包括 USDC）都是不同的 coin type。
//!
//! 本适配器提供只读查询 + 本地地址派生 + **离线构造并签名 `transfer`**（GraphQL 广播）。

// `async_trait` 属性宏：稳定版 Rust 不允许 trait 里直接写 `async fn`
// （会破坏对象安全），它把 `async fn` 改写成返回装箱 Future 的普通 `fn`，
// 于是 `Box<dyn ChainClient>` 依然可用，上层才能在运行期按链名分发。
use async_trait::async_trait;
// `Blake2bVar` 是**可变输出长度**的 BLAKE2b：Sui 地址要 32 字节，
// 而 Filecoin 的 f1 只要 20 字节，同一个类型靠运行期参数覆盖两种需求。
use blake2::Blake2bVar;
// digest 生态把「输入」与「输出」拆成两个 trait，必须都引入：
// `Update` 给 `.update(..)`，`VariableOutput` 给 `.finalize_variable(..)`。
use blake2::digest::{Update, VariableOutput};
// `Value` 是任意 JSON 值，`json!` 是用字面量语法构造它的宏。
use serde_json::{Value, json};

use allchain_core::{
    AddressView, BalanceView, BlockView, BuildTransferRequest, BuildTransferView, ChainClient,
    ChainKind, ErrorCode, SdkError, StatusView, SubmitRequest, SubmitView, TransferRequest,
    TransferView, TxStatus, TxView, hexutil,
};
// 共用工具层：HTTP 客户端 + 宽松数值解析 + RFC3339 时间解析。
use chain_rpcutil::{Http, loose_u64, loose_u128, rfc3339_to_unix};

// 本地构造并签名 SUI 交易（Programmable Transaction Block）所需。
//
// 交易体（PTB）的构造与签名摘要的计算都下沉到了 `crate::tx`，
// 这里只保留适配器自身要用的类型：地址、对象引用、digest、签名封装。
// 少一个导入就少一处「两条路径写法漂移」的隐患。
use sui_sdk_types::{Address, Digest, ObjectReference, SignatureScheme, UserSignature};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use base64::Engine;
use bcs;
use std::str::FromStr;

use crate::network;

/// SUI 的 coin type 标识。
///
/// `0x2` 是 Sui 框架包的固定地址，`sui::SUI` 是其中的原生币类型。
/// 查余额时**必须**指定它，否则拿到的是其它 token 的余额
/// （甚至可能是空结果，而不是报错——这是 Sui GraphQL 的一个易踩的坑）。
const SUI_COIN_TYPE: &str = "0x2::sui::SUI";

/// SUI coin **对象**的 Move 类型，用于 `objects(filter: { type: … })` 过滤。
///
/// 注意它与 [`SUI_COIN_TYPE`] 是两个不同的东西：
/// - `0x2::sui::SUI` 是「币种类别」，用于 `balance(coinType: …)`；
/// - `0x2::coin::Coin<0x2::sui::SUI>` 是「装这种币的对象类型」，用于按类型筛对象。
///
/// 混用不会报错，只会查不到对象（filter 按字符串精确匹配），
/// 表现为「地址明明有钱却说没有 coin」。
const SUI_COIN_OBJECT_TYPE: &str = "0x2::coin::Coin<0x2::sui::SUI>";

/// SUI 转账的 gas budget（MIST，精度 9）。0.05 SUI 对单条 PTB 足够宽裕；
/// 选币时要求 coin 余额 ≥ 转账额 + 该预算，确保同币既作转账源又作 gas 付款。
/// `pub(crate)` 而非私有：`tx` 模块的无私钥构造流程也要用它，
/// 两条路径共用同一个常量才不会「一体式用 0.05 SUI、两段式用另一个值」。
pub(crate) const DEFAULT_GAS_BUDGET: u64 = 50_000_000;

/// checkpoint 查询里要取的字段清单，直接插进 GraphQL 选择集。
///
/// 抽成常量的原因：status 与 block 两处都要用同一批字段，
/// 抽出来才能保证两处**永远一致**——否则很容易出现
/// 「block 里能取到 previousCheckpointDigest、status 里却忘了取」这类偏差。
///
/// 语法说明：这是 `&'static str` 常量，`format!` 里用 `{CHECKPOINT_FIELDS}`
/// 直接内联捕获同名变量（Rust 1.58 起支持的**隐式命名参数**）。
const CHECKPOINT_FIELDS: &str =
    "sequenceNumber digest previousCheckpointDigest timestamp networkTotalTransactions";

/// Sui 适配器。构造后不可变，可在多任务间共享。
pub struct SuiClient {
    /// 网络名（`mainnet` / `testnet` / `devnet` / `localnet` / `custom`）。
    network: String,
    /// 实际端点，回显到各 View 的 `rpc_url` 字段。
    rpc_url: String,
    /// 共用 HTTP 客户端（内含连接池）。
    http: Http,
}

/// 构造查询某地址 SUI 主币 coin 对象的 GraphQL 查询。
///
/// # 现行 schema（2026-09 对 `graphql.mainnet.sui.io` 实测）
///
/// `Address` 上已经**没有** `coins` 字段了。旧写法（对齐 `sui-graphql-client 0.0.7`）
/// `address { coins(first: 50, type: "0x2::sui::SUI") }` 现在会被
/// `GRAPHQL_VALIDATION_FAILED` 整条拒掉，SUI 的构造流程因此完全不可用。
/// 现行写法走 `objects(... filter: { type: … })`。
///
/// # 为什么余额读 `contents { json }` 而不是 `balance { totalBalance }`
///
/// 这是本函数最容易踩的坑，且踩了**不报错**：
/// `MoveObject` 上确实也有 `balance(coinType:)` 字段，但对 coin 对象它恒返回 0。
/// 实测证据——某地址 `0x0feb54a7…` 总余额 58,569,188,076,346 MIST，
/// 其 10 个 coin 对象逐个查 `balance { totalBalance }` **全部是 "0"**；
/// 真正的面值在 Move 结构内部，`contents { json }` 给出 `{"id":…, "balance": "57853702401719"}`。
///
/// 若误用前者，得到的是「所有 coin 余额为 0」，选币逻辑于是判定余额不足——
/// 典型的**不报错、只给错答案**。
fn coins_query(owner: &str) -> String {
    format!(
        r#"{{ address(address: "{owner}") {{ objects(first: 50, filter: {{ type: "{SUI_COIN_OBJECT_TYPE}" }}) {{ nodes {{ address version digest contents {{ json }} }} }} }} }}"#
    )
}

/// 把 GraphQL 返回的 `objects.nodes` 数组解析成 [`SuiCoin`] 列表。
///
/// # 为什么抽成纯函数
///
/// 面值该从哪个字段读，是本模块**最容易错且错了不报错**的地方
/// （`balance.totalBalance` 对 coin 对象恒为 0，只有 `contents.json.balance` 才是真面值）。
/// 把解析从 `fetch_sui_coins` 里抽出来，就能用**线上抓回的真实响应**当夹具做离线测试，
/// 不必依赖网络，也不必有一个有币的密钥对。
fn parse_sui_coins(nodes: &[Value]) -> Result<Vec<SuiCoin>, SdkError> {
    let mut out = Vec::new();
    for n in nodes {
        let object_id = n
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "coin 缺 address (object id)"))?
            .to_string();
        // 面值在 Move 结构里（`contents.json.balance`，字符串形式的大整数），
        // **不是** `balance.totalBalance`——后者对 coin 对象恒为 0。
        let balance = n
            .pointer("/contents/json/balance")
            .and_then(loose_str_u128)
            .ok_or_else(|| {
                SdkError::new(ErrorCode::ParseError, "coin 缺 contents.json.balance")
            })?;
        let digest = n
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "coin 缺 digest"))?
            .to_string();
        // `version` 在现行 schema 里是 JSON 数字（UInt53），不是字符串，
        // 故用 `loose_u64` 而不是 `loose_str_u128`。
        let version = n
            .get("version")
            .and_then(|v| loose_u64(v).ok())
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "coin 缺 version"))?;
        out.push(SuiCoin { object_id, balance, digest, version });
    }
    Ok(out)
}

/// 构造广播已签名交易的 GraphQL mutation。
///
/// 对齐 `sui-graphql-client 0.0.7` 的 `schema.graphql`：`executeTransactionBlock` 只接受
/// `(txBytes, signatures)` 两个参数（**无** `requestType`）；返回 `ExecutionResult`
/// 只有 `effects`，digest 在 `effects.transactionBlock.digest`，执行状态是枚举 `status`。
///
/// 语法说明：`signatures` 是切片 `&[String]`，用 `join` 拼成
/// `"a","b"` 这种 GraphQL 列表字面量。写成切片而非固定一个字符串，
/// 是因为 Sui 允许多签（multisig / 赞助交易）携带多个签名。
fn broadcast_query(tx_base64: &str, signatures: &[String]) -> String {
    let list = signatures
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"mutation {{ executeTransactionBlock(txBytes: "{tx_base64}", signatures: [{list}]) {{ effects {{ transactionBlock {{ digest }} status }} }} }}"#
    )
}

impl SuiClient {
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
                (net.as_str().to_string(), net.graphql_url().to_string())
            }
        };
        let http = Http::new(&url)?;
        Ok(Self {
            network: network_name,
            rpc_url: url,
            http,
        })
    }

    /// 查询指定序号 checkpoint；`None` 表示最新。
    ///
    /// 语法说明：这是**私有**关联方法（无 `pub`），只在本文件内使用。
    /// `Option<u64>` 参数把「查最新」与「查指定」两个语义合并成一个函数，
    /// 避免调用方记两套名字。
    async fn checkpoint(&self, seq: Option<u64>) -> Result<Value, SdkError> {
        // GraphQL 没有路径参数，条件只能拼进查询文本。
        // 带序号时写成 `checkpoint(sequenceNumber: 123)`，不带则直接 `checkpoint`（取最新）。
        let selector = match seq {
            Some(n) => format!("checkpoint(sequenceNumber: {n})"),
            // `.to_string()` 把 `&str` 转成 `String`：match 的两个分支**必须**类型相同，
            // 而 `format!` 返回 `String`，所以这一支也得是 `String`。
            None => "checkpoint".to_string(),
        };
        // 拼出完整查询。`{{` 与 `}}` 是 `format!` 里对字面花括号的**转义**——
        // GraphQL 语法本身需要 `{ }`，而 `format!` 会把单花括号当成插值占位符。
        let query = format!("{{ {selector} {{ {CHECKPOINT_FIELDS} epoch {{ epochId }} }} }}");
        let data = self.http.graphql(&query).await?;
        // `data` 是 GraphQL 的 `data` 对象，里面只有一个 `checkpoint` 键。
        // `.filter(|v| !v.is_null())` 把「查不到返回 null」折成 None，
        // 于是下面的 `ok_or_else` 能统一报 NotFound。
        data.get("checkpoint")
            .filter(|v| !v.is_null())
            // `.cloned()` 把 `Option<&Value>` 变成 `Option<Value>`——
            // 必须克隆，因为借用的引用活不过本函数。
            .cloned()
            .ok_or_else(|| SdkError::not_found("checkpoint 不存在"))
    }

    /// 取出发件人的 `0x2::sui::SUI` coin 列表（GraphQL `address.objects`）。
    ///
    /// 按 coin 对象类型过滤，只保留原生 SUI coin；其余 coin type 直接跳过。
    /// 面值读 `contents.json.balance` 而非 `balance.totalBalance`，
    /// 原因见 [`coins_query`] 的文档——读错了不报错，只会得到全 0。
    pub(crate) async fn fetch_sui_coins(&self, owner: &str) -> Result<Vec<SuiCoin>, SdkError> {
        let query = coins_query(owner);
        let data = self.http.graphql(&query).await?;
        let nodes = data
            .pointer("/address/objects/nodes")
            .and_then(|v| v.as_array())
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "SUI coins 查询无 nodes"))?;
        parse_sui_coins(nodes)
    }

    /// 取参考 gas 价（GraphQL `epoch.referenceGasPrice`，字符串或数字大整数）。
    pub(crate) async fn fetch_reference_gas_price(&self) -> Result<u64, SdkError> {
        let query = "{ epoch { referenceGasPrice } }";
        // 参数类型是泛型 `impl Serialize`，`String` 与 `&String` 都满足，直接按值传。
        let data = self.http.graphql(query).await?;
        let v = data
            .pointer("/epoch/referenceGasPrice")
            .and_then(loose_str_u128)
            .or_else(|| {
                data.pointer("/epoch/referenceGasPrice").and_then(|x| loose_u128(x).ok())
            })
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "缺 referenceGasPrice"))?;
        Ok(v as u64)
    }

    /// 广播已签名的交易（GraphQL `executeTransactionBlock` mutation）。
    ///
    /// 领域说明——两个参数的分工是 Sui 特有的：
    /// - `tx_base64` 必须是 **`bcs(TransactionData)` 的 base64**，
    ///   **不含** 3 字节 intent 前缀（前缀只在**签名时**拼接），也**不含**签名；
    /// - `signatures` 是各自 base64 编码的 `flag || sig || pubkey`（ed25519 下 97 字节）。
    ///
    /// 早期实现误把 `bcs(SignedTransaction)`（交易体 + 签名打包后的整体）当作
    /// `txBytes` 传进去，节点侧会反序列化失败。正确拆分见 `tx::split_signed`——
    /// 那个函数是这条约束的唯一防线。
    ///
    /// 返回交易 digest；若执行状态非 `SUCCESS` 则报错。
    pub(crate) async fn broadcast_tx(
        &self,
        tx_base64: &str,
        signatures: &[String],
    ) -> Result<String, SdkError> {
        let query = broadcast_query(tx_base64, signatures);
        let data = self.http.graphql(&query).await?;
        let digest = data
            .pointer("/executeTransactionBlock/effects/transactionBlock/digest")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "广播无 digest 返回"))?
            .to_string();
        let status = data
            .pointer("/executeTransactionBlock/effects/status")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN");
        if status != "SUCCESS" {
            return Err(SdkError::new(
                ErrorCode::RpcError,
                format!("SUI 交易执行失败: {status}"),
            ));
        }
        Ok(digest)
    }
}

// `#[async_trait]` 写在 `impl` 块**正上方**，作用于块内所有 `async fn`。
#[async_trait]
impl ChainClient for SuiClient {
    /// 所属链。同步方法：值在构造时就已确定，无需 IO。
    fn kind(&self) -> ChainKind {
        ChainKind::Sui
    }

    /// 网络名。返回 `&str` 借用的是 `self.network`，
    /// 生命周期由编译器自动绑到 `&self`（生命周期省略规则）。
    fn network(&self) -> &str {
        &self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// 链与节点状态：最新 checkpoint + 链标识 + 当前 epoch。
    async fn status(&self) -> Result<StatusView, SdkError> {
        // 一次查询同时取三样东西，正是 GraphQL 相对 REST 最大的优势：
        // 换成 REST/JSON-RPC 这里至少得发三次请求。
        let query = format!(
            "{{ chainIdentifier epoch {{ epochId }} checkpoint {{ {CHECKPOINT_FIELDS} }} }}"
        );
        let data = self.http.graphql(&query).await?;
        // checkpoint 是 status 的核心，拿不到就直接报错（不像其它字段可以留空）。
        let cp = data
            .get("checkpoint")
            .ok_or_else(|| SdkError::new(ErrorCode::RpcError, "缺少最新 checkpoint"))?;
        let mut view = StatusView::new(ChainKind::Sui, &self.network, &self.rpc_url);
        // Sui 没有「区块高度」，用 checkpoint 序号顶上——
        // 它是单调递增的，调用方拿它做「进度比较」是合理的。
        if let Some(seq) = cp.get("sequenceNumber").and_then(Value::as_u64) {
            view = view.with_height(seq);
        }
        if let Some(digest) = cp.get("digest").and_then(Value::as_str) {
            view = view.with_hash(digest);
        }
        // 注意这里把 **chainIdentifier**（链标识，如 `35834a8a`）塞进了
        // `node_version` 字段。Sui 的 GraphQL 不暴露节点版本号，
        // 而 chainIdentifier 是唯一能区分「连的是主网还是测试网」的稳定标识，
        // 语义上最贴近「我连的是哪个节点」。
        if let Some(chain) = data.get("chainIdentifier").and_then(Value::as_str) {
            view = view.with_version(chain);
        }
        Ok(view.with_extra(json!({
            "epoch": data.pointer("/epoch/epochId").cloned().unwrap_or(Value::Null),
            "network_total_transactions": cp.get("networkTotalTransactions").cloned().unwrap_or(Value::Null),
        })))
    }

    /// 查询地址的原生 SUI 余额（MIST，精度 9）。
    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        // **安全要点**：地址是用 `format!` 直接插值进 GraphQL 查询文本的，
        // 所以这一步校验不只是「友好提示」，它同时是防止构造出畸形/恶意查询的闸门。
        // `validate_address` 严格限定为 `0x` + 64 位十六进制，把风险彻底封死。
        validate_address(address)?;
        // 注意 `\"{}\"` 里的转义双引号：GraphQL 的字符串参数必须用双引号包裹，
        // 而它又处在 Rust 字符串字面量里，所以要转义。
        let query = format!(
            "{{ address(address: \"{}\") {{ balance(coinType: \"{SUI_COIN_TYPE}\") {{ totalBalance }} }} }}",
            address.trim()
        );
        let data = self.http.graphql(&query).await?;
        let raw = data
            // `pointer` 用 JSON Pointer 一路取到嵌套三层的值，
            // 比 `get("address").and_then(|a| a.get("balance"))...` 清晰得多。
            .pointer("/address/balance/totalBalance")
            // `.and_then(|v| loose_u128(v).ok())` 把 `Result` 折成 `Option`：
            // 解析失败不报错，交给下面统一兜底为 0。
            .and_then(|v| loose_u128(v).ok())
            // 地址从未被使用过（链上没有这个对象）时查询结果为 null，
            // 此时按 0 处理——「未创建」与「余额为零」对调用方是一回事。
            .unwrap_or(0);
        Ok(
            BalanceView::new(ChainKind::Sui, &self.network, address, raw).with_extra(json!({
                "coin_type": SUI_COIN_TYPE,
            })),
        )
    }


    /// 查询一笔交易（digest 定位）。
    /// 链头高度：最新 checkpoint 序号（裸 `u64`）。
    async fn last_block_height(&self) -> Result<u64, SdkError> {
        let cp = self.checkpoint(None).await?;
        cp.get("sequenceNumber")
            .and_then(Value::as_u64)
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "checkpoint 缺少 sequenceNumber"))
    }

    /// 按 checkpoint 序号查询区块。
    async fn block_by_height(&self, height: u64) -> Result<BlockView, SdkError> {
        let cp = self.checkpoint(Some(height)).await?;
        let hash = cp
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "checkpoint 缺少 digest"))?
            .to_string();
        let seq = cp.get("sequenceNumber").and_then(Value::as_u64);
        let timestamp = cp.get("timestamp").and_then(Value::as_str).and_then(rfc3339_ok);
        let total_here = cp.get("networkTotalTransactions").and_then(|v| loose_u64(v).ok());
        let mut tx_count: Option<u64> = None;
        if let (Some(s), Some(total)) = (seq, total_here) {
            if s == 0 {
                tx_count = Some(total);
            } else if let Ok(prev) = self.checkpoint(Some(s - 1)).await
                && let Some(prev_total) = prev
                    .get("networkTotalTransactions")
                    .and_then(|v| loose_u64(v).ok())
            {
                tx_count = Some(total.saturating_sub(prev_total));
            }
        }
        let mut view = BlockView::new(ChainKind::Sui, &self.network, hash);
        if let Some(s) = seq { view = view.with_height(s); }
        if let Some(ts) = timestamp { view = view.with_timestamp(ts); }
        if let Some(n) = tx_count { view = view.with_tx_count(n); }
        if let Some(parent) = cp.get("previousCheckpointDigest").and_then(Value::as_str) {
            view = view.with_parent(parent);
        }
        Ok(view.with_extra(json!({
            "epoch": cp.pointer("/epoch/epochId").cloned().unwrap_or(Value::Null),
            "network_total_transactions": cp.get("networkTotalTransactions").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        // digest 会被插值进 GraphQL 查询，先做字符集校验（同 `balance` 的道理）。
        validate_digest(hash)?;
        let digest = hash.trim();
        // 语法说明：`r#"..."#` 是**原始字符串**字面量，
        // 里面的双引号与反斜杠都不需要转义，写 GraphQL / JSON 这类文本时可读性极好。
        // `#` 的个数可以按需增加（如 `r##".."##`）以容纳内容里出现的 `"#`。
        let query = format!(
            r#"{{ transaction(digest: "{digest}") {{
                digest
                sender {{ address }}
                effects {{
                    status
                    timestamp
                    checkpoint {{ sequenceNumber }}
                    gasEffects {{ gasSummary {{
                        computationCost storageCost storageRebate nonRefundableStorageFee
                    }} }}
                    balanceChanges(first: 20) {{ nodes {{ coinType {{ repr }} amount }} }}
                }}
            }} }}"#
        );
        let data = self.http.graphql(&query).await?;
        let tx = data
            .get("transaction")
            // 查不到交易时 GraphQL 返回 `{"transaction": null}`（**不是** errors），
            // 所以要用 `.filter(|v| !v.is_null())` 折成 None 再报 NotFound。
            .filter(|v| !v.is_null())
            .ok_or_else(|| SdkError::not_found(format!("SUI 交易不存在: {digest}")))?;
        // effects 是 Sui 的交易执行结果，缺了它什么都查不到，因此直接报错。
        let effects = tx
            .get("effects")
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "交易缺少 effects"))?;

        // Sui 的 status 是字符串枚举 `SUCCESS` / `FAILURE`。
        // 取不到（交易还在共识中）时判为 Unknown 而非 Failed——
        // 「不知道」与「确定失败」必须区分，否则调用方会误报。
        let status = match effects.get("status").and_then(Value::as_str) {
            Some("SUCCESS") => TxStatus::Success,
            Some("FAILURE") => TxStatus::Failed,
            _ => TxStatus::Unknown,
        };
        let mut view = TxView::new(ChainKind::Sui, &self.network, digest, status);
        if let Some(sender) = tx.pointer("/sender/address").and_then(Value::as_str) {
            view = view.with_from(sender);
        }
        // Sui 的「高度」是交易所在 checkpoint 的序号。
        if let Some(seq) = effects
            .pointer("/checkpoint/sequenceNumber")
            .and_then(Value::as_u64)
        {
            view = view.with_height(seq);
        }
        if let Some(ts) = effects
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(rfc3339_ok)
        {
            view = view.with_timestamp(ts);
        }
        // gas 总额 = computation + storage − rebate。
        //
        // Sui 的 gas 计费拆成四部分，其中 `storageRebate` 是**删除对象时退还**的存储费，
        // 所以要减掉；而 `nonRefundableStorageFee` 是不可退部分，已包含在 storageCost 里，
        // 无需再处理（这里只取它原样透出到 extra）。
        //
        // 注意：**没有** `with_to`。Sui 一笔 PTB 可能有零个或多个接收方，
        // 不存在单一收款地址，强行填一个会误导；真实去向看 `extra.balance_changes`。
        let summary = effects.pointer("/gasEffects/gasSummary");
        if let Some(s) = summary {
            // 三个成本都是「可能是字符串也可能是数字」的大整数，
            // 统一走 `loose_str_u128`（见文件末尾）。
            let comp = s
                .get("computationCost")
                .and_then(loose_str_u128)
                .unwrap_or(0);
            let storage = s.get("storageCost").and_then(loose_str_u128).unwrap_or(0);
            let rebate = s.get("storageRebate").and_then(loose_str_u128).unwrap_or(0);
            // 链式饱和运算：全程不会 panic，也不会静默回绕。
            let fee = comp.saturating_add(storage).saturating_sub(rebate);
            // 只在算得出有效手续费时才填，避免把 0 当成「已知为 0」。
            if fee != 0 {
                view = view.with_fee(fee);
            }
        }
        Ok(view.with_extra(json!({
            "balance_changes": effects.pointer("/balanceChanges/nodes").cloned().unwrap_or(Value::Null),
            "gas_summary": summary.cloned().unwrap_or(Value::Null),
        })))
    }

    /// 由公钥派生 Sui 地址。**纯本地计算**，不发 RPC。
    ///
    /// 委托给下面的自由函数 `derive_address`，
    /// 这样单元测试可以直接测它而不必先构造一个客户端。
    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        derive_address(pubkey, &self.network)
    }

    /// 转账：本地构造 Programmable Transaction Block、ed25519 签名、GraphQL 广播。
    ///
    /// 私钥只参与本地签名，绝不外发。金额为人类可读 SUI（9 位精度），按 `dry_run`
    /// 决定是否广播。签名封装与 `sign` 程序共用同一套 Intent + ed25519 + UserSignature。
    async fn transfer(&self, req: TransferRequest) -> Result<TransferView, SdkError> {
        // 1) 收款地址：必须是规范化 `0x` + 64hex，并取出 32 字节作为 PTB 的 Pure 输入。
        let to_hex = req.to.trim();
        validate_address(to_hex)?;
        let to_bytes = hexutil::decode_hex(to_hex)
            .map_err(|e| SdkError::invalid_argument(format!("收款地址解析失败: {e}")))?;
        // 2) 金额：SUI 9 位精度，按整数 MIST 解析（避免浮点误差）。
        let amount = parse_sui_mist(&req.amount)
            .map_err(|e| SdkError::invalid_argument(format!("非法 SUI 金额: {e}")))?;
        // 3) 私钥（0x + 64hex 种子）→ ed25519 密钥对；发件地址由种子派生。
        let seed = parse_seed(&req.private_key)?;
        let sk = SigningKey::from_bytes(&seed);
        let vk = VerifyingKey::from(&sk);
        let from_hex = address_from_pubkey_bytes(&vk.to_bytes());
        let sender = Address::from_str(&from_hex)
            .map_err(|e| SdkError::new(ErrorCode::Internal, format!("发件地址构造失败: {e}")))?;

        // 4) 取出发件人可用 SUI coin + 参考 gas 价。
        //
        // 这两步与「无私钥」的 `build_transfer` 完全共用：
        // 只有**签名**那一步涉及私钥，构造过程两侧必须逐字节一致，
        // 否则会出现「dry-run 能过、真发失败」这类只在一条路径上复现的缺陷。
        let coins = self.fetch_sui_coins(&from_hex).await?;
        let coin = coins
            .into_iter()
            .find(|c| c.balance >= amount as u128 + DEFAULT_GAS_BUDGET as u128)
            .ok_or_else(|| {
                SdkError::invalid_argument(format!(
                    "没有余额充足的 SUI coin（需 ≥ {} + {} MIST）",
                    amount, DEFAULT_GAS_BUDGET
                ))
            })?;
        let price = self.fetch_reference_gas_price().await?;

        // 5) coin 同时作为「转账源」与「gas 付款」对象引用。
        let coin_addr = Address::from_str(&coin.object_id)
            .map_err(|e| SdkError::new(ErrorCode::Internal, format!("coin 对象地址失败: {e}")))?;
        let coin_ref = ObjectReference::new(
            coin_addr,
            coin.version,
            Digest::from_str(&coin.digest)
                .map_err(|e| SdkError::new(ErrorCode::Internal, format!("coin digest 解析失败: {e}")))?,
        );

        // 6) 构造 PTB：SplitCoins(coin, [amount]) → TransferObjects([split], to)。
        //
        // 走 `tx::build_transaction` 而不是在这里内联，理由同上：
        // 交易体的构造逻辑只有一份，两条签名路径不可能漂移。
        let tx = crate::tx::build_transaction(&crate::tx::TransferParams {
            sender,
            public_key: vk.to_bytes(),
            receiver: Address::new(
                to_bytes
                    .clone()
                    .try_into()
                    .map_err(|_| SdkError::invalid_argument("收款地址不是 32 字节"))?,
            ),
            amount,
            coin: coin_ref,
            gas_price: price,
            gas_budget: DEFAULT_GAS_BUDGET,
        })?;

        // 7) 本地签名。
        //
        // **关键修正**：签的是 `blake2b256([0,0,0] || bcs(TransactionData))` 这个
        // **32 字节摘要**，不是 intent 消息原文。官方规范见
        // `docs.sui.io/learn/cryptography/sui-offline-signing`。
        // 漏掉哈希时本地验签照样通过，只有节点会以 `InvalidSignature` 拒绝——
        // 这类缺陷必须靠外部真值测试才能发现，见
        // `tx::tests::signing_digest_is_the_blake2b_of_the_intent_message`。
        //
        // 摘要计算复用 `crate::tx::signing_digest`，与无私钥路径是同一个实现。
        let digest = crate::tx::signing_digest(&tx)?;
        let sig = sk.sign(&digest);
        let mut full = vec![SignatureScheme::Ed25519 as u8];
        full.extend_from_slice(&sig.to_bytes());
        full.extend_from_slice(&vk.to_bytes());
        // 封装成 `UserSignature`：这一步顺带校验「flag ‖ sig ‖ pubkey」的
        // 长度与方案合法性，比自己拼字符串后再交给节点要早暴露问题。
        let user_sig = UserSignature::from_bytes(&full)
            .map_err(|e| SdkError::new(ErrorCode::Internal, format!("签名封装失败: {e}")))?;
        // 用官方的 `to_base64()` 而不是自己 base64 编码：编码方式只有一处定义。
        let sig_base64 = user_sig.to_base64();

        // 8) 广播用的两个参数必须**分开**：
        //    tx_bytes 是纯 `bcs(TransactionData)`，签名单独传。
        //    早期版本把 `bcs(SignedTransaction)` 整体当 tx_bytes 传，节点会拒绝。
        let tx_bytes = bcs::to_bytes(&tx)
            .map_err(|e| SdkError::new(ErrorCode::Internal, format!("交易序列化失败: {e}")))?;
        let tx_base64 = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);

        // 9) dry-run：仅返回本地签名，不广播。
        if req.dry_run {
            return Ok(TransferView::new(
                ChainKind::Sui,
                &self.network,
                Some(from_hex.clone()),
                req.to,
                amount as u128,
                Some(hexutil::encode_hex_prefixed(&full)),
                false,
            )
            .with_extra(json!({ "signed_tx_base64": tx_base64 })));
        }

        // 10) 真发：GraphQL executeTransactionBlock 广播。
        let tx_digest = self.broadcast_tx(&tx_base64, &[sig_base64]).await?;
        Ok(TransferView::new(
            ChainKind::Sui,
            &self.network,
            Some(from_hex),
            req.to,
            amount as u128,
            Some(tx_digest),
            true,
        )
        .with_extra(json!({ "signed_tx_base64": tx_base64 })))
    }

    /// **无私钥**构造转账：选 coin、取 gas 价、组装 PTB，产出待签摘要。
    ///
    /// 与 [`ChainClient::transfer`] 的分工：`transfer` 是**一段式**（私钥进 SDK，
    /// 构造 + 签名 + 广播全在 SDK 内）；本方法是**两段式**的第一段——只组装，
    /// 签名交给调用方（agent）用自己的私钥做，私钥从不进入本进程。
    ///
    /// 调用方拿到结果后应：
    ///   1. 对 `signing_payload_hex`（32 字节 blake2b-256 摘要）做 ed25519 签名；
    ///   2. 把 64 字节签名写到 `unsigned_tx_hex` 的 `signature_offset` 处；
    ///   3. 交给 [`Self::submit_tx`] 广播。
    ///
    /// 领域说明——为什么本链**必须**显式给 `public_key`：
    /// Sui 的地址是 `blake2b256(flag || pubkey)`，**哈希不可逆**；
    /// 而 `UserSignature` 里又必须带公钥（节点靠它定位签名密钥）。
    /// 没有公钥就组不出可广播的字节，故没有回退路径。
    async fn build_transfer(
        &self,
        req: BuildTransferRequest,
    ) -> Result<BuildTransferView, SdkError> {
        // 三个地址/金额的解析都是纯本地的，失败即为参数错误，
        // 不必联网——让错误尽早、便宜地暴露。
        let sender = Address::from_str(req.from.trim())
            .map_err(|e| SdkError::invalid_argument(format!("非法 SUI 付款地址 {}: {e}", req.from)))?;
        let receiver = Address::from_str(req.to.trim())
            .map_err(|e| SdkError::invalid_argument(format!("非法 SUI 收款地址 {}: {e}", req.to)))?;
        let amount = parse_sui_mist(&req.amount)
            .map_err(|e| SdkError::invalid_argument(format!("非法 SUI 金额: {e}")))?;

        // 公钥必填，且必须是 ed25519。secp256k1 / secp256r1 的地址派生虽已支持，
        // 但两段式流程里的占位签名写死了 ed25519 标志位，故此处明确拒绝而不是静默出错。
        let public_key = self.resolve_signer_public_key(req.public_key.as_deref(), &sender)?;

        let unsigned =
            crate::tx::build_unsigned_transfer(self, sender, public_key, receiver, amount).await?;

        Ok(BuildTransferView::new(
            ChainKind::Sui,
            &self.network,
            req.from,
            req.to,
            amount as u128,
            unsigned.unsigned_tx_hex,
            unsigned.signing_payload_hex,
            "ed25519",
            // Sui 与其余 ed25519 链不同：待签对象是 **blake2b-256 摘要**（32 字节），
            // 不是消息原文。这一步哈希是官方规范强制的，漏掉会导致节点拒签。
            "blake2b-256",
        )
        .with_extra(json!({
            "public_key": hexutil::encode_hex_prefixed(&public_key),
            // 广播时单独提交的 bcs(TransactionData)，便于调用方核对「签的是什么」。
            "tx_bytes_hex": unsigned.tx_bytes_hex,
            "gas_coin_id": unsigned.gas_coin_id.to_string(),
            "gas_price": unsigned.gas_price,
            "gas_budget": unsigned.gas_budget,
            // 与 NEAR / APT 的「覆盖最后 64 字节」不同：Sui 的 UserSignature 是
            // flag || sig || pubkey，公钥在签名**之后**，故这里给的是显式偏移。
            "splice": "replace_64_bytes_at_offset",
            "signature_offset": unsigned.signature_offset,
            "signature_length": 64,
            "note": "对 signing_payload_hex（32 字节 blake2b-256 摘要）做 ed25519 签名；\
                     把得到的 64 字节写到 unsigned_tx_hex 的 signature_offset 处后提交",
            "next": "submit_tx",
        })))
    }

    /// 广播已签名交易，返回交易 digest。
    ///
    /// 领域说明：Sui 的 `executeTransactionBlock` 是**同步等待执行结果**的
    /// （返回里带 `effects.status`），故这里的 digest 意味着交易**已执行成功**，
    /// 与 ETH / NEAR 那种「进 mempool 就返回、落块另说」的模型不同。
    ///
    /// 编码说明：`encoding` 支持 `hex`（默认）与 `base64`；
    /// 两者都指向同一份 `bcs(SignedTransaction)` 字节。
    async fn submit_tx(&self, req: SubmitRequest) -> Result<SubmitView, SdkError> {
        let encoding = req
            .encoding
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("hex");

        let raw = match encoding {
            "hex" => hexutil::decode_hex(&req.signed_tx_hex)?,
            "base64" => base64::engine::general_purpose::STANDARD
                .decode(req.signed_tx_hex.trim())
                .map_err(|e| {
                    SdkError::invalid_argument(format!("已签名交易不是合法 base64: {e}"))
                })?,
            other => {
                return Err(SdkError::invalid_argument(format!(
                    "SUI 已签名交易只接受 hex 或 base64 编码，收到 {other}"
                )))
            }
        };
        if raw.is_empty() {
            return Err(SdkError::invalid_argument("已签名交易为空"));
        }

        let digest = crate::tx::broadcast_raw(self, &raw).await?;

        Ok(SubmitView::new(ChainKind::Sui, &self.network, digest).with_extra(json!({
            "broadcast": true,
            "encoding": encoding,
        })))
    }
}

impl SuiClient {
    /// 解析并校验「用哪把公钥签名」，同时确认它确实对应付款地址。
    ///
    /// 领域说明——为什么要做地址一致性校验：
    /// 一个 Sui 账户名下可以挂多把密钥，用错一把仍能签出**结构合法**的交易，
    /// 但节点会以含糊的 `InvalidSignature` / `SignerNotFound` 拒绝。
    /// 在本地把这桩错误拦下，比让用户拿着一笔广播失败的交易去猜要省事得多。
    ///
    /// 语法说明：`explicit: Option<&str>` 用 `Option` 表达「调用方没给」，
    /// 而不是用空串之类的哨兵值——后者属于「不适用场景」而非「错误」，
    /// 这里按约定统一在**缺失**时才判定为错误。
    fn resolve_signer_public_key(
        &self,
        explicit: Option<&str>,
        sender: &Address,
    ) -> Result<[u8; 32], SdkError> {
        let raw = explicit
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SdkError::invalid_argument(
                    "SUI 构造交易必须显式提供 public_key：\
                     地址是 blake2b256(flag || 公钥)，无法反推；\
                     请传 32 字节 ed25519 公钥（0x + 64 位十六进制）",
                )
            })?;

        // 只接受 ed25519：带其它方案前缀的直接拒绝，避免静默产出无效交易。
        let hex_part = match raw.split_once(':') {
            Some(("ed25519", rest)) => rest,
            Some((other, _)) => {
                return Err(SdkError::unsupported(format!(
                    "SUI 两段式流程目前只支持 ed25519 公钥，收到方案 {other}"
                )))
            }
            // 裸十六进制默认 ed25519，与 `derive_address` 的约定保持一致。
            None => raw,
        };
        let bytes = hexutil::decode_hex(hex_part)
            .map_err(|e| SdkError::invalid_argument(format!("非法 SUI 公钥: {e}")))?;
        let public_key = crate::tx::validate_public_key(&bytes)?;

        // 地址一致性：用同一套派生规则反算地址，逐字节比对。
        let derived = address_from_pubkey_bytes(&public_key);
        if derived != sender.to_string() {
            return Err(SdkError::invalid_argument(format!(
                "公钥与付款地址不匹配：公钥派生出 {derived}，而 from 是 {sender}"
            )));
        }
        Ok(public_key)
    }
}

/// Sui 地址 = blake2b-256(scheme_flag || 公钥字节)。
///
/// 输入格式有两种：
/// - `ed25519:hex` / `secp256k1:hex` / `secp256r1:hex` —— 带签名方案前缀；
/// - 裸十六进制 —— **默认按 ed25519**（32 字节）处理。
///
/// flag 取值：ed25519 = `0x00`、secp256k1 = `0x01`、secp256r1 = `0x02`。
/// 这 1 字节先于公钥参与哈希，所以**同一把公钥字节在不同方案下会派生出不同地址**，
/// 这也是为什么必须让调用方明确指定方案。
///
/// 产出的地址是**完整 32 字节**的 `0x` + 64 位十六进制（共 66 字符）。
/// 注意这里**不做**任何截断或补零：blake2b 输出恒为 32 字节，长度天然固定。
/// 若上游返回的地址被省略了前导零（不足 64 位），本函数**不会**帮你补齐——
/// 那类地址请在传入前自行规范化。
fn derive_address(pubkey: &str, network: &str) -> Result<AddressView, SdkError> {
    // 语法说明：这是对**元组**做模式匹配并一次性解构出四个值。
    // 用 `match` 而不是 if-else，是因为要区分「有没有冒号」两种结构。
    let (scheme, flag, expected_len, hex_part) = match pubkey.split_once(':') {
        Some((scheme, rest)) => {
            // 内层 match 也是**表达式**，直接产出元组 `(flag, 期望长度)`。
            let (flag, len) = match scheme {
                "ed25519" => (0x00u8, 32),
                // secp256k1 / secp256r1 用**压缩**公钥，故是 33 字节（不是 65）。
                "secp256k1" => (0x01u8, 33),
                "secp256r1" => (0x02u8, 33),
                // 未知方案直接返回错误：`other` 绑定方案名用于回显。
                other => {
                    return Err(SdkError::invalid_argument(format!(
                        "未知 SUI 签名方案: {other}（ed25519 / secp256k1 / secp256r1）"
                    )));
                }
            };
            // `scheme.to_string()`：把借来的 `&str` 复制成自有 `String`，
            // 因为返回值要把它交出去。
            (scheme.to_string(), flag, len, rest)
        }
        // 裸公钥默认 ed25519（32 字节）。
        None => ("ed25519".to_string(), 0x00u8, 32, pubkey),
    };
    // `hexutil::decode_hex` 允许 `0x` 前缀、大小写不敏感。
    let key_bytes = hexutil::decode_hex(hex_part)?;
    if key_bytes.len() != expected_len {
        return Err(SdkError::invalid_argument(format!(
            "{scheme} 公钥应为 {expected_len} 字节，实际 {} 字节",
            key_bytes.len()
        )));
    }
    // 建一个输出长度为 32 字节的 BLAKE2b。
    // `expect` 而非 `?`：32 在合法范围 1..=64 内，失败只可能是程序员错误。
    // Sui 地址 = blake2b-256(flag ‖ 公钥)，抽成共享函数供种子派生路径复用。
    let digest = address_hash(flag, &key_bytes);
    Ok(AddressView::new(
        ChainKind::Sui,
        network,
        // `pubkey` 字段回显的是**原始公钥字节**（不含 flag），
        // 便于调用方核对输入是否被正确解析。
        hexutil::encode_hex_prefixed(&key_bytes),
        // 地址 = 整个 32 字节摘要，带 `0x` 前缀，恒为 66 字符。
        hexutil::encode_hex_prefixed(&digest),
        format!("{scheme}-blake2b"),
        key_bytes.len(),
    )
    .with_extra(json!({
        "scheme": scheme,
        // `format!("0x{flag:02x}")`：格式化微语言——`02` 表示宽度 2 左补零，
        // `x` 表示小写十六进制。于是 0 输出成 `0x00` 而不是 `0x0`。
        "flag": format!("0x{flag:02x}"),
        "derivation": "blake2b256(flag || pubkey)",
    })))
}

/// Sui 地址 = blake2b-256(flag ‖ 公钥)，输出恒为 32 字节。
///
/// `derive_address` 与种子派生路径共用，保证「同一公钥字节 + 同一方案」在任何入口
/// 都派生出同一个地址。
fn address_hash(flag: u8, pubkey: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32 字节输出合法");
    // `&[flag]` 是单元素数组的借用，`&[u8; 1]` 自动解引用成 `&[u8]`。
    hasher.update(&[flag]);
    hasher.update(pubkey);
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .expect("输出缓冲 32 字节");
    digest
}

/// 由 ed25519 公钥字节直接派生 Sui 地址字符串（`0x` + 64hex）。
///
/// 与 `derive_address` 一致，默认按 ed25519（flag = `0x00`）。
fn address_from_pubkey_bytes(pubkey: &[u8]) -> String {
    let digest = address_hash(0x00, pubkey);
    hexutil::encode_hex_prefixed(&digest)
}

/// 转账用：`TransferRequest.private_key` 是 `0x` + 64hex 的 32 字节种子。
fn parse_seed(s: &str) -> Result<[u8; 32], SdkError> {
    let b = hexutil::decode_hex(s.trim())
        .map_err(|e| SdkError::invalid_argument(format!("私钥格式非法: {e}")))?;
    if b.len() != 32 {
        return Err(SdkError::invalid_argument(format!(
            "私钥种子须为 32 字节，实际 {} 字节",
            b.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

/// 转账用：人类可读 SUI 金额（如 `"0.01"`）→ 整数 MIST（精度 9），避免浮点误差。
fn parse_sui_mist(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    let int_mist: u128 = int_part
        .parse::<u128>()
        .map_err(|e| format!("整数部分非法: {e}"))?
        .checked_mul(1_000_000_000)
        .ok_or("金额溢出")?;
    let frac: u128 = if frac_part.is_empty() {
        0
    } else {
        if frac_part.len() > 9 {
            return Err("小数精度超过 9 位".into());
        }
        let f = frac_part
            .parse::<u128>()
            .map_err(|e| format!("小数部分非法: {e}"))?;
        f.checked_mul(10u128.pow((9 - frac_part.len()) as u32))
            .ok_or("金额溢出")?
    };
    int_mist
        .checked_add(frac)
        .ok_or("金额溢出")?
        .try_into()
        .map_err(|_| "金额超过 u64 上限".into())
}

/// 转账用：选出的一条 SUI coin（来自 GraphQL `address.coins`）。
///
/// 字段设为 `pub(crate)`：`tx` 模块的无私钥流程也要读它们来拼对象引用。
/// 类型本身也要 `pub(crate)`：Rust 要求**类型至少和用到它的函数一样可见**，
/// 否则 `pub(crate) fn fetch_sui_coins() -> Vec<SuiCoin>` 会触发
/// `private_interfaces` 告警（`tx` 模块也用得到它）。
/// 不用 `pub`，是因为它属于内部数据形状，不该成为对外契约的一部分。
pub(crate) struct SuiCoin {
    pub(crate) object_id: String,
    pub(crate) balance: u128,
    pub(crate) digest: String,
    pub(crate) version: u64,
}

/// 严格校验 Sui 地址：必须是 `0x` + **恰好 64 位**十六进制。
///
/// 为什么要「恰好 64 位」而不是「不超过 64 位」：
/// Sui 官方规范允许在 JSON 里省略前导零（写成 `0x1234`），
/// 但本 SDK 选择**要求规范化形式**，理由有二：
/// 1. GraphQL 是按字符串精确匹配的，长度不齐会直接查不到；
/// 2. 统一口径后，同一账户在所有响应里的地址字符串完全一致，便于调用方做键。
///
/// 语法说明：`strip_prefix("0x")` 返回 `Option<&str>`。
/// 这里**不接受** `0X` 大写前缀——与本 SDK 其它地方的宽松策略不同，
/// 是刻意收紧：地址要原样拼进查询文本，宁可严格。
fn validate_address(raw: &str) -> Result<(), SdkError> {
    let body = raw
        .trim()
        .strip_prefix("0x")
        .ok_or_else(|| SdkError::invalid_argument(format!("SUI 地址需以 0x 开头: {raw}")))?;
    if body.len() != 64 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SdkError::invalid_argument(format!("非法 SUI 地址: {raw}")));
    }
    Ok(())
}

/// 校验 Sui 交易 digest（base58 编码的 32 字节）。
///
/// 两个判断都有讲究：
/// - 长度 32..=64：base58 编码 32 字节通常得 43~44 字符，放宽区间是为了
///   兼容不同实现的表示差异，同时仍能挡住明显不对的输入；
/// - **排除** `0` `O` `I` `l` 四个字符：这是 base58 相对 base64 的核心特征
///   （剔除易混淆字符）。真的 Sui digest 绝不会含它们，含了就说明用户
///   传错了（常见情况是把别的链的 txid 传了进来）。
fn validate_digest(raw: &str) -> Result<(), SdkError> {
    let t = raw.trim();
    // Sui digest 为 base58 的 32 字节，通常 43/44 字符。
    //
    // 语法说明：`(32..=64).contains(&t.len())` 里取的是 `&usize`——
    // `RangeInclusive::contains` 的签名接受引用，写成 `contains(t.len())` 会编译失败。
    if !(32..=64).contains(&t.len())
        || t.chars()
            // `.any(闭包)`：任一字符满足条件即为真（短路）。
            .any(|c| !c.is_ascii_alphanumeric() || matches!(c, '0' | 'O' | 'I' | 'l'))
    {
        return Err(SdkError::invalid_argument(format!(
            "非法 SUI 交易 digest: {raw}"
        )));
    }
    Ok(())
}

/// 宽松解析 u128：优先按十进制字符串，失败再退回 [`loose_u128`]。
///
/// Sui GraphQL 把大整数几乎都返回成字符串（避免 JS 精度问题），
/// 但少量字段仍是 JSON number，所以保留兜底路径。
///
/// 语法说明：`.or_else(闭包)` 惰性求值——成功路径上不会白跑一次 `loose_u128`。
fn loose_str_u128(v: &Value) -> Option<u128> {
    v.as_str()
        .and_then(|s| s.parse::<u128>().ok())
        // `.ok()` 把 `Result` 折成 `Option`：本函数只回答「能不能解析出来」，不解释原因。
        .or_else(|| loose_u128(v).ok())
}

/// 把 `rfc3339_to_unix` 的 `Result` 适配成 `Option`，以便直接传给 `and_then`。
///
/// 语法说明：这是把「函数签名」改成「组合子能用的形态」的胶水函数。
/// `and_then` 需要 `FnOnce(T) -> Option<U>`，而 `rfc3339_to_unix` 返回 `Result`，
/// 于是包一层丢掉错误。时间解析失败在本 SDK 里一律按「该字段留空」处理。
fn rfc3339_ok(s: &str) -> Option<i64> {
    rfc3339_to_unix(s).ok()
}

/// 单元测试模块：只测纯函数，网络行为靠集成测试或手工验证。
#[cfg(test)]
mod tests {
    use super::*;

    /// 地址与 digest 校验的正反用例，含 base58 易混淆字符的专项检查。
    #[test]
    fn validates_addresses_and_digests() {
        // `"ab".repeat(32)` = 64 个十六进制字符，是合法的规范化地址。
        assert!(validate_address(&format!("0x{}", "ab".repeat(32))).is_ok());
        assert!(validate_address("0x123").is_err());
        // 44 字符的真实 base58 digest。
        assert!(validate_digest("6LRkL8ez2KVq2m3QuwE46DKetS7xuxwwHndLwK1h6cuV").is_ok());
        assert!(validate_digest("has space").is_err());
        // 含 base58 禁用字符 `0OIl`。
        assert!(validate_digest("0OIl").is_err());
    }

    /// 带前缀与裸公钥两种写法必须派生出**同一个**地址。
    #[test]
    fn derives_ed25519_address_stably() {
        let pk = "01".repeat(32);
        let v1 = derive_address(&pk, "mainnet").unwrap();
        let v2 = derive_address(&format!("ed25519:{pk}"), "mainnet").unwrap();
        assert_eq!(v1.address, v2.address);
        // 66 = `0x`(2) + 64 位十六进制。
        assert_eq!(v1.address.len(), 66);
        assert_eq!(v1.address_type, "ed25519-blake2b");
    }

    /// 未知方案、长度不符必须被拒；33 字节的 secp256k1 压缩公钥必须被接受。
    #[test]
    fn rejects_unknown_scheme_and_bad_length() {
        assert!(derive_address("rsa:abcd", "mainnet").is_err());
        // 31 字节：既不是 ed25519 的 32 也不是 secp 的 33。
        assert!(derive_address(&"ab".repeat(31), "mainnet").is_err());
        let secp = "02".repeat(33);
        assert!(derive_address(&format!("secp256k1:{secp}"), "mainnet").is_ok());
    }

    /// 字符串形态的数字要能被解析成 u128。
    #[test]
    fn loose_helpers_accept_strings() {
        assert_eq!(loose_str_u128(&json!("1000000000")).unwrap(), 1_000_000_000);
    }

    /// 转账金额解析：人类可读 SUI → 整数 MIST（精度 9），无浮点误差。
    #[test]
    fn parses_sui_amount_to_mist() {
        assert_eq!(parse_sui_mist("0.01").unwrap(), 10_000_000);
        assert_eq!(parse_sui_mist("1").unwrap(), 1_000_000_000);
        assert_eq!(parse_sui_mist("1.5").unwrap(), 1_500_000_000);
        assert_eq!(parse_sui_mist("0.000000001").unwrap(), 1);
        assert_eq!(parse_sui_mist("123.456789012").unwrap(), 123_456_789_012);
        // 超过 9 位小数、整体溢出都必须被拒。
        assert!(parse_sui_mist("0.0000000001").is_err());
        assert!(parse_sui_mist("not-a-number").is_err());
    }

    /// 由 ed25519 公钥字节派生地址：长度、前缀、确定性都正确。
    #[test]
    fn derives_address_from_pubkey_bytes() {
        let pk = hexutil::decode_hex(&"01".repeat(32)).unwrap();
        let a1 = address_from_pubkey_bytes(&pk);
        let a2 = address_from_pubkey_bytes(&pk);
        assert_eq!(a1, a2, "同一公钥必须派生同一地址");
        assert!(a1.starts_with("0x"));
        assert_eq!(a1.len(), 66, "0x + 64 位十六进制");
    }

    /// 离线验证：构造一笔 SUI 转账交易（PTB）、本地签名，签名能被派生公钥验过，
    /// 且 UserSignature 封装能原样解回 flag ‖ sig ‖ pubkey。无需任何 RPC。
    ///
    /// **本测试刻意复用 `crate::tx` 的构造与摘要函数**，而不是在这里重写一遍：
    /// 早先版本在这里内联了「intent ‖ bcs(tx) → 直接签名」的写法，
    /// 结果把「漏掉 blake2b-256」这个缺陷**固化成了断言**——
    /// 实现错了，测试却是绿的。共用同一份实现才能杜绝这种情形。
    #[test]
    fn transfer_tx_signs_and_verifies_offline() {
        use ed25519_dalek::Verifier;
        // 1) 种子 → 密钥对（与 transfer 运行时一致）。
        let seed = [7u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk = VerifyingKey::from(&sk);
        let from_hex = address_from_pubkey_bytes(&vk.to_bytes());
        let sender = Address::from_str(&from_hex).unwrap();
        // 收款地址（规范化 0x + 64hex）→ 32 字节 Pure 输入。
        let receiver = Address::from_str(&format!("0x{}", "02".repeat(32))).unwrap();
        let amount: u64 = 10_000_000;

        // 2) 用一个确定性 digest 造一个对象引用（仅用于离线构造，不接触链）。
        let coin_ref = ObjectReference::new(sender, 0, Digest::from_bytes([0u8; 32]).unwrap());
        // 3) 构造 PTB —— 走 tx 模块，与运行时和两段式流程共用同一份实现。
        let tx = crate::tx::build_transaction(&crate::tx::TransferParams {
            sender,
            public_key: vk.to_bytes(),
            receiver,
            amount,
            coin: coin_ref,
            gas_price: 1000,
            gas_budget: DEFAULT_GAS_BUDGET,
        })
        .unwrap();

        // 4) 本地签名：签的是 **blake2b-256 摘要**，不是 intent 消息原文。
        let digest = crate::tx::signing_digest(&tx).unwrap();
        assert_eq!(digest.len(), 32, "待签对象应是 32 字节摘要");
        let sig = sk.sign(&digest);
        let mut full = vec![SignatureScheme::Ed25519 as u8];
        full.extend_from_slice(&sig.to_bytes());
        full.extend_from_slice(&vk.to_bytes());

        // 5) 验签：派生公钥必须认可「对摘要的签名」。
        assert!(
            vk.verify(&digest, &sig).is_ok(),
            "种子重建的密钥对签名验签失败"
        );
        // 6) UserSignature 封装可原样解回。
        let user_sig = UserSignature::from_bytes(&full).unwrap();
        let back = user_sig.to_bytes();
        assert_eq!(back.as_slice(), full.as_slice(), "UserSignature 往返不一致");
    }

    /// 查询文本必须匹配**现行** Sui GraphQL schema（2026-09 对 mainnet 端点实测）。
    ///
    /// 这条测试的存在理由：旧版 `address { coins(...) }` 会被线上端点整条拒掉
    /// （`GRAPHQL_VALIDATION_FAILED`），而这类错误只有真发请求才会暴露——
    /// 单元测试里没有网络，靠这条文本断言兜住。
    #[test]
    fn coins_query_matches_the_current_sui_schema() {
        let q = coins_query("0xabc");

        // 1) 走 objects + filter，而不是已下线的 coins 字段。
        assert!(
            q.contains("objects(first: 50, filter: { type: \"0x2::coin::Coin<0x2::sui::SUI>\" })"),
            "必须按 coin **对象**类型过滤；旧的 coins(type:) 已被 schema 移除。实际: {q}"
        );
        assert!(
            !q.contains("coins("),
            "Address 已无 coins 字段，留着会让整条查询被拒。实际: {q}"
        );

        // 2) 面值只能从 contents.json 取。
        //
        // 反向钉住旧写法：只断言「包含新写法」是不够的——若有人把
        // `balance { totalBalance }` 一起加回来，新断言照样通过，
        // 而解析路径可能又指回那个恒为 0 的字段。
        assert!(
            q.contains("contents { json }"),
            "coin 面值在 Move 结构里，必须读 contents.json。实际: {q}"
        );
        assert!(
            !q.contains("totalBalance"),
            "MoveObject.balance 对 coin 对象恒为 0，读它会导致选币误判余额不足。实际: {q}"
        );

        // 3) 对象引用三元组缺一不可（Sui 对象模型要求 id + version + digest）。
        for field in ["address", "version", "digest"] {
            assert!(q.contains(field), "查询缺对象引用字段 {field}。实际: {q}");
        }
    }

    /// 线上抓回的真实 `objects` 响应（2026-09-02，`graphql.mainnet.sui.io`）。
    ///
    /// 地址 `0x0feb54a7…`（总余额 58,569,188,076,346 MIST）的前 3 个 SUI coin。
    /// 三个面值各不相同，所以「读错字段」不会恰好撞对——这是选它当夹具的原因。
    const REAL_COINS_RESPONSE: &str = r#"{
      "address": { "objects": { "nodes": [
        { "address": "0x697a8e3343a521d1e0f5ea9b67360fcafc32504cb0813d27b41048f9f4e1bd92",
          "version": 986735984,
          "digest": "GQV5XZyUef1tRRnFSKZDhxvPEVV8zFY52a4bPdGThLGB",
          "contents": { "json": {
            "id": "0x697a8e3343a521d1e0f5ea9b67360fcafc32504cb0813d27b41048f9f4e1bd92",
            "balance": "4049752227351" } } },
        { "address": "0x62ac4e1870f2a08eb753922b13797a7004e1850405e15439f641fbaf5a21f6e1",
          "version": 986736151,
          "digest": "HZ77xm1PirJEsf4RMHgJWWtd6zW66R2wqRGFqZNfeRG6",
          "contents": { "json": {
            "id": "0x62ac4e1870f2a08eb753922b13797a7004e1850405e15439f641fbaf5a21f6e1",
            "balance": "14633341382" } } },
        { "address": "0x20fef4ce023beccec110991d0c0ee460fb82514d4afa68d804af17264f842533",
          "version": 986736199,
          "digest": "9eouAVVtz3L7RYhXQF13zvJwi5EPGG2ea4mz27Cp9Eeu",
          "contents": { "json": {
            "id": "0x20fef4ce023beccec110991d0c0ee460fb82514d4afa68d804af17264f842533",
            "balance": "7985301260" } } }
      ] } }
    }"#;

    /// 用真实响应验证解析：面值必须读到真数，而不是 0。
    ///
    /// # 为什么必须断言「非 0」
    ///
    /// 若把面值错读成 `balance.totalBalance`，解析**照样成功**、只是全为 0，
    /// 所有「字段存在」类的断言都会通过。只有钉住真实数值才能挡住这个坑。
    #[test]
    fn parses_real_coin_balances_from_contents_json() {
        let data: Value = serde_json::from_str(REAL_COINS_RESPONSE).expect("夹具应是合法 JSON");
        let nodes = data
            .pointer("/address/objects/nodes")
            .and_then(|v| v.as_array())
            .expect("夹具应含 objects.nodes");

        let coins = parse_sui_coins(nodes).expect("真实响应应能解析");
        assert_eq!(coins.len(), 3, "夹具里有 3 个 coin");

        assert_eq!(coins[0].balance, 4_049_752_227_351, "第一个 coin 的面值");
        assert_eq!(coins[1].balance, 14_633_341_382, "第二个 coin 的面值");
        assert_eq!(coins[2].balance, 7_985_301_260, "第三个 coin 的面值");
        assert!(
            coins.iter().all(|c| c.balance > 0),
            "真实 coin 面值都应大于 0；出现 0 说明读错了字段"
        );

        // 对象引用三元组：Sui 要求 id + version + digest 齐全且精确。
        assert_eq!(
            coins[0].object_id,
            "0x697a8e3343a521d1e0f5ea9b67360fcafc32504cb0813d27b41048f9f4e1bd92"
        );
        assert_eq!(coins[0].version, 986_735_984, "version 是 JSON 数字，需按数字解析");
        assert_eq!(coins[0].digest, "GQV5XZyUef1tRRnFSKZDhxvPEVV8zFY52a4bPdGThLGB");
    }

    /// 反向反证：只有 `balance.totalBalance` 而没有 `contents` 的节点必须**报错**。
    ///
    /// 没有这条，实现者可能「贴心地」加一条回落：读不到 contents 就退回
    /// `balance.totalBalance`——那正是恒为 0 的字段，于是选币永远判余额不足。
    /// 宁可报错，也不要悄悄给个错的。
    #[test]
    fn rejects_a_coin_node_without_contents_json() {
        let data: Value = serde_json::from_str(
            r#"{"address":{"objects":{"nodes":[{"address":"0xabc","version":7,
                 "digest":"DIGEST","balance":{"totalBalance":"0"}}]}}}"#,
        )
        .expect("夹具应是合法 JSON");
        let nodes = data
            .pointer("/address/objects/nodes")
            .and_then(|v| v.as_array())
            .expect("夹具应含 nodes");

        assert!(
            parse_sui_coins(nodes).is_err(),
            "缺 contents.json 的节点必须报错；静默回落到 totalBalance(=0) 会导致选币误判"
        );
    }

    #[test]
    fn broadcast_query_matches_sui_0_0_7_schema() {
        let q = broadcast_query("TX", &["SIG1".to_string(), "SIG2".to_string()]);
        assert!(
            q.contains("executeTransactionBlock(txBytes: \"TX\", signatures: [\"SIG1\", \"SIG2\"])"),
            "executeTransactionBlock 仅接受 txBytes + signatures"
        );
        assert!(
            !q.contains("requestType"),
            "0.0.7 schema 的 executeTransactionBlock 无 requestType 参数"
        );
        assert!(
            q.contains("effects { transactionBlock { digest } status }"),
            "digest 在 effects.transactionBlock.digest，执行状态是枚举 status"
        );
    }
}
