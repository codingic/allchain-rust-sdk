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
//! 本适配器**只提供只读查询 + 本地地址派生**，不实现 `transfer`。

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
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, ErrorCode, SdkError, StatusView,
    TxStatus, TxView, hexutil,
};
// 共用工具层：HTTP 客户端 + 宽松数值解析 + RFC3339 时间解析。
use chain_rpcutil::{Http, loose_u64, loose_u128, rfc3339_to_unix};

use crate::network;

/// SUI 的 coin type 标识。
///
/// `0x2` 是 Sui 框架包的固定地址，`sui::SUI` 是其中的原生币类型。
/// 查余额时**必须**指定它，否则拿到的是其它 token 的余额
/// （甚至可能是空结果，而不是报错——这是 Sui GraphQL 的一个易踩的坑）。
const SUI_COIN_TYPE: &str = "0x2::sui::SUI";

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
    // 语法说明：这里**没有** `transfer` 方法，走 `ChainClient` 的默认实现返回 `UNSUPPORTED`。
    // trait 默认方法让「新链接入」只需实现真正支持的能力。
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
    let mut hasher = Blake2bVar::new(32).expect("32 字节输出合法");
    // 语法说明：`&[flag]` 是**单元素数组的借用**，`&[u8; 1]` 会自动
    // 解引用强制转换成 `&[u8]`，正好匹配 `update` 的参数类型。
    hasher.update(&[flag]);
    hasher.update(&key_bytes);
    // 语法说明：`[0u8; 32]` 是**定长数组**（类型里带长度，存在栈上），
    // 与 `Vec<u8>`（堆上、长度可变）是两种不同的类型。
    // `finalize_variable` 接受 `&mut [u8]`，数组可自动借成切片。
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .expect("输出缓冲 32 字节");
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
}
