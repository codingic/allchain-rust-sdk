//! Nervos CKB 链对统一 `ChainClient` 契约的实现（JSON-RPC）。
//!
//! 上游的坑（对照代码理解）：
//! - CKB 的 JSON-RPC 里所有数字都是 **`0x` 前缀的十六进制字符串**，
//!   没有一处是 JSON number，所以处处要 `from_str_radix(.., 16)`；
//! - 区块/交易时间戳单位是**毫秒**，而统一 View 用秒，需除以 1000；
//! - `get_transaction` 对不存在的交易返回 `result: null`（不是 error），
//!   必须显式判 `is_null()`；
//! - `tx_status.status` 只有 `committed` / `proposed` / `pending` 三态，
//!   没有「失败」态——CKB 的交易若脚本执行失败，根本进不了区块；
//! - `get_cells` 是**游标分页**的，且默认只返回有限条，
//!   因此余额必须翻页累加（见 `sum_capacity`）。

use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::{Value, json};

use allchain_core::{
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, ErrorCode, SdkError, StatusView,
    TransferRequest, TransferView, TxStatus, TxView, hexutil, parse_units,
};
use chain_rpcutil::{Http, loose_u64, loose_u128};

// 原生转账依赖的官方 ckb-sdk（在 Cargo.toml 里已重命名为 `official-ckb-sdk`，
// 以避免与本 crate 的 `[lib] name = "ckb_sdk"` 撞车）。
use ckb_jsonrpc_types::{OutputsValidator, TransactionView as JsonTransactionView};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView as CoreBlockView, ScriptHashType},
    packed::{CellOutput, Script, WitnessArgs},
    prelude::*,
};
use official_ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::CkbRpcClient,
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner, Signer,
    },
    tx_builder::{transfer::CapacityTransferBuilder, CapacityBalancer, TxBuilder},
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
    Address, ScriptId, SECP256K1,
};
use secp256k1::{PublicKey, SecretKey};

// `use crate::address::{self, LockScript}`：`self` 表示「模块本身也一起导入」，
// 于是既能写 `address::encode_address(..)`，又能直接写 `LockScript`。
// 若不写 `self`，就只能写前者，用 `LockScript` 时得写 `address::LockScript`。
use crate::address::{self, LockScript};
use crate::network::{self, NetworkArg};

// JSON-RPC 的 limit 参数同样是十六进制字符串；0x64 = 100。
const PAGE_LIMIT: &str = "0x64"; // 每页 100 个 live cell

/// CKB 客户端：绑定一个 JSON-RPC 端点 + 一个 reqwest 连接池。
///
/// 字段比其它链多一个 `is_mainnet`：因为 CKB 的地址编码（bech32 hrp）
/// 随网络而变，而「派生地址」是纯本地计算、拿不到 hrp 本身，
/// 所以构造时就把它缓存下来（见 `address_from_pubkey`）。
pub struct CkbClient {
    /// 网络名；使用自定义端点时为 `"custom"`。
    network: String,
    /// 实际 JSON-RPC 端点，回显给调用方确认「打的是不是预期节点」。
    rpc_url: String,
    /// 是否主网。决定派生地址时用 `ckb` 还是 `ckt` 作 hrp。
    is_mainnet: bool,
    /// 共享 HTTP 客户端（内部 `Arc`，克隆廉价）。
    http: Http,
}

impl CkbClient {
    /// 构造客户端：`rpc_url` 优先，否则按 `network` 取预置端点（缺省主网）。
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        // trim → 过滤空串 → 转成 `String`（取得所有权，不再依赖调用方的临时借用）。
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        // 三元组的第一个 match：两个分支都返回 `(String, String, bool)`。
        let (network_name, url, is_mainnet) = match custom {
            // 自定义端点时**无法**从 URL 判断网络，保守地按主网处理
            // （hrp 用 `ckb`）。调用方若连的是测试网自建节点，
            // 派生出的地址 hrp 会不对，这是当前实现的已知局限。
            Some(url) => ("custom".to_string(), url, true),
            None => {
                let net = network::parse(network)?;
                (
                    net.as_str().to_string(),
                    net.rpc_url().to_string(),
                    // `net == NetworkArg::Mainnet`：这里靠 `PartialEq` 比较，
                    // 而 `NetworkArg` 派生了它。若要更地道可以写 `matches!(..)`，
                    // 但 `==` 对两个变体的枚举更直白。
                    net == NetworkArg::Mainnet,
                )
            }
        };
        let http = Http::new(&url)?;
        Ok(Self {
            network: network_name,
            rpc_url: url,
            is_mainnet,
            http,
        })
    }

    /// 分页汇总锁脚本下全部 live cell 的 capacity。
    ///
    /// 领域说明：这是 CKB 与账户模型链**最根本的差异**——
    /// 没有「余额」这个存储项，余额 = 属于该 lock script 的所有未花费 cell 的
    /// capacity 之和。而 `get_cells` 一次最多返回 limit 条，
    /// 所以余额查询天然是「翻页 + 累加」，cell 多的账户甚至要几十次请求。
    ///
    /// 注意 capacity 的单位是 **shannon**，与统一 View 的 `balance_raw` 一致，无需换算。
    async fn sum_capacity(&self, script: &LockScript) -> Result<u128, SdkError> {
        // `get_cells` 的 search_key：按 lock script 精确匹配。
        //
        // `json!` 宏里每个值都要是能转成 `Value` 的表达式，
        // 因此 `format!("0x{}", hexutil::encode_hex(..))` 这样的调用可以直接内联。
        let search_key = json!({
            "script": {
                "code_hash": format!("0x{}", hexutil::encode_hex(&script.code_hash)),
                "hash_type": hash_type_str(script.hash_type),
                "args": format!("0x{}", hexutil::encode_hex(&script.args)),
            },
            "script_type": "lock",
            // `exact` 表示按完整 script 匹配；若用 `prefix` 则会把 args 前缀相同的
            // （比如多签的）也算进来，余额就会算多。
            "script_search_mode": "exact",
        });
        // 游标：JSON-RPC 要求传 `null` 表示「从头开始」，故初值是 `Value::Null`。
        let mut cursor: Value = Value::Null;
        let mut total = 0u128;
        let mut pages = 0u32;
        // 翻页循环的四个要素：发请求 → 累加 → 取下一个游标 → 判断是否结束。
        loop {
            // 参数顺序：[search_key, order, limit, cursor]，`desc` 表示从新到旧。
            let page = self
                .http
                .jsonrpc("get_cells", json!([search_key, "desc", PAGE_LIMIT, cursor]))
                .await?;
            // `objects` 是本页的 cell 列表，每个元素形如
            // `{ "output": { "capacity": "0x...", "lock": {...} }, "out_point": {...} }`。
            let objects = page.get("objects").and_then(Value::as_array);
            if let Some(objs) = objects {
                for obj in objs {
                    // `Value::pointer("/output/capacity")` 是 **JSON Pointer** 语法：
                    // 用 `/` 分隔的路径一次性下钻多层，等价于
                    // `obj.get("output").and_then(|o| o.get("capacity"))`。
                    // 路径里任一层缺失就返回 `None`，非常省事。
                    if let Some(cap) = obj.pointer("/output/capacity") {
                        // `saturating_add`：cell 数量理论上是天文数字，
                        // 用饱和加法保证即使溢出也只是停在 `u128::MAX` 而不 panic。
                        total = total.saturating_add(loose_u128(cap)?);
                    }
                }
            }
            // 服务端用空游标 `"0x"` 表示「没有下一页了」。
            let next = page
                .get("last_cursor")
                .and_then(Value::as_str)
                .unwrap_or("0x");
            // 空游标表示遍历结束。
            //
            // `objects.is_none_or(|o| o.is_empty())`：
            // `is_none_or` 是 `Option` 上的组合子，语义是
            // 「`None` 时为 true，`Some(v)` 时看 `predicate(v)`」。
            // 于是这一句同时覆盖了「字段缺失」与「本页是空数组」两种情况。
            if next == "0x" || objects.is_none_or(|o| o.is_empty()) {
                break;
            }
            // `json!(next)` 把 `&str` 包成 `Value::String`，作为下一轮的游标参数。
            cursor = json!(next);
            pages += 1;
            // 熔断：200 页 × 100 条 = 20000 个 cell。正常账户远远达不到；
            // 超过说明要么是巨鲸地址，要么是游标没推进（服务端行为异常）导致死循环。
            // 与其让请求无限打下去，不如明确报错让调用方介入。
            if pages > 200 {
                return Err(SdkError::new(
                    ErrorCode::RpcError,
                    "get_cells 翻页超过 200 页，疑似异常，请缩小查询范围",
                ));
            }
        }
        Ok(total)
    }
}

// trait 实现块：实现之后本类型即可被 `Box<dyn ChainClient>` 持有，
// 上层 acli 因而能在运行期按链名分发，完全不认识 `CkbClient`。
#[async_trait]
impl ChainClient for CkbClient {
    /// 所属链（同步方法，值在编译期就定死了）。
    fn kind(&self) -> ChainKind {
        ChainKind::Ckb
    }

    /// 网络名。`&str` 借用的是 `self` 内部的 `String`，
    /// 生命周期自动绑定为「不比 `self` 活得更久」。
    fn network(&self) -> &str {
        &self.network
    }

    /// 实际 JSON-RPC 端点。
    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        // `get_tip_header`：链头区块头，一次拿到高度（`number`）与哈希（`hash`）。
        // 第二个参数是 JSON-RPC 的 params，空参数也要写成空数组 `[]`。
        let header = self.http.jsonrpc("get_tip_header", json!([])).await?;
        let mut view = StatusView::new(ChainKind::Ckb, &self.network, &self.rpc_url);
        // `and_then(|v| loose_u64(v).ok())` 与直接 `.and_then(loose_u64_opt)` 等价
        // （apt 适配器里就是抽了个 `loose_u64_opt` 函数）。
        // 这里用闭包内联，是因为本文件只有两三处需要，不值得抽函数。
        if let Some(n) = header.get("number").and_then(|v| loose_u64(v).ok()) {
            view = view.with_height(n);
        }
        if let Some(h) = header.get("hash").and_then(Value::as_str) {
            view = view.with_hash(h);
        }
        Ok(view.with_extra(json!({
            // CKB 的 epoch 形如 `0x7080291000045`，高位是编号、低位是进度百分比，
            // 不是简单的自增整数，因此按原样透出不做解析。
            "epoch": header.get("epoch").cloned().unwrap_or(Value::Null),
            "parent_hash": header.get("parent_hash").cloned().unwrap_or(Value::Null),
            // DAO 相关字段，CKB 特有的二级发行机制状态。
            "dao": header.get("dao").cloned().unwrap_or(Value::Null),
            // 字段名带 `_ms` 后缀，明确提示这是**毫秒**，
            // 与统一 View 里已换算成秒的 `timestamp` 区分开。
            "timestamp_ms": header.get("timestamp").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        // 两步走：先把地址解成 lock script，再累加该 script 名下所有 live cell。
        //
        // `let (script, _) = ..`：第二个返回值 `is_mainnet` 这里用不上，
        // 用 `_` 通配符丢弃。注意 `_` 是**模式**而非变量名，
        // 不会触发「未使用变量」警告，也不会取得所有权。
        let (script, _) = address::decode_address(address)?;
        let raw = self.sum_capacity(&script).await?;
        Ok(
            BalanceView::new(ChainKind::Ckb, &self.network, address, raw).with_extra(json!({
                // 把 lock script 回显出来：调用方能据此核对「解出来的 script
                // 是不是我想要的那个」，也能拿去做 further 查询。
                "lock_code_hash": format!("0x{}", hexutil::encode_hex(&script.code_hash)),
                "lock_hash_type": hash_type_str(script.hash_type),
            })),
        )
    }


    /// 查询交易。
    /// 链头高度：最新区块高度（裸 `u64`）。
    async fn last_block_height(&self) -> Result<u64, SdkError> {
        let tip = self.http.jsonrpc("get_tip_header", json!([])).await?;
        loose_u64(tip.get("number").ok_or_else(|| {
            SdkError::new(ErrorCode::ParseError, "tip header 缺少 number")
        })?)
    }

    /// 按高度查询区块（CKB 的 `get_block` 只接受哈希，故先按高度换哈希）。
    async fn block_by_height(&self, height: u64) -> Result<BlockView, SdkError> {
        let number = normalize_number(&height.to_string())?;
        let hash = self.http.jsonrpc("get_block_hash", json!([number])).await?;
        let hash = hash.as_str().ok_or_else(|| {
            SdkError::new(ErrorCode::ParseError, "get_block_hash 未返回哈希")
        })?;
        let block = self.http.jsonrpc("get_block", json!([hash])).await?;
        let header = block.get("header").ok_or_else(|| {
            SdkError::new(ErrorCode::ParseError, format!("区块缺少 header: {block}"))
        })?;
        let hash_v = header
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, "header 缺少 hash"))?
            .to_string();
        let mut view = BlockView::new(ChainKind::Ckb, &self.network, hash_v);
        if let Some(n) = header.get("number").and_then(|v| loose_u64(v).ok()) {
            view = view.with_height(n);
        }
        if let Some(ts_hex) = header.get("timestamp").and_then(Value::as_str)
            && let Ok(ms) = u64::from_str_radix(ts_hex.trim_start_matches("0x"), 16)
        {
            view = view.with_timestamp((ms / 1000) as i64);
        }
        if let Some(parent) = header.get("parent_hash").and_then(Value::as_str) {
            view = view.with_parent(parent);
        }
        let tx_count = block
            .get("transactions")
            .and_then(Value::as_array)
            .map(|txs| txs.len() as u64)
            .unwrap_or(0);
        let proposal_count = block
            .get("proposals")
            .and_then(Value::as_array)
            .map(|p| p.len() as u64)
            .unwrap_or(0);
        Ok(view.with_tx_count(tx_count).with_extra(json!({
            "proposal_count": proposal_count,
            "uncle_count": block.get("uncles").and_then(Value::as_array).map(|u| u.len()),
            "epoch": header.get("epoch").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        validate_txid(hash)?;
        let result = self
            .http
            .jsonrpc("get_transaction", json!([hash.trim()]))
            .await?;
        // CKB 对不存在的交易返回 `result: null` 而**不是** JSON-RPC error，
        // 所以必须显式判空，否则会一路走到下面的「缺少字段」错误，
        // 给调用方一个误导性的 PARSE_ERROR。
        if result.is_null() {
            return Err(SdkError::not_found(format!("CKB 交易不存在: {hash}")));
        }
        // 响应分两块：`transaction`（交易本体）+ `tx_status`（上链状态）。
        let tx_status = result.get("tx_status").cloned().unwrap_or(Value::Null);
        let status_str = tx_status
            .get("status")
            .and_then(Value::as_str)
            // 缺字段时按空串处理，进而落到下面的 `_` 分支（Pending），
            // 语义上「不知道」比「断定失败」更保守。
            .unwrap_or("");
        // CKB 只有三态，且**没有失败态**：脚本执行失败的交易根本进不了区块，
        // 会一直停在 pending 直到被丢弃。
        let status = match status_str {
            "committed" => TxStatus::Success,
            "proposed" => TxStatus::Pending,
            _ => TxStatus::Pending,
        };
        let transaction = result.get("transaction").ok_or_else(|| {
            SdkError::new(
                ErrorCode::ParseError,
                format!("交易缺少 transaction: {result}"),
            )
        })?;

        let mut view = TxView::new(ChainKind::Ckb, &self.network, hash.trim(), status);
        // `block_number` 在 `tx_status` 里，不在 `transaction` 里——
        // 这是 CKB JSON-RPC 的一个常见绊脚石。
        if let Some(n) = tx_status
            .get("block_number")
            .and_then(|v| loose_u64(v).ok())
        {
            view = view.with_height(n);
        }
        // `fee` 是节点算好的手续费（单位 shannon），同样是十六进制字符串。
        if let Some(fee_hex) = result.get("fee").and_then(Value::as_str)
            && let Ok(fee) = u128::from_str_radix(fee_hex.trim_start_matches("0x"), 16)
        {
            view = view.with_fee(fee);
        }

        // 输入只引用前序 outpoint，无法直接还原地址，记录到 extra。
        //
        // 领域说明：这是 UTXO 模型的固有特性——输入只说「我花的是哪一笔输出」，
        // 即 `(前序交易哈希, 输出下标)` 组成的 **outpoint**，
        // 并不携带地址。要还原付款方地址，必须再查一次那笔前序交易。
        // 本适配器刻意不做这一次（省一次请求、且可能查不到），
        // 于是 `from` 只能留空，把 outpoint 放进 extra 供调用方自行追溯。
        let mut from_outpoint = Value::Null;
        let mut is_cellbase = false;
        if let Some(inputs) = transaction.get("inputs").and_then(Value::as_array)
            // `inputs.first()` 而非 `inputs[0]`：空数组时返回 `None`，不会 panic。
            && let Some(first) = inputs.first()
        {
            from_outpoint = first.get("previous_output").cloned().unwrap_or(Value::Null);
            // cellbase（创币交易，即矿工奖励）的约定：输入的 index 固定是 `0xffffffff`，
            // 表示「没有真正的输入」。这是 CKB 沿用比特币的做法。
            //
            // `.is_some_and(|i| i == "0xffffffff")`：`Option` 的组合子，
            // 等价于 `matches!(opt, Some(i) if i == "0xffffffff")`，语义是
            // 「有值且满足条件」。比 `map(..).unwrap_or(false)` 更直白。
            is_cellbase = from_outpoint
                .get("index")
                .and_then(Value::as_str)
                .is_some_and(|i| i == "0xffffffff");
        }

        // 输出：to 取首个输出锁脚本重新编码出的地址；金额为全部输出 capacity 之和。
        //
        // 两个**重要的语义妥协**，调用方须知：
        // 1. `to` 只取**第一个**输出。CKB 交易常有多个输出，
        //    其余接收方（含找零地址）在统一 View 里体现不出来，只能去读原始响应。
        // 2. 金额是**所有输出 capacity 之和**，包含找零，
        //    因此它不是「转账金额」，而是「这笔交易动用的总容量」。
        //    这与账户模型链的 `amount` 语义不同，是 UTXO 映射的固有限制。
        let mut to_address: Option<String> = None;
        if let Some(outputs) = transaction.get("outputs").and_then(Value::as_array) {
            let mut total = 0u128;
            for out in outputs {
                if let Some(cap) = out.get("capacity").and_then(|v| loose_u128(v).ok()) {
                    total = total.saturating_add(cap);
                }
            }
            view = view.with_amount(total);
            if let Some(first_lock) = outputs.first().and_then(|o| o.get("lock"))
                && let Some(script) = parse_lock_json(first_lock)
            {
                // 把 JSON 里的 lock script 解析成 `LockScript`，再编回地址字符串。
                // 之所以要「解出来再编回去」而不是直接找个地址字段：
                // CKB 的交易输出里**根本没有地址字段**，只有 lock script。
                to_address = Some(address::encode_address(&script, self.is_mainnet));
            }
        }
        if let Some(to) = to_address {
            view = view.with_to(to);
        }

        Ok(view.with_extra(json!({
            "status_detail": status_str,
            "block_hash": tx_status.get("block_hash").cloned().unwrap_or(Value::Null),
            "tx_index": tx_status.get("tx_index").cloned().unwrap_or(Value::Null),
            "cycles": result.get("cycles").cloned().unwrap_or(Value::Null),
            "from_outpoint": from_outpoint,
            "cellbase": is_cellbase,
        })))
    }

    /// 由压缩 secp256k1 公钥派生地址：**纯本地计算**，不访问网络。
    ///
    /// 领域说明（完整的派生链条）：
    ///   33 字节压缩公钥
    ///   → `blake2b(personal="ckb-default-hash")` 取前 20 字节，得 **blake160**
    ///   → 作为 lock script 的 `args`，配上系统 code_hash 与 hash_type=type
    ///   → payload = `0x00 | code_hash(32) | hash_type(1) | args`（扁平拼接，无 molecule）
    ///   → **bech32m** 编码（hrp 主网 `ckb` / 其余 `ckt`），得到 ckb2021 full 地址
    ///
    /// 只支持标准单签。多签锁的 args 是 blake160(multisig 脚本) 且长度不同，
    /// 需要额外的配置参数，当前未实现。
    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        // `hexutil::decode_hex` 允许 `0x` / `0X` 前缀、大小写不敏感。
        let bytes = hexutil::decode_hex(pubkey)?;
        // 必须是**压缩**公钥 33 字节（1 字节奇偶前缀 + 32 字节 x 坐标）。
        if bytes.len() != 33 {
            return Err(SdkError::invalid_argument(format!(
                "CKB 单签公钥需为 33 字节压缩 secp256k1 公钥，实际 {} 字节",
                bytes.len()
            )));
        }
        let blake160 = address::ckb_blake160(&bytes);
        let script = LockScript::sighash_blake160(blake160);
        let address = address::encode_address(&script, self.is_mainnet);
        // 额外再算一份**旧 short 格式**地址，供需要与历史系统对接的调用方使用。
        // 它只作为 `extra.alternatives` 出现，不影响主地址字段。
        let short = address::encode_short_sighash_address(&blake160, self.is_mainnet)?;
        Ok(AddressView::new(
            ChainKind::Ckb,
            &self.network,
            // 回填规范化后的公钥（小写、带 0x），便于调用方核对。
            hexutil::encode_hex_prefixed(&bytes),
            address,
            "secp256k1-blake160-full",
            bytes.len(),
        )
        .with_extra(json!({
            "derivation": "blake160(compressed_pubkey) -> secp256k1_blake160_sighash_all lock",
            "address_format": "full",
            "alternatives": {
                "short_deprecated": short,
            },
            "lock_args": format!("0x{}", hexutil::encode_hex(&blake160)),
        })))
    }

    /// 原生 CKB 转账：收集发送方 live cell → 组装交易（含找零）→ 系统单签锁签名 → 广播。
    ///
    /// 实现说明（对照 ckb-sdk 5.1.0 `examples/chain_transfer_sighash.rs`）：
    /// - 发送方 lock script 由私钥本地派生（blake160(压缩公钥) + 系统 SIGHASH code_hash）；
    /// - cell 收集走 `DefaultCellCollector`（底层用 ckb-indexer，与现有 `sum_capacity` 同一端点约定）；
    /// - 容量平衡与找零由 `CapacityBalancer` 处理，手续费按 `fee_rate` 估算；
    /// - 签名由 `SecpSighashUnlocker` + `SecpCkbRawKeySigner` 完成，与链上
    ///   secp256k1_blake160_sighash_all 校验路径一致；
    /// - `dry_run = true` 时只构建并签名、不广播（仍需要节点做 cell 收集）。
    ///
    /// 注意 CKB 的 UTXO 语义：转账金额是「接收方 output 的 capacity」，不含找零；
    /// 找零 cell 由 `CapacityBalancer` 自动加回发送方。
    async fn transfer(&self, req: TransferRequest) -> Result<TransferView, SdkError> {
        // 1) 私钥 → 发送方公钥 → SecretKey（ckb-sdk 签名器要求 `secp256k1::SecretKey`）。
        let priv_bytes = hexutil::decode_hex(&req.private_key)
            .map_err(|e| SdkError::invalid_argument(format!("CKB 私钥非法: {e}")))?;
        if priv_bytes.len() != 32 {
            return Err(SdkError::invalid_argument(format!(
                "CKB 私钥需为 32 字节，实际 {} 字节",
                priv_bytes.len()
            )));
        }
        let secret_key = SecretKey::from_slice(&priv_bytes)
            .map_err(|e| SdkError::invalid_argument(format!("CKB 私钥非法: {e}")))?;
        let sender_pubkey = PublicKey::from_secret_key(&SECP256K1, &secret_key);

        // 2) 发送方 lock script（ckb-types `Script`）+ 人类可读地址（用于回显 from）。
        let sender_blake160 = address::ckb_blake160(&sender_pubkey.serialize());
        let sender_script = Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type)
            .args(Bytes::from(sender_blake160.to_vec()).pack())
            .build();
        let sender_address =
            address::encode_address(&LockScript::sighash_blake160(sender_blake160), self.is_mainnet);

        // 3) 接收方地址解析为 lock script（ckb-sdk 的 `Address` 走官方 bech32 解析）。
        let receiver: Address = req
            .to
            .trim()
            .parse()
            .map_err(|e| SdkError::invalid_argument(format!("非法 CKB 接收方地址: {e}")))?;
        let receiver_script = Script::from(&receiver);

        // 4) 金额：统一 `TransferRequest.amount` 按人类可读 CKB（如 "1.5"）解析为 shannon。
        let amount_raw = parse_units(&req.amount, self.kind().decimals())?;
        let capacity: u64 = amount_raw
            .try_into()
            .map_err(|_| SdkError::invalid_argument("CKB 转账金额超出 capacity 上限"))?;
        // 单个 cell 的 capacity 不能低于系统最小容量（61 CKB），否则节点会拒收。
        if capacity < official_ckb_sdk::constants::MIN_SECP_CELL_CAPACITY {
            return Err(SdkError::invalid_argument(format!(
                "CKB 单笔转账金额不能低于 {} shannon（约 {} CKB）",
                official_ckb_sdk::constants::MIN_SECP_CELL_CAPACITY,
                official_ckb_sdk::constants::MIN_SECP_CELL_CAPACITY
                    / official_ckb_sdk::constants::ONE_CKB
            )));
        }

        // 5) 组装 unlocker（签名器持有发送方私钥）。
        let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![secret_key]);
        let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<dyn Signer>);
        let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH);
        let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::default();
        unlockers.insert(
            sighash_script_id,
            Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
        );

        // 6) 容量平衡器：发送方 lock script 作为 capacity provider，占位 witness 为 65 字节签名槽。
        let placeholder_witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; 65])).pack())
            .build();
        let mut balancer = CapacityBalancer::new_simple(sender_script, placeholder_witness, 1000);
        // 最大手续费上限，避免手续费估算失控。
        balancer.set_max_fee(Some(100_000_000));

        // 7) 各 resolver / collector（均复用 `self.rpc_url`，与现有查询同一端点）。
        let mut cell_collector = DefaultCellCollector::new(self.rpc_url.as_str());
        let tx_dep_provider = DefaultTransactionDependencyProvider::new(self.rpc_url.as_str(), 10);
        let ckb_client = CkbRpcClient::new(self.rpc_url.as_str());
        let genesis_block = ckb_client
            .get_block_by_number(0.into())
            .map_err(|e| SdkError::new(ErrorCode::RpcError, format!("获取创世区块失败: {e}")))?
            .ok_or_else(|| SdkError::new(ErrorCode::RpcError, "创世区块不存在"))?;
        let cell_dep_resolver = DefaultCellDepResolver::from_genesis(&CoreBlockView::from(genesis_block))
            .map_err(|e| SdkError::new(ErrorCode::RpcError, format!("解析 cell dep 失败: {e}")))?;
        let header_dep_resolver = DefaultHeaderDepResolver::new(self.rpc_url.as_str());

        // 8) 构建并签名交易。
        let output = CellOutput::new_builder()
            .lock(receiver_script)
            .capacity(capacity)
            .build();
        let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);
        let (tx, still_locked) = builder
            .build_unlocked(
                &mut cell_collector,
                &cell_dep_resolver,
                &header_dep_resolver,
                &tx_dep_provider,
                &balancer,
                &unlockers,
            )
            .map_err(|e| SdkError::new(ErrorCode::RpcError, format!("构建 CKB 交易失败: {e}")))?;
        if !still_locked.is_empty() {
            return Err(SdkError::new(
                ErrorCode::RpcError,
                "存在未被解锁的 lock group，转账失败（接收方/发送方脚本不支持？）",
            ));
        }

        // 9) 序列化并决定广播与否。
        let json_tx = JsonTransactionView::from(tx.clone());
        let n_inputs = json_tx.inner.inputs.len();
        let n_outputs = json_tx.inner.outputs.len();
        let n_cell_deps = json_tx.inner.cell_deps.len();

        let tx_hash: String = if req.dry_run {
            // 未广播：交易哈希由本地计算（与广播后节点返回的一致）。
            format!("0x{}", hexutil::encode_hex(json_tx.hash.as_bytes()))
        } else {
            let ckb_client = CkbRpcClient::new(self.rpc_url.as_str());
            let hash = ckb_client
                .send_transaction(json_tx.inner, Some(OutputsValidator::Passthrough))
                .map_err(|e| SdkError::new(ErrorCode::RpcError, format!("广播 CKB 交易失败: {e}")))?;
            format!("0x{}", hexutil::encode_hex(hash.as_bytes()))
        };

        Ok(TransferView::new(
            ChainKind::Ckb,
            &self.network,
            Some(sender_address),
            req.to,
            amount_raw,
            Some(tx_hash.clone()),
            !req.dry_run,
        )
        .with_extra(json!({
            "tx_hash": tx_hash,
            "dry_run": req.dry_run,
            "note": if req.dry_run {
                "已构建并签名，未广播（dry_run）"
            } else {
                "已广播到 CKB 节点"
            },
            "inputs": n_inputs,
            "outputs": n_outputs,
            "cell_deps": n_cell_deps,
            "from_script_args": format!("0x{}", hexutil::encode_hex(&sender_blake160)),
        })))
    }
}

/// `hash_type` 数值 → CKB JSON-RPC 要求的字符串。
///
/// 领域说明：取值 **0/1/2/4**（data / type / data1 / data2）。
/// 跳过了 3，这是因为 data1 / data2 是后来新增的、按位移方式定义的匹配模式，
/// 与最初的 data / type 不在同一次协议扩展里。照「连续枚举」写会错。
///
/// 语法说明：返回 `&'static str` 是编译进二进制的字面量，零分配；
/// 兜底分支返回 `"type"`（最常用、也最安全的一种）。
fn hash_type_str(hash_type: u8) -> &'static str {
    match hash_type {
        0 => "data",
        1 => "type",
        2 => "data1",
        4 => "data2",
        _ => "type",
    }
}

/// 把 JSON-RPC 返回的 lock script 对象解析成 `LockScript`。
///
/// 返回 `Option` 而非 `Result`：这里的失败都是「上游结构不符合预期」，
/// 调用方（如 `tx`）只想「有就解析、没有就算了」，不需要错误详情。
fn parse_lock_json(value: &Value) -> Option<LockScript> {
    // 一连串 `?` 是 `Option` 的**提前返回**运算符（与 `Result` 的 `?` 同形）：
    // 任何一步为 `None` 就立即 `return None`。这比层层 `if let` 嵌套清爽得多。
    //
    // `.get("code_hash")?`  → `Option<&Value>`，为 None 则整个函数返回 None
    // `.as_str()?`          → `Option<&str>`
    let code_hash_hex = value.get("code_hash")?.as_str()?;
    // `hexutil::decode_hex` 返回 `Result<Vec<u8>, SdkError>`，
    // 而这里要的是 `Option`，所以 `.ok()` 把错误详情丢弃。
    let code_hash_bytes = hexutil::decode_hex(code_hash_hex).ok()?;
    // `try_into()`：`Vec<u8>` → `[u8; 32]`。这是**可能失败**的转换
    // （长度不等时失败），返回 `Result`，故再 `.ok()` 一次。
    //
    // 为什么需要这一步：`LockScript.code_hash` 的类型是定长数组 `[u8; 32]`，
    // 定长数组能把「一定是 32 字节」这个约束写进类型系统，
    // 而 `Vec<u8>` 表达不了。代价就是这里要做一次带检查的转换。
    let code_hash: [u8; 32] = code_hash_bytes.try_into().ok()?;
    let ht = match value.get("hash_type")?.as_str()? {
        "data" => 0,
        "type" => 1,
        "data1" => 2,
        "data2" => 4,
        // 未知取值按 `type` 处理（与 `hash_type_str` 的兜底保持一致）。
        _ => 1,
    };
    let args = hexutil::decode_hex(value.get("args")?.as_str()?).ok()?;
    // 结构体字面量；字段名与变量名相同时可简写，如 `args` 等价于 `args: args`。
    Some(LockScript {
        code_hash,
        hash_type: ht,
        args,
    })
}

/// 校验交易哈希：`0x` 前缀（**必须有**）+ 恰好 64 位十六进制。
fn validate_txid(raw: &str) -> Result<(), SdkError> {
    // 与 apt 的 `validate_tx_hash` 不同，这里**强制**要求 `0x` 前缀：
    // CKB 的 JSON-RPC 参数一律用 `0x` 十六进制字符串，不带前缀会被节点拒绝，
    // 与其让服务端报含糊的错误，不如本地给出明确提示。
    let body = raw
        .trim()
        .strip_prefix("0x")
        .ok_or_else(|| SdkError::invalid_argument(format!("CKB 哈希需带 0x 前缀: {raw}")))?;
    if body.len() != 64 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SdkError::invalid_argument(format!(
            "非法 CKB 交易哈希: {raw}"
        )));
    }
    Ok(())
}

/// 判断 `raw` 是否形如 `0x` + 64 位十六进制（即区块哈希/交易哈希）。
fn is_txid_hex(raw: &str) -> bool {
    // `strip_prefix("0x").is_some_and(|b| ..)`：
    // 先剥前缀（失败即 `None`），再用闭包判断主体是否合规，
    // 两步合成一句。`is_some_and` 是 `Option` 的组合子，
    // 相当于 `map(闭包).unwrap_or(false)` 的简写。
    raw.strip_prefix("0x")
        .is_some_and(|b| b.len() == 64 && b.chars().all(|c| c.is_ascii_hexdigit()))
}

/// 区块号统一为 `0x` 十六进制字符串。
///
/// 领域说明：CKB 的 JSON-RPC 在**不同版本的节点**上对区块号的接受度不一致，
/// 有的要十六进制字符串、有的也吃十进制字符串。统一归一成 `0x..` 最稳妥。
fn normalize_number(raw: &str) -> Result<String, SdkError> {
    if let Some(hex) = raw.strip_prefix("0x") {
        // 已经是十六进制：解析一遍确认合法，再按规范形式重新输出。
        // `{n:x}` 是格式串里的「小写十六进制」说明符。
        u64::from_str_radix(hex, 16)
            .map(|n| format!("0x{n:x}"))
            .map_err(|_| SdkError::invalid_argument(format!("非法区块号: {raw}")))
    } else {
        // 十进制：解析后转成十六进制输出。
        // 注意两条分支的错误文案不同（「区块号」vs「区块引用」），
        // 便于调用方区分自己传的是哪种形式。
        raw.parse::<u64>()
            .map(|n| format!("0x{n:x}"))
            .map_err(|_| SdkError::invalid_argument(format!("非法区块引用: {raw}")))
    }
}

/// 单元测试模块：`#[cfg(test)]` 保证它只在 `cargo test` 时编译，正式构建里不存在。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_block_numbers() {
        // 十进制与十六进制输入都应归一成同一种输出形式。
        assert_eq!(normalize_number("100").unwrap(), "0x64");
        assert_eq!(normalize_number("0x64").unwrap(), "0x64");
        // 非数字输入必须报错。
        assert!(normalize_number("abc").is_err());
    }

    #[test]
    fn validates_txids() {
        assert!(validate_txid(&format!("0x{}", "ab".repeat(32))).is_ok());
        // 不带 `0x` 前缀要被拒——这与 apt 的宽松策略不同，是 CKB 的硬性要求。
        assert!(validate_txid(&"ab".repeat(32)).is_err());
        assert!(is_txid_hex(&format!("0x{}", "ab".repeat(32))));
    }

    #[test]
    fn transfer_derives_sender_address_offline() {
        // 离线验证 `transfer` 里的「私钥 → 发送方地址」派生路径，避免任何 RPC。
        // 测试私钥仅为向量用途，切勿用于真实资金。
        let priv_hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let priv_bytes = hexutil::decode_hex(priv_hex).unwrap();
        assert_eq!(priv_bytes.len(), 32);
        let secret_key = SecretKey::from_slice(&priv_bytes).unwrap();
        let pubkey = PublicKey::from_secret_key(&SECP256K1, &secret_key);

        // 严格复刻 transfer 里的派生逻辑（与 adapter.rs 同一套零件）。
        let blake160 = address::ckb_blake160(&pubkey.serialize());
        let lock = LockScript::sighash_blake160(blake160);
        let mainnet_addr = address::encode_address(&lock, true);
        let testnet_addr = address::encode_address(&lock, false);

        // 1) 与地址模块自己的「压缩公钥 → 地址」函数结果完全一致，
        //    锁死 transfer 用的是正确的 code_hash / hash_type（type=1）。
        assert_eq!(
            mainnet_addr,
            address::address_from_compressed_pubkey(&hexutil::encode_hex(&pubkey.serialize()), true)
                .unwrap()
        );
        // 2) 主网/测试网前缀正确（ckb1 / ckt1）。
        assert!(mainnet_addr.starts_with("ckb1"));
        assert!(testnet_addr.starts_with("ckt1"));
        // 3) 往返：编码 → 解码必须还原出同一 lock 与「是否主网」标识。
        let (decoded, is_main) = address::decode_address(&mainnet_addr).unwrap();
        assert!(is_main);
        assert_eq!(decoded, lock);
        // 4) 非 32 字节私钥必须被 `SecretKey::from_slice` 拒绝，
        //    对应 transfer 里「私钥需为 32 字节」的长度守卫。
        assert!(SecretKey::from_slice(&priv_bytes[..31]).is_err());
    }
}
