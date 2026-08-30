//! MCP stdio 服务器：让支持 MCP 的 agent 直接把十链能力当工具调用。
//!
//! 协议为 JSON-RPC 2.0 over stdio（MCP `2024-11-05` 的 stdio 传输）。
//! 这里手写实现而非引入 SDK，只为少一层不稳定依赖——
//! 需要支持的只有 `initialize` / `tools/list` / `tools/call` 三个方法。
//!
//! **stdout 只能输出 JSON-RPC 报文**，任何日志都必须走 stderr。
//!
//! ## 为什么手写而不引入 MCP SDK
//! 我们只需要三个方法（`initialize` / `tools/list` / `tools/call`，外加一个 `ping`），
//! 协议本身也极简：一行一个 JSON 对象，进 stdin、出 stdout。
//! 引入 SDK 会带来三件麻烦：它仍在快速演进（breaking change 频繁）、
//! 会绑定自己的异步运行时与传输层、还会把「工具注册」抽象成另一套 DSL；
//! 而本项目真正的业务逻辑已经全部在 [`dispatch`] 里了。
//! 手写 300 行换掉一层不稳定依赖，对常驻在 agent 进程里的组件是划算的。
//!
//! ## 为什么工具 schema 里 `chain` 用 `enum` 约束
//! agent（大模型）填参数时，`"type": "string"` + 描述里的「可选 eth / btc / ...」
//! 远不如直接给 `"enum": ["eth", "btc", ...]` 可靠：后者是**闭合取值集合**，
//! 客户端可以在调用前就校验并纠正，模型也不容易写出 `Ethereum` / `ETH_MAINNET`
//! 这类自由发挥的取值。链标识是本项目最关键的入参，值得用 schema 兜一层。
//! 其余参数（地址、哈希）无法枚举，只能靠 `description` 说明格式。

use serde_json::{Value, json};
// tokio 的异步 IO：`AsyncBufReadExt` 提供 `.lines()`（按行异步读取），
// `AsyncWriteExt` 提供 `.write_all()` / `.flush()`，`BufReader` 给 stdin 加缓冲，
// 否则每次读一个字节会产生大量系统调用。
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::dispatch::{self, Action};

/// 与客户端协商的 MCP 协议版本。
///
/// 语法说明：`const` 定义**编译期常量**，类型必须显式写出（`&str`）。
/// 与 `let` 的区别：`const` 没有固定的内存地址，值会被内联到每一处使用点；
/// 而且它必须能在编译期求值，所以不能装 `String`（需要堆分配）。
/// 这里用 `&str` 而非 `String`，就是因为它只是一个编译进二进制的字面量。
const PROTOCOL_VERSION: &str = "2024-11-05";

/// MCP 主循环：从 stdin 一行一条地读 JSON-RPC 请求，往 stdout 一行一条地写响应。
///
/// **这是全模块最硬的约束**：stdout 是本进程的协议通道，
/// 任何 `println!` / `dbg!` / panic 信息混进去都会让客户端解析失败，
/// 表现是「agent 反复报 JSON parse error」而很难定位。
/// 所以排障日志一律用 `eprintln!` 走 stderr（stderr 不参与协议，客户端也不会读它）。
pub async fn serve_stdio() -> anyhow::Result<()> {
    // `tokio::io::stdin()` 返回异步的 stdin 句柄（不阻塞整个线程）。
    let stdin = tokio::io::stdin();
    // `BufReader` 加一层缓冲，`.lines()` 由 `AsyncBufReadExt` 提供，
    // 产出一个**异步行迭代器**：每次 `.next_line().await` 读到一行（不含换行符）。
    let mut lines = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    // `while let Some(line) = ...` = 「只要还能读出下一行就继续」。
    // 两种模式合在一起：`let` 解构 `Option`，`while` 在得到 `None`（stdin 关闭）时结束循环。
    // 末尾的 `?`：读失败（IO 错误）时把错误交给调用方，进程随之退出。
    while let Some(line) = lines.next_line().await? {
        // 客户端可能在行尾带 `\r`（Windows）或发空行，先 trim 再判空跳过。
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // 解析失败时**不能**丢弃请求：JSON-RPC 要求返回一条 parse error，
        // 否则客户端会一直等在这条请求的响应上。
        let request: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(err) => {
                // 注意这里拿不到 `id`——报文根本没解析出来，故 `parse_error` 里 id 为 null。
                write_line(&mut stdout, &parse_error(&err.to_string())).await?;
                continue;
            }
        };
        // `handle` 返回 `Option<Value>`：`None` 表示「按协议不该回复」，
        // 于是这里什么都不写，继续等下一条。
        if let Some(response) = handle(&request).await {
            write_line(&mut stdout, &response).await?;
        }
    }
    // stdin 关闭（父进程退出）时循环结束，正常返回 `Ok(())`。
    Ok(())
}

/// 把一条 JSON-RPC 请求分派到具体方法；返回 `None` 表示**不需要回复**（通知类消息）。
///
/// 语法说明：`&Value` 借用请求，因为我们只需要读它；
/// 返回 `Value` 则是把构造好的响应所有权交出去。
async fn handle(request: &Value) -> Option<Value> {
    // `.get("id")` 返回 `Option<&Value>`；`.cloned()` 是 `Option<&T>` 上的便捷方法，
    // 把它变成 `Option<Value>`（克隆出一份自有值，等价于 `.map(|v| v.clone())`）。
    // 必须克隆：请求只是借来的，而响应要独立存在到被写出去为止。
    let id = request.get("id").cloned();
    // `?` 在返回 `Option` 的函数里表示「为 None 就整体返回 None」，
    // 这就是 `?` 的**双重身份**：在 `Result` 上提前返回 Err，在 `Option` 上提前返回 None。
    // 没有 `id` 或 `method` 不是字符串 -> 无法应答，静默丢弃。
    let method = request.get("method")?.as_str()?;

    match method {
        "initialize" => Some(result(
            // `id?`：通知类消息没有 id；`initialize` 必然是请求，故这里直接 `?` 取出。
            id?,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                // 能力声明：只声明 tools，且明确「工具列表不会在运行中变化」，
                // 客户端就不必订阅 listChanged 通知，省掉一轮往返。
                "capabilities": { "tools": { "listChanged": false } },
                // `env!("CARGO_PKG_VERSION")` 是**编译期**宏：
                // 直接把 Cargo.toml 里的版本号字符串内联进来，运行期零开销，
                // 也就不会出现「二进制与版本号不一致」的情况。
                "serverInfo": {
                    "name": "allchain-sdk",
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": "统一操作 eth / btc / sol / near / apt / ar / ckb / fil / sui / ton 十链：全链只读查询，前四链支持转账（含 dry-run）"
                }
            }),
        )),

        "tools/list" => Some(result(id?, json!({ "tools": tools() }))),

        "tools/call" => {
            // 先取出 id（后面要用到两次，先解一次避免重复 `?`）。
            let id = id?;
            // `params` 缺失时用空对象兜底，这样后续 `.get(..)` 一律安全。
            let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
            // 取值链：`.get("name")` -> `Option<&Value>`，`.and_then(|v| v.as_str())` 转成 `Option<&str>`，
            // `.unwrap_or_default()` 取不到时给空串，`.to_string()` 得到自有 `String`。
            // 为什么要 `to_string()`：下面要把它传给 `call_tool`，
            // 而 `params` 是局部变量，借用它的结果活不了那么久。
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            Some(result(id, call_tool(&name, &arguments).await))
        }

        "ping" => Some(result(id?, json!({}))),

        // 通知类消息没有 id，按协议不回复。
        // `|` 在这里是**或模式**：一个分支匹配两个方法名。
        "notifications/initialized" | "notifications/cancelled" => None,

        // 未知方法：有 id 就回一条 -32601（标准 JSON-RPC 的「方法不存在」），
        // 没 id（通知）则 `id.map(..)` 直接得到 None，不回复——与上面的规则一致。
        other => id.map(|id| error_response(id, -32601, format!("不支持的方法: {other}"))),
    }
}

/// 执行一次工具调用并包装成 MCP 的 `CallToolResult`。
///
/// 关键设计：**工具本身的失败不返回 JSON-RPC error**。
/// `tools/call` 的协议层成功（我们确实执行了这个工具），
/// 业务上的成败通过 `content` 里的内容 + `isError` 表达。
/// 这样 agent 能看到完整的信封（含 `error.code` / `retryable`），
/// 而不是只拿到一句「工具调用失败」——后者会让它无从判断要不要重试。
async fn call_tool(name: &str, arguments: &Value) -> Value {
    // `match` 的两个分支都产出 `(String, bool)` 元组：文本内容 + 是否算错误。
    let (text, is_error) = match execute(name, arguments).await {
        // 拿到信封：整份 JSON（含可能的错误体）都作为文本回给 agent，
        // `is_error` 直接取信封 `ok` 的反面。
        Ok(envelope) => (envelope.to_json_pretty(), !envelope.ok),
        // 参数层面的失败（未知工具名、缺必填参数）拿不到信封，
        // 手工构造一个与信封错误体**同构**的 JSON，保持 agent 的解析逻辑不变。
        Err(message) => (
            json!({ "ok": false, "error": { "code": "INVALID_ARGUMENT", "message": message } })
                .to_string(),
            true,
        ),
    };

    // MCP 规定结果必须是 `content` 数组，每个元素是一段带 `type` 的内容块；
    // 这里只回一段纯文本（`text`），把信封 JSON 原样放进去。
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error,
    })
}

/// 把「工具名 + 参数」翻译成一次 dispatch 调用。
///
/// 返回 `Result<Envelope<Value>, String>`：
/// `Err` 只表示**参数/工具名层面**的问题（连链都还没认出来）；
/// 一旦进了 dispatch，成败就由信封表达，不再走 `Err`。
async fn execute(name: &str, arguments: &Value) -> Result<allchain_core::Envelope<Value>, String> {
    // `chain_catalog` 是唯一不需要 `chain` 参数的工具，先单独处理掉，
    // 这样下面所有分支都可以无条件要求 `chain`——参数校验规则保持一致。
    if name == "chain_catalog" {
        return Ok(success_envelope(dispatch::chain_catalog()));
    }

    // `require_str(..)?` 缺参数时直接返回 `Err`；
    // `parse_chain(..).map_err(|err| err.message)?` 把 `SdkError` 压成一个字符串：
    // 这里只需要把提示透传给 agent，没必要再包一层错误类型。
    let chain =
        dispatch::parse_chain(require_str(arguments, "chain")?).map_err(|err| err.message)?;
    // `network` / `rpc_url` 是可选的：`and_then(|v| v.as_str())` 取不到就是 `None`，
    // 交给适配器套用该链的默认值。
    let network = arguments.get("network").and_then(|v| v.as_str());
    let rpc_url = arguments.get("rpc_url").and_then(|v| v.as_str());

    let action = match name {
        "chain_status" => Action::Status,
        // 一个分支匹配多个工具名：这几个是历史/习惯别名，行为完全一致。
        // 放在**同一个分支**而不是写多份实现，保证别名永远不会与正主跑偏。
        "chain_balance" | "chain_get_balance" | "get_balance" | "getbalance" => Action::Balance {
            address: require_str(arguments, "address")?.to_string(),
        },
        "chain_block_height" => Action::LastBlockHeight,
        "chain_block_by_height" => Action::BlockByHeight {
            // JSON 数字用 `as_u64()` 取出；取不到就报缺参错误。
            // 类型化参数意味着 agent 传非数字高度会被这里拦下，
            // 而不是被某条链的适配器运行期才报错。
            height: arguments
                .get("height")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "缺少必填参数: height".to_string())?,
        },
        "chain_tx" => Action::Tx {
            hash: require_str(arguments, "hash")?.to_string(),
        },
        // 兼容调用方按 `getaddressfrompubkey` / `get_address_from_pubkey` 的写法。
        "chain_address_from_pubkey" | "get_address_from_pubkey" | "getaddressfrompubkey" => {
            Action::AddressFromPubkey {
                pubkey: require_str(arguments, "pubkey")?.to_string(),
            }
        }
        "chain_transfer" => Action::Transfer {
            to: require_str(arguments, "to")?.to_string(),
            amount: require_str(arguments, "amount")?.to_string(),
            private_key: arguments
                .get("private_key")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            // 布尔参数用 `as_bool()`（而不是 `as_str()`）：JSON 里的 `true` 是布尔而非字符串。
            // `.unwrap_or(false)` 表示缺省就**真的广播**——dry-run 必须由调用方显式开启，
            // 默认行为不替它猜测意图（真要防误转，应该在描述里提醒，而不是偷偷改默认）。
            dry_run: arguments
                .get("dry_run")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            from: arguments
                .get("from")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        },
        // 兜底分支：未知工具名。注意这里是 `return Err(..)` 直接退出函数，
        // 因为已经没有 `Action` 可构造了；`{other}` 会把工具名内联进提示里。
        other => return Err(format!("未知工具: {other}")),
    };

    // 到这一步参数齐备，成败一律由信封表达，故直接 `Ok(..)`。
    Ok(dispatch::run_action(chain, network, rpc_url, action).await)
}

/// 为 `chain_catalog` 这类「不属于任何一条链」的结果造一个外壳信封。
///
/// 为什么仍要包信封：agent 的解析逻辑是按信封写的（先看 `ok`、再看 `data`），
/// 让**所有**工具返回同一种结构，它就不必为清单工具单独分支。
/// `chain` 填 `"all"`、`network` 填 `"catalog"`，是为了让人类一眼看出这不是某条链的响应。
fn success_envelope(data: Value) -> allchain_core::Envelope<Value> {
    allchain_core::Envelope::ok("all", "catalog", 0, data)
}

/// 取必填的字符串参数，缺失则返回可读错误。
///
/// 语法说明：`<'a>` 是**生命周期参数**，`arguments: &'a Value` 与返回值 `&'a str`
/// 用同一个 `'a` 标注，意思是「返回的引用借自 `arguments`，活得不会比它更久」。
/// 有了这个标注，编译器就能证明我们没有把局部量的引用交出去。
/// 不写的话，`&Value -> &str` 的生命周期无法推断（多个输入引用时规则失效），会编译失败。
fn require_str<'a>(arguments: &'a Value, key: &str) -> Result<&'a str, String> {
    arguments
        .get(key)
        .and_then(|v| v.as_str())
        // `ok_or_else` 惰性构造错误串：成功路径上不付 `format!` 的分配代价。
        .ok_or_else(|| format!("缺少必填参数: {key}"))
}

/// 工具清单。schema 写得具体一些，agent 才能正确填参数。
///
/// 这是 agent 认识本 SDK 的**唯一入口**，所以每条描述都写得像文档：
/// 「哪些链支持」「参数是什么格式」「NEAR 要传账户名」这类信息，
/// 模型在 `tools/list` 时看不到，就只能靠猜或靠报错重试。
/// 宁可描述长一点，也不要让 agent 拿错误参数去试。
///
/// 返回 `Vec<Value>` 而不是定义一个 `Tool` 结构体：schema 本身就是动态的 JSON，
/// 各工具的字段组合差异大，用结构体描述反而要写一堆 `Option` 字段。
fn tools() -> Vec<Value> {
    // 三个**无参闭包**，每次调用返回一个新的 schema 片段。
    // 为什么是闭包而不是 `const`：`json!` 宏构造的是运行期的 `Value`（需要堆分配），
    // 不能做成 `const`；写成闭包则既能避免把同一段 schema 抄七八遍，
    // 又能让每个工具拿到**彼此独立**的对象（各自持有自己的 `Map`）。
    let chain_prop = || {
        json!({
            "type": "string",
            // `enum` 是这里最关键的约束：链标识是闭合集合，
            // 客户端可以在调用前校验，模型也不会写出 `Ethereum` 这类自由发挥的取值。
            "enum": ["eth", "btc", "sol", "near", "apt", "ar", "ckb", "fil", "sui", "ton"],
            "description": "链标识"
        })
    };
    let network_prop = || {
        json!({
            "type": "string",
            "description": "网络名；十链默认均为 mainnet，可显式指定 testnet / devnet / sepolia 等"
        })
    };
    let rpc_prop = || {
        json!({
            "type": "string",
            "description": "自定义 RPC 端点；BTC 上为 Esplora 索引器，SUI 上为 GraphQL 端点"
        })
    };

    // `vec![ ... ]` 宏构造一个 `Vec<Value>`；每个元素是一个工具的完整定义，
    // 顺序即 `tools/list` 返回给 agent 的顺序——把 `chain_catalog` 放第一个，
    // 因为它是「元工具」：agent 先调它能确认链标识，再调其它工具。
    vec![
        json!({
            "name": "chain_catalog",
            "description": "列出所有支持的链、原生资产精度、默认网络与可用能力。无需参数，先调用它可以确认链标识。",
            "inputSchema": { "type": "object", "properties": {}, "required": [] }
        }),
        json!({
            "name": "chain_status",
            "description": "查询指定链的节点与链状态：最新高度、最新区块哈希、节点版本。",
            "inputSchema": {
                "type": "object",
                "properties": { "chain": chain_prop(), "network": network_prop(), "rpc_url": rpc_prop() },
                "required": ["chain"]
            }
        }),
        json!({
            "name": "chain_balance",
            "description": "查询地址或账户的原生资产余额，同时返回最小单位整数与可读金额。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chain": chain_prop(),
                    "address": { "type": "string", "description": "地址；NEAR 传账户名，如 example.near" },
                    "network": network_prop(),
                    "rpc_url": rpc_prop()
                },
                "required": ["chain", "address"]
            }
        }),
        json!({
            "name": "chain_get_balance",
            // 与 `chain_balance` 行为完全一致，只是名字不同：
            // 不同 agent 平台对工具名有各自的命名习惯（下划线 / 全小写 / 带前缀），
            // 与其让调用方适配我们，不如多注册几个别名，成本几乎为零。
            "description": "查询地址余额，与 chain_balance 等价（别名：getbalance / get_balance）。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chain": chain_prop(),
                    "address": { "type": "string", "description": "地址；NEAR 传账户名，如 example.near" },
                    "network": network_prop(),
                    "rpc_url": rpc_prop()
                },
                "required": ["chain", "address"]
            }
        }),
        json!({
            "name": "chain_block_height",
            "description": "查询链头高度（最新区块高度），返回裸数字。轮询同步进度或确认节点是否追上链头时优先用它，比拉整块更轻。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chain": chain_prop(),
                    "network": network_prop(),
                    "rpc_url": rpc_prop()
                },
                "required": ["chain"]
            }
        }),
        json!({
            "name": "chain_block_by_height",
            "description": "按高度查询区块（含父哈希、时间戳、交易数、gas 等）。各链「高度」含义：ETH/BTC/NEAR/APT/AR/CKB/FIL 为区块高度；SOL 为 slot；SUI 为 checkpoint 序号；TON 为 masterchain seqno。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chain": chain_prop(),
                    "height": { "type": "integer", "description": "区块高度（数字）。SOL 传 slot，SUI 传 checkpoint 序号，TON 传 masterchain seqno。" },
                    "network": network_prop(),
                    "rpc_url": rpc_prop()
                },
                "required": ["chain", "height"]
            }
        }),
        json!({
            "name": "chain_tx",
            "description": "查询交易详情与执行状态。NEAR 的 hash 必须形如 <tx_hash>@<sender.near>；TON 必须形如 <tx_hash>:<lt>@<address>。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chain": chain_prop(),
                    "hash": { "type": "string", "description": "交易哈希；NEAR 需附带发送者账户，TON 需附带 lt 与账户地址" },
                    "network": network_prop(),
                    "rpc_url": rpc_prop()
                },
                "required": ["chain", "hash"]
            }
        }),
        json!({
            "name": "chain_address_from_pubkey",
            // 长描述用**反斜杠续行**：字符串末尾的 `\` 会连同换行符与
            // 下一行开头的空白一起被吃掉，于是多行内容最终拼成一段连续的文本，
            // 而源码里可以保持整齐的缩进。这是 Rust 字符串字面量的语法，不是 JSON 的。
            "description": "由公钥派生地址。纯本地计算、不联网、无需 RPC（TON 不支持，地址依赖钱包合约 StateInit）。\
                            ETH: 64 字节未压缩坐标或 65 字节带 04 前缀的十六进制；\
                            BTC: 33 字节压缩公钥（02/03 开头）的十六进制，返回 P2WPKH 主地址并给出 p2pkh / p2sh-p2wpkh / p2tr；\
                            SOL: base58 或 64 位十六进制的 32 字节 ed25519 公钥；\
                            NEAR: ed25519:<base58> 形式，返回 64 位十六进制的隐式账户；\
                            APT: 32 字节 ed25519 公钥十六进制（SHA3-256 派生）；\
                            AR: RSA 公钥模数 n 的 base64url；\
                            CKB: 33 字节压缩 secp256k1 公钥（blake160 派生，附 short 地址）；\
                            FIL: 65 字节未压缩 secp256k1 公钥（f1 地址）；\
                            SUI: 32 字节 ed25519 公钥，可加 ed25519:/secp256k1: 前缀。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chain": chain_prop(),
                    "pubkey": { "type": "string", "description": "公钥；格式随链而异，见工具描述" },
                    "network": network_prop(),
                    "rpc_url": rpc_prop()
                },
                "required": ["chain", "pubkey"]
            }
        }),
        json!({
            "name": "chain_transfer",
            // 这是唯一会动用私钥、可能造成真实资产损失的工具，描述里刻意写足了安全提示：
            // 能力边界（只有四链）、私钥来源优先级、format 说明，
            // 以及最后一句「陌生环境先 dry_run」——这是给 agent 的操作规程，不是给用户看的文案。
            "description": "转账原生资产：仅 eth / btc / sol / near 四链支持本地构造、签名并广播；其余六链返回 UNSUPPORTED。\
                            私钥优先用 private_key 参数；缺省时读环境变量 ETH_SECRET_KEY / BTC_WIF / SOL_KEYPAIR / NEAR_SECRET_KEY。\
                            dry_run=true 时只本地构造并签名（返回预期 tx_hash 与签名详情），绝不广播，可用于审计。\
                            private_key 格式：ETH 32 字节十六进制；BTC WIF；SOL JSON 数组或 base58 的 64 字节；NEAR ed25519:...。\
                            NEAR 的 from 传命名账户；省略时按私钥派生隐式账户。\
                            先对陌生环境用 dry_run 验证，再正式 broadcast，防止误转。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chain": chain_prop(),
                    "to": { "type": "string", "description": "收款地址；NEAR 传账户名，如 bob.near" },
                    "amount": { "type": "string", "description": "金额，原生单位（如 0.01）；BTC 还支持 10000sat" },
                    "private_key": { "type": "string", "description": "签名私钥，格式随链而异（见工具描述）" },
                    "dry_run": { "type": "boolean", "description": "true=只本地签名不广播（默认 false）" },
                    "from": { "type": "string", "description": "源账户；NEAR 命名账户必填" },
                    "network": network_prop(),
                    "rpc_url": rpc_prop()
                },
                // `required` 里**没有** `private_key`：它通常由环境变量提供
                // （见 dispatch::resolve_private_key），写进必填会逼 agent 每次都索要私钥。
                "required": ["chain", "to", "amount"]
            }
        }),
    ]
}

/// 把一条响应**原子地**写成一行：内容 + 换行符，然后立刻 flush。
///
/// 为什么要自己拼 `\n` 再 `write_all` 一次写完：
/// 若分两次写（先 JSON 再换行），并发场景下两半之间可能插入别的内容，
/// 客户端就会读到半条报文。一次 `write_all` 保证这一行是完整的。
///
/// 为什么要 `flush`：stdout 在面向管道时是**带缓冲**的，
/// 不 flush 的话响应会攒在缓冲区里，客户端迟迟收不到回复，表现为「卡死」。
///
/// 语法说明：`<W: AsyncWriteExt + Unpin>` 是**多重 trait 约束**：
/// `W` 必须能异步写（`AsyncWriteExt`），且必须是 `Unpin`
/// （`Unpin` 表示「这个类型在内存中移动是安全的」——`async fn` 生成的 future
/// 内部持有 `&mut W`，需要它可安全移动/固定）。
/// 泛型而非直接写 `Stdout`，是为了让这个函数能被单元测试用一个内存 buffer 替换掉。
async fn write_line<W: AsyncWriteExt + Unpin>(out: &mut W, payload: &Value) -> anyhow::Result<()> {
    let mut line = serde_json::to_string(payload)?;
    line.push('\n');
    // `as_bytes()` 借出 `&[u8]`：`write_all` 面向字节，而 `String` 是 UTF-8 字符串。
    out.write_all(line.as_bytes()).await?;
    out.flush().await?;
    Ok(())
}

/// 构造 JSON-RPC 2.0 的**成功响应**。
///
/// 三个固定字段：`jsonrpc`（协议版本字符串）、`id`（与请求一一对应，
/// 客户端靠它把响应对回请求，所以必须原样回传，哪怕它是字符串或 null）、`result`。
fn result(id: Value, payload: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": payload })
}

/// 构造 JSON-RPC 2.0 的**错误响应**。
///
/// 语法说明：`impl Into<String>` 是「任意能转成 `String` 的类型」：
/// 调用方既能传 `&str` 字面量，也能传已分配好的 `String`（后者不会再多分配一次）。
/// 这是 Rust 里让 API 对调用方友好的标准写法。
///
/// 注意这是**协议层**错误（方法不存在、报文解析失败），
/// 与工具执行失败（走 `isError`）是两回事，不要混用。
fn error_response(id: Value, code: i32, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        // `.into()` 完成 `&str` / `String` -> `String` 的转换，目标类型由上下文推断。
        "error": { "code": code, "message": message.into() }
    })
}

/// 构造 JSON 解析失败的响应。
///
/// `id` 固定为 `null`：报文根本没解析出来，无从知道这是哪条请求，
/// 这正是 JSON-RPC 规范里规定的做法（-32700 Parse error）。
fn parse_error(message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": { "code": -32700, "message": format!("JSON 解析失败: {message}") }
    })
}
