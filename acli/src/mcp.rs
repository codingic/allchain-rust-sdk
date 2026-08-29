//! MCP stdio 服务器：让支持 MCP 的 agent 直接把十链能力当工具调用。
//!
//! 协议为 JSON-RPC 2.0 over stdio（MCP `2024-11-05` 的 stdio 传输）。
//! 这里手写实现而非引入 SDK，只为少一层不稳定依赖——
//! 需要支持的只有 `initialize` / `tools/list` / `tools/call` 三个方法。
//!
//! **stdout 只能输出 JSON-RPC 报文**，任何日志都必须走 stderr。

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::dispatch::{self, Action};

const PROTOCOL_VERSION: &str = "2024-11-05";

pub async fn serve_stdio() -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(err) => {
                write_line(&mut stdout, &parse_error(&err.to_string())).await?;
                continue;
            }
        };
        if let Some(response) = handle(&request).await {
            write_line(&mut stdout, &response).await?;
        }
    }
    Ok(())
}

async fn handle(request: &Value) -> Option<Value> {
    let id = request.get("id").cloned();
    let method = request.get("method")?.as_str()?;

    match method {
        "initialize" => Some(result(
            id?,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": {
                    "name": "allchain-sdk",
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": "统一操作 eth / btc / sol / near / apt / ar / ckb / fil / sui / ton 十链：全链只读查询，前四链支持转账（含 dry-run）"
                }
            }),
        )),

        "tools/list" => Some(result(id?, json!({ "tools": tools() }))),

        "tools/call" => {
            let id = id?;
            let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
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
        "notifications/initialized" | "notifications/cancelled" => None,

        other => id.map(|id| error_response(id, -32601, format!("不支持的方法: {other}"))),
    }
}

async fn call_tool(name: &str, arguments: &Value) -> Value {
    let (text, is_error) = match execute(name, arguments).await {
        Ok(envelope) => (envelope.to_json_pretty(), !envelope.ok),
        Err(message) => (
            json!({ "ok": false, "error": { "code": "INVALID_ARGUMENT", "message": message } })
                .to_string(),
            true,
        ),
    };

    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error,
    })
}

async fn execute(name: &str, arguments: &Value) -> Result<allchain_core::Envelope<Value>, String> {
    if name == "chain_catalog" {
        return Ok(success_envelope(dispatch::chain_catalog()));
    }

    let chain =
        dispatch::parse_chain(require_str(arguments, "chain")?).map_err(|err| err.message)?;
    let network = arguments.get("network").and_then(|v| v.as_str());
    let rpc_url = arguments.get("rpc_url").and_then(|v| v.as_str());

    let action = match name {
        "chain_status" => Action::Status,
        "chain_balance" | "chain_get_balance" | "get_balance" | "getbalance" => Action::Balance {
            address: require_str(arguments, "address")?.to_string(),
        },
        "chain_block" => Action::Block {
            reference: arguments
                .get("reference")
                .and_then(|v| v.as_str())
                .map(str::to_string),
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
            dry_run: arguments
                .get("dry_run")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            from: arguments
                .get("from")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        },
        other => return Err(format!("未知工具: {other}")),
    };

    Ok(dispatch::run_action(chain, network, rpc_url, action).await)
}

fn success_envelope(data: Value) -> allchain_core::Envelope<Value> {
    allchain_core::Envelope::ok("all", "catalog", 0, data)
}

fn require_str<'a>(arguments: &'a Value, key: &str) -> Result<&'a str, String> {
    arguments
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("缺少必填参数: {key}"))
}

/// 工具清单。schema 写得具体一些，agent 才能正确填参数。
fn tools() -> Vec<Value> {
    let chain_prop = || {
        json!({
            "type": "string",
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
            "name": "chain_block",
            "description": "查询区块。ETH/NEAR/BTC/APT/AR/CKB/FIL/SUI/TON 可省略 reference 取最新；SOL 必须传 slot；SUI 传 checkpoint 序号；TON 传主链 seqno。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chain": chain_prop(),
                    "reference": { "type": "string", "description": "区块高度/哈希；SOL 为 slot（必填），SUI 为 checkpoint 序号" },
                    "network": network_prop(),
                    "rpc_url": rpc_prop()
                },
                "required": ["chain"]
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
                "required": ["chain", "to", "amount"]
            }
        }),
    ]
}

async fn write_line<W: AsyncWriteExt + Unpin>(out: &mut W, payload: &Value) -> anyhow::Result<()> {
    let mut line = serde_json::to_string(payload)?;
    line.push('\n');
    out.write_all(line.as_bytes()).await?;
    out.flush().await?;
    Ok(())
}

fn result(id: Value, payload: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": payload })
}

fn error_response(id: Value, code: i32, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() }
    })
}

fn parse_error(message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": { "code": -32700, "message": format!("JSON 解析失败: {message}") }
    })
}
