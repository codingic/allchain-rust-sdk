//! sign：本地离线签名服务。
//!
//! 仅监听回环地址（`127.0.0.1`），**无任何鉴权**——本服务只应在本机被信任的程序调用。
//!
//! 端点（与 acli 的统一信封结构一致）：
//! - `GET  /v1/getprikey?chaintype=eth`      生成密钥对、派生地址、存入内存、返回私钥+地址。
//! - `POST /v1/signtx`  body `{chaintype, txdatahex, fromaddress}`
//!                                           用内存中 `fromaddress` 的私钥对 `txdatahex` 签名并组装可广播交易。
//! - `GET  /v1/chains`                       列出本服务支持的链与签名算法。
//!
//! 安全模型（与用户约定一致）：
//! - 私钥只在 `getprikey` 返回时一次性出现在响应里，并存于进程内存（按地址索引）；
//! - 进程退出即丢失，绝不写盘、绝不进日志；
//! - `signtx` 的 `fromaddress` 必须此前由 `getprikey` 在本进程生成过，否则返回参数错误。

mod keys;
mod sign;
mod store;

use std::time::Instant;

use axum::{
    Router,
    extract::{Json as JsonExtractor, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
};
use clap::Parser;
use serde::Deserialize;
use serde_json::{Value, json};

use allchain_core::{Envelope, ErrorCode, SdkError};
use store::{KeyStore, Scheme};

/// 进程内共享状态：内存密钥库。
#[derive(Clone)]
struct AppState {
    store: KeyStore,
}

/// CLI 参数。
#[derive(Parser)]
#[command(name = "sign", about = "本地离线签名服务：getprikey / signtx（eth/sol/near/apt/sui/ton）")]
struct Cli {
    /// 监听地址；默认回环，不对外暴露（本服务无鉴权）。
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 7878)]
    port: u16,
}

/// `GET /v1/getprikey` 查询参数。
#[derive(Debug, Deserialize)]
struct GetPriKeyParams {
    chaintype: String,
}

/// `POST /v1/signtx` 请求体。
#[derive(Debug, Deserialize)]
struct SignBody {
    chaintype: String,
    /// 交易原始字节（hex，可带 0x 前缀）；各链格式见 `sign` 模块文档。
    txdatahex: String,
    /// 由 getprikey 生成的地址（签名所用私钥在内存中按此地址索引）。
    fromaddress: String,
}

/// 启动 HTTP 服务并阻塞到进程终止。
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let state = AppState {
        store: KeyStore::new(),
    };

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/v1/chains", get(chains_handler))
        .route("/v1/getprikey", get(getprikey_handler))
        .route("/v1/signtx", post(signtx_handler))
        .with_state(state);

    let addr = format!("{}:{}", cli.host, cli.port);
    eprintln!("sign offline-signer listening on http://{addr}  (loopback only, no auth)");
    eprintln!("  GET  /v1/getprikey?chaintype=eth");
    eprintln!("  POST /v1/signtx  body: {{chaintype, txdatahex, fromaddress}}");
    eprintln!("  GET  /v1/chains");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// 根路径：返回简短说明。
async fn root_handler() -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "service": "sign offline-signer",
            "endpoints": ["GET /v1/getprikey", "POST /v1/signtx", "GET /v1/chains"],
            "supported_chains": ["eth", "sol", "near", "apt", "sui", "ton"],
            "warning": "loopback-only, no auth; keys live in process memory and are lost on exit"
        })),
    )
        .into_response()
}

/// `GET /v1/chains`：能力清单。
async fn chains_handler() -> Response {
    let chains: Vec<Value> = ["eth", "sol", "near", "apt", "sui", "ton"]
        .iter()
        .map(|c| {
            json!({
                "chain": c,
                "scheme": if *c == "eth" { "secp256k1" } else { "ed25519" },
                "signed_tx_encoding": if *c == "sol" || *c == "sui" { "base64" } else { "hex" },
                "assembles_full_tx": *c != "ton"
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "chains": chains, "count": chains.len() }))).into_response()
}

/// `GET /v1/getprikey`：生成密钥对并存入内存。
async fn getprikey_handler(
    State(state): State<AppState>,
    Query(params): Query<GetPriKeyParams>,
) -> Response {
    let started = Instant::now();
    if !keys::is_supported(&params.chaintype) {
        return err(
            ErrorCode::Unsupported,
            &format!("不支持的链: {}（可选 eth / sol / near / apt / sui / ton）", params.chaintype),
            started,
        );
    }
    match keys::generate(&params.chaintype) {
        Ok(info) => {
            state.store.insert(&info.address, keys::to_stored(&info));
            let data = json!({
                "chain": info.chain,
                "scheme": scheme_str(info.scheme),
                "address": info.address,
                "private_key": info.private_key,
                "public_key": info.public_key,
            });
            ok(data, started)
        }
        Err(e) => err(ErrorCode::Internal, &e.to_string(), started),
    }
}

/// `POST /v1/signtx`：按地址取密钥，签名并组装交易。
async fn signtx_handler(
    State(state): State<AppState>,
    JsonExtractor(body): JsonExtractor<SignBody>,
) -> Response {
    let started = Instant::now();
    if !keys::is_supported(&body.chaintype) {
        return err(
            ErrorCode::Unsupported,
            &format!("不支持的链: {}（可选 eth / sol / near / apt / sui / ton）", body.chaintype),
            started,
        );
    }
    let txdata = match hex::decode(strip_0x(&body.txdatahex)) {
        Ok(b) => b,
        Err(e) => {
            return err(
                ErrorCode::InvalidArgument,
                &format!("txdatahex 解码失败（需 hex，可带 0x 前缀）: {e}"),
                started,
            )
        }
    };
    let key = match state.store.get(&body.fromaddress) {
        Some(k) => k,
        None => {
            return err(
                ErrorCode::InvalidArgument,
                &format!(
                    "地址 {} 不在内存密钥库；请先调用 GET /v1/getprikey?chaintype={} 在本进程生成",
                    body.fromaddress, body.chaintype
                ),
                started,
            )
        }
    };
    match sign::sign(&body.chaintype, &txdata, &key).await {
        Ok(r) => {
            let data = json!({
                "chain": body.chaintype,
                "from_address": body.fromaddress,
                "scheme": scheme_str(key.scheme),
                "signature": r.signature,
                "signed_tx": r.signed_tx,
                "encoding": r.encoding,
                "note": r.note,
            });
            ok(data, started)
        }
        Err(e) => err(ErrorCode::Internal, &e.to_string(), started),
    }
}

/// 把 `0x` / `0X` 前缀剥掉（无前缀原样返回）。
fn strip_0x(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        rest
    } else {
        s
    }
}

/// 算法族转字符串。
fn scheme_str(s: Scheme) -> &'static str {
    match s {
        Scheme::Secp256k1 => "secp256k1",
        Scheme::Ed25519 => "ed25519",
    }
}

/// 成功信封 → (200, JSON)。
fn ok(data: Value, started: Instant) -> Response {
    let env: Envelope<Value> =
        Envelope::ok("sign", "offline", started.elapsed().as_millis() as u64, data);
    (StatusCode::OK, Json(env.to_value().unwrap_or(Value::Null))).into_response()
}

/// 失败信封 → (按错误码选状态码, JSON)。
fn err(code: ErrorCode, msg: &str, started: Instant) -> Response {
    let status = match code {
        ErrorCode::InvalidArgument => StatusCode::BAD_REQUEST,
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::Unsupported => StatusCode::NOT_IMPLEMENTED,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let env: Envelope<()> = Envelope::err(
        "sign",
        "offline",
        started.elapsed().as_millis() as u64,
        SdkError::new(code, msg.to_string()),
    );
    (status, Json(env.to_value().unwrap_or(Value::Null))).into_response()
}
