//! 本地 HTTP 服务：任何能发 HTTP 的 agent / 程序都能调用。
//!
//! 端点与 CLI、MCP 返回完全一致的信封结构。

use axum::{
    Router,
    extract::{Json as JsonExtractor, Query},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::Value;

use crate::dispatch::{self, Action};

/// `chain` 与连接参数，所有查询端点共用。
#[derive(Debug, Deserialize)]
struct BaseParams {
    chain: String,
    network: Option<String>,
    rpc_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BalanceParams {
    #[serde(flatten)]
    base: BaseParams,
    address: String,
}

#[derive(Debug, Deserialize)]
struct BlockParams {
    #[serde(flatten)]
    base: BaseParams,
    reference: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TxParams {
    #[serde(flatten)]
    base: BaseParams,
    hash: String,
}

#[derive(Debug, Deserialize)]
struct AddressFromPubkeyParams {
    #[serde(flatten)]
    base: BaseParams,
    pubkey: String,
}

/// 转账请求体。私钥等敏感字段放 body 而非 query，避免进访问日志。
#[derive(Debug, Deserialize)]
struct TransferBody {
    chain: String,
    network: Option<String>,
    rpc_url: Option<String>,
    to: String,
    amount: String,
    private_key: Option<String>,
    #[serde(default)]
    dry_run: bool,
    from: Option<String>,
}

pub async fn serve(host: String, port: u16) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/v1/chains", get(chains_handler))
        .route("/v1/status", get(status_handler))
        .route("/v1/balance", get(balance_handler))
        .route("/v1/getbalance", get(balance_handler))
        .route("/v1/block", get(block_handler))
        .route("/v1/tx", get(tx_handler))
        .route("/v1/address-from-pubkey", get(address_from_pubkey_handler))
        .route("/v1/transfer", post(transfer_handler));

    let addr = format!("{host}:{port}");
    // 提示信息走 stderr，stdout 保持干净以便管道消费。
    eprintln!("acli http listening on http://{addr}");
    eprintln!("  GET /v1/chains");
    eprintln!("  GET /v1/status?chain=btc[&network=mainnet][&rpc_url=...]");
    eprintln!("  GET /v1/balance?chain=eth&address=0x...");
    eprintln!("  GET /v1/getbalance?chain=eth&address=0x...   # balance 的别名");
    eprintln!("  GET /v1/block?chain=sol&reference=<slot>");
    eprintln!("  GET /v1/tx?chain=near&hash=<tx_hash>@<sender.near>");
    eprintln!("  GET /v1/address-from-pubkey?chain=eth&pubkey=<64B 十六进制公钥>");
    eprintln!(
        "  POST /v1/transfer   body: {{chain,to,amount,private_key?,dry_run?,from?,network?,rpc_url?}}"
    );

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn chains_handler() -> Response {
    (StatusCode::OK, Json(dispatch::chain_catalog())).into_response()
}

async fn status_handler(Query(params): Query<BaseParams>) -> Response {
    run(params, Action::Status).await
}

async fn balance_handler(Query(params): Query<BalanceParams>) -> Response {
    run(
        params.base,
        Action::Balance {
            address: params.address,
        },
    )
    .await
}

async fn block_handler(Query(params): Query<BlockParams>) -> Response {
    run(
        params.base,
        Action::Block {
            reference: params.reference,
        },
    )
    .await
}

async fn tx_handler(Query(params): Query<TxParams>) -> Response {
    run(params.base, Action::Tx { hash: params.hash }).await
}

async fn address_from_pubkey_handler(Query(params): Query<AddressFromPubkeyParams>) -> Response {
    run(
        params.base,
        Action::AddressFromPubkey {
            pubkey: params.pubkey,
        },
    )
    .await
}

async fn transfer_handler(JsonExtractor(body): JsonExtractor<TransferBody>) -> Response {
    run(
        BaseParams {
            chain: body.chain,
            network: body.network,
            rpc_url: body.rpc_url,
        },
        Action::Transfer {
            to: body.to,
            amount: body.amount,
            private_key: body.private_key,
            dry_run: body.dry_run,
            from: body.from,
        },
    )
    .await
}

async fn run(params: BaseParams, action: Action) -> Response {
    let chain = match dispatch::parse_chain(&params.chain) {
        Ok(chain) => chain,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    allchain_core::Envelope::<Value>::err(params.chain.clone(), "default", 0, err)
                        .to_value()
                        .unwrap_or(Value::Null),
                ),
            )
                .into_response();
        }
    };

    let envelope = dispatch::run_action(
        chain,
        params.network.as_deref(),
        params.rpc_url.as_deref(),
        action,
    )
    .await;

    let status = match &envelope.error {
        None => StatusCode::OK,
        Some(err) => match err.code {
            allchain_core::ErrorCode::InvalidArgument => StatusCode::BAD_REQUEST,
            allchain_core::ErrorCode::NotFound => StatusCode::NOT_FOUND,
            allchain_core::ErrorCode::NetworkError | allchain_core::ErrorCode::RpcError => {
                StatusCode::BAD_GATEWAY
            }
            allchain_core::ErrorCode::Unsupported => StatusCode::NOT_IMPLEMENTED,
            allchain_core::ErrorCode::ParseError | allchain_core::ErrorCode::Internal => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        },
    };

    (status, Json(envelope.to_value().unwrap_or(Value::Null))).into_response()
}
