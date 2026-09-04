//! 本地 HTTP 服务：任何能发 HTTP 的 agent / 程序都能调用。
//!
//! 端点与 CLI、MCP 返回完全一致的信封结构。
//!
//! 本模块只做三件事：把 HTTP 查询参数 / body 映射成 [`dispatch::Action`]、
//! 调用 dispatch、把 `error.code` 映射成合适的 HTTP 状态码。
//! 任何链相关的逻辑都不在这里——那属于 dispatch 与各自的链 crate。
//!
//! 关于 `ErrorCode -> HTTP 状态码` 的映射（见 [`run`]）：
//! 状态码是给**通用 HTTP 客户端**看的粗粒度信号——它不认识我们的错误码，
//! 但认识 400 / 404 / 502；而信封里的 `error.code` 才是给 agent 看的细粒度原因。
//! 两者并存、各司其职，不因为有了状态码就省略信封里的错误体。

// axum 的类型：`Router` 是路由表，`extract::{Query, Json}` 是**提取器（extractor）**，
// `response::{IntoResponse, Json as .., Response}` 是响应侧的类型。
use axum::{
    Router,
    extract::{Json as JsonExtractor, Query},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
};
// `Deserialize` 是 serde 的**反序列化**派生宏：把 query string / JSON body
// 直接解析成下面的结构体，字段缺失或类型不符时 axum 会自动返回 400。
use serde::Deserialize;
use serde_json::Value;

use crate::dispatch::{self, Action};

/// `chain` 与连接参数，所有查询端点共用。
///
/// 与 CLI 的 `ChainArgs` 是同一个概念的两种载体：那边来自命令行，这边来自 query string。
///
/// 语法说明：`#[derive(Deserialize)]` 让 serde 能从 key-value 形式的数据（axum 的 `Query`
/// 用的就是 `serde_urlencoded`）直接构造本结构体。
/// `Option<String>` 字段表示**可缺省**；`String` 字段（如 `chain`）缺失时会直接反序列化失败，
/// 由 axum 返回 400——也就是说「必填校验」不需要我们自己写。
#[derive(Debug, Deserialize)]
struct BaseParams {
    chain: String,
    network: Option<String>,
    rpc_url: Option<String>,
}

/// `balance` 端点参数：`BaseParams` 之外再加一个 `address`。
///
/// 语法说明：`#[serde(flatten)]` 把 `base` 的字段**平铺**到同一层级：
/// 客户端写的是 `?chain=eth&address=0x..`，而不是 `?base.chain=eth&address=0x..`。
/// 代价是 serde 解析 flatten 时需要缓冲，性能略低——对查询参数这种小结构可以忽略。
#[derive(Debug, Deserialize)]
struct BalanceParams {
    #[serde(flatten)]
    base: BaseParams,
    address: String,
}

/// `block/by-height` 端点参数：高度是数字，clap/serde 反序列化即校验类型。
#[derive(Debug, Deserialize)]
struct BlockByHeightParams {
    #[serde(flatten)]
    base: BaseParams,
    height: u64,
}

/// `tx` 端点参数。
#[derive(Debug, Deserialize)]
struct TxParams {
    #[serde(flatten)]
    base: BaseParams,
    hash: String,
}

/// `address-from-pubkey` 端点参数。
#[derive(Debug, Deserialize)]
struct AddressFromPubkeyParams {
    #[serde(flatten)]
    base: BaseParams,
    pubkey: String,
}

/// 转账请求体。私钥等敏感字段放 body 而非 query，避免进访问日志。
///
/// 这是本项目里**唯一**接受写操作的端点，两个额外约束：
/// 1. 只注册了 `POST`——GET 请求天然 405，避免被爬虫或预加载器误触；
/// 2. 私钥放在 body 里而不是 URL 上：query string 会被 nginx / 浏览器历史 /
///    各类访问日志原样记下来，body 通常不会。
///
/// `#[serde(default)]` 表示 `dry_run` 缺省时取 `bool::default()`（即 `false`）；
/// 没有它，客户端少传这个字段就会 400。
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

/// `GET /v1/build-transfer` 参数：无私钥构造转账（两段式第一阶段）。
///
/// 用 **GET** 而不是 POST 是刻意的：本端点只读取链上状态（nonce / gas / blockhash /
/// UTXO）并在本地组装交易，**既不广播也不接触私钥**，没有任何副作用，符合 GET 的语义。
#[derive(Debug, Deserialize)]
struct BuildTransferParams {
    #[serde(flatten)]
    base: BaseParams,
    /// 付款地址/账户；必填，因为没有私钥可供推导。
    from: String,
    to: String,
    amount: String,
    /// 签名公钥；NEAR / APT 等多密钥账户需要，AR 必填。
    public_key: Option<String>,
}

/// `POST /v1/submit-tx` 请求体：广播已签名交易（两段式第二阶段）。
///
/// 与 `TransferBody` 同样刻意**扁平**：客户端直接按字段名 POST，不必多嵌一层。
/// 注意这里**没有任何私钥字段**——第二阶段只接收签完名的字节。
#[derive(Debug, Deserialize)]
struct SubmitTxBody {
    chain: String,
    network: Option<String>,
    rpc_url: Option<String>,
    /// 已签名交易的十六进制（`encoding` 为 `base64` 时是 base64 串）。
    signed_tx_hex: String,
    /// 编码：`hex`（缺省）或 `base64`。
    encoding: Option<String>,
    /// 构造阶段下发的上下文，**原样回传**（TON 的 cell 树需要）。
    context: Option<Value>,
    /// 签名列表（BTC 多输入场景），顺序须与构造阶段下发的待签对象一致。
    signatures: Option<Vec<String>>,
}

/// 启动 HTTP 服务并**一直阻塞**直到进程被终止。
///
/// 语法说明：参数写成 `host: String` / `port: u16` 而不是引用，
/// 是因为这个 `async fn` 会长期存活；把所有权收进来，
/// 调用方就不必保证某个借用在服务运行期间始终有效（借用检查器也不会允许）。
pub async fn serve(host: String, port: u16) -> anyhow::Result<()> {
    // axum 的路由表是**不可变链式构造**：每个 `.route(..)` 返回新的 `Router`，
    // 因此要重新绑定给 `app`。`get(..)` / `post(..)` 是 `MethodRouter` 的构造器，
    // 把「哪个方法」与「哪个 handler」绑在一起。
    let app = Router::new()
        .route("/v1/chains", get(chains_handler))
        .route("/v1/status", get(status_handler))
        .route("/v1/balance", get(balance_handler))
        // 兼容旧路径：`/v1/getbalance` 与 `/v1/balance` 指向**同一个 handler**，
        // 这样老客户端不用改代码，也不会出现两份实现慢慢跑偏。
        .route("/v1/getbalance", get(balance_handler))
        .route("/v1/block/height", get(block_height_handler))
        .route("/v1/block/by-height", get(block_by_height_handler))
        .route("/v1/tx", get(tx_handler))
        .route("/v1/address-from-pubkey", get(address_from_pubkey_handler))
        // 写操作只挂在 POST 上。
        .route("/v1/transfer", post(transfer_handler))
        // 两段式的两个端点。构造走 GET：它只读取链上状态并在本地组装，
        // 既不广播也不接触私钥，没有副作用；广播走 POST。
        .route("/v1/build-transfer", get(build_transfer_handler))
        .route("/v1/submit-tx", post(submit_tx_handler));

    // `format!("{host}:{port}")` 是内联格式化捕获：大括号里写变量名即可，
    // 等价于 `format!("{}:{}", host, port)`。
    let addr = format!("{host}:{port}");
    // 提示信息走 stderr，stdout 保持干净以便管道消费。
    eprintln!("acli http listening on http://{addr}");
    eprintln!("  GET /v1/chains");
    eprintln!("  GET /v1/status?chain=btc[&network=mainnet][&rpc_url=...]");
    eprintln!("  GET /v1/balance?chain=eth&address=0x...");
    eprintln!("  GET /v1/getbalance?chain=eth&address=0x...   # balance 的别名");
    eprintln!("  GET /v1/block/height?chain=eth        # 链头高度");
    eprintln!("  GET /v1/block/by-height?chain=eth&height=19000000");
    eprintln!("  GET /v1/tx?chain=near&hash=<tx_hash>@<sender.near>");
    eprintln!("  GET /v1/address-from-pubkey?chain=eth&pubkey=<64B 十六进制公钥>");
    eprintln!(
        "  POST /v1/transfer   body: {{chain,to,amount,private_key?,dry_run?,from?,network?,rpc_url?}}"
    );
    eprintln!("  GET /v1/build-transfer?chain=eth&from=0x..&to=0x..&amount=0.01[&public_key=..]");
    eprintln!("  POST /v1/submit-tx   body: {{chain,signed_tx_hex,encoding?,context?,signatures?}}");

    // 先 `bind` 再 `serve`：分开写的好处是绑定失败（端口被占用）会以 `Err` 提前返回，
    // 由 main 里的 `?` 转给 anyhow 打印，而不是在 axum 内部 panic。
    // `&addr` 传引用：`bind` 只需要读这个地址。
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    // 这里会**一直 await** 到进程收到终止信号；正常路径永不返回。
    axum::serve(listener, app).await?;
    Ok(())
}

/// `GET /v1/chains`：能力清单，纯本地计算，不会失败，故固定 200。
///
/// 语法说明：返回值写 `Response` 而不是具体的 JSON 类型，是为了让**所有 handler 签名一致**，
/// 便于统一走下面的 `run(..)`；`Response` 是一个装箱的动态类型，能装下任何实现了
/// `IntoResponse` 的东西。
///
/// `(StatusCode::OK, Json(..))` 是一个**元组**，axum 为它实现了 `IntoResponse`：
/// 第一个元素是状态码，第二个是响应体。最后的 `.into_response()` 把它转成 `Response`。
async fn chains_handler() -> Response {
    (StatusCode::OK, Json(dispatch::chain_catalog())).into_response()
}

/// `GET /v1/status`
///
/// 语法说明：`Query(params): Query<BaseParams>` 是**带模式的解构参数**——
/// axum 的 handler 参数都必须是「提取器」，`Query<T>` 从 URL 查询串提取，
/// 外面再套一层模式 `Query(params)` 把内部值取出来。
/// 提取失败（缺 `chain`、类型不符）时 axum 会**在 handler 被调用之前**直接返回 400，
/// 所以我们拿到的 `params` 一定是合法的。
async fn status_handler(Query(params): Query<BaseParams>) -> Response {
    // `.await` 推进异步执行；`run` 内部会调用 dispatch 完成真正的查询。
    run(params, Action::Status).await
}

/// `GET /v1/balance`（与 `/v1/getbalance` 共用）。
async fn balance_handler(Query(params): Query<BalanceParams>) -> Response {
    // 把 flatten 进来的 `base` 与专属字段拆开，各自交给 dispatch：
    // `params.base` 是**按所有权移动**（`params` 之后不可再用），
    // `params.address` 同理被移进 `Action::Balance`。
    run(
        params.base,
        Action::Balance {
            address: params.address,
        },
    )
    .await
}

/// `GET /v1/block/height`：链头高度（最新区块高度）。
async fn block_height_handler(Query(params): Query<BaseParams>) -> Response {
    run(params, Action::LastBlockHeight).await
}

/// `GET /v1/block/by-height?height=N`：按高度查询区块。
async fn block_by_height_handler(Query(params): Query<BlockByHeightParams>) -> Response {
    run(
        params.base,
        Action::BlockByHeight {
            height: params.height,
        },
    )
    .await
}

/// `GET /v1/tx`
async fn tx_handler(Query(params): Query<TxParams>) -> Response {
    run(params.base, Action::Tx { hash: params.hash }).await
}

/// `GET /v1/address-from-pubkey`
async fn address_from_pubkey_handler(Query(params): Query<AddressFromPubkeyParams>) -> Response {
    run(
        params.base,
        Action::AddressFromPubkey {
            pubkey: params.pubkey,
        },
    )
    .await
}

/// `POST /v1/transfer`
///
/// 语法说明：`JsonExtractor<TransferBody>` 从**请求体**解析 JSON（这就是它被
/// `use ... as JsonExtractor` 重命名引入的原因——避免与响应侧的 `Json` 撞名）。
/// body 解析失败或 `Content-Type` 不对时，axum 同样在进入 handler 前就返回 400 / 415。
async fn transfer_handler(JsonExtractor(body): JsonExtractor<TransferBody>) -> Response {
    // 手动重组一个 `BaseParams`：body 是扁平的，没有用 `#[serde(flatten)]`，
    // 这样客户端直接按字段名 POST 即可，不必多嵌一层 `base`。
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

/// `GET /v1/build-transfer`：无私钥构造转账（两段式第一阶段）。
///
/// 返回 `unsigned_tx_hex` + `signing_payload_hex` + 签名算法标识，
/// 以及需要原样回传的 `extra.submit_context`。全程不接触私钥。
async fn build_transfer_handler(Query(params): Query<BuildTransferParams>) -> Response {
    run(
        params.base,
        Action::BuildTransfer {
            from: params.from,
            to: params.to,
            amount: params.amount,
            public_key: params.public_key,
        },
    )
    .await
}

/// `POST /v1/submit-tx`：广播已签名交易（两段式第二阶段）。
async fn submit_tx_handler(JsonExtractor(body): JsonExtractor<SubmitTxBody>) -> Response {
    // 与 `transfer_handler` 同样的重组：body 是扁平的，手动拼出 `BaseParams`。
    run(
        BaseParams {
            chain: body.chain,
            network: body.network,
            rpc_url: body.rpc_url,
        },
        Action::SubmitTx {
            signed_tx_hex: body.signed_tx_hex,
            encoding: body.encoding,
            context: body.context,
            signatures: body.signatures,
        },
    )
    .await
}

/// 所有查询端点的公共出口：解析链 -> 调 dispatch -> 选状态码 -> 出响应。
///
/// 与 CLI 的 `run`、MCP 的 `execute` 是同一层的三个孪生实现，
/// 差别只在「错误怎么表达」：这里用 HTTP 状态码，那边用退出码 / `isError`。
async fn run(params: BaseParams, action: Action) -> Response {
    let chain = match dispatch::parse_chain(&params.chain) {
        Ok(chain) => chain,
        Err(err) => {
            // 链标识非法时，适配器还建不起来，只能手工包一个信封返回 400。
            // `params.chain.clone()` 而不是直接移动：`params` 后面还要取
            // `network` / `rpc_url`，克隆一行搞定，省得依赖「部分移动」的细粒度推理。
            // （链式调用是 `&params.chain` 借用在前、克隆在后，NLL 下顺序是安全的。）
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    // `Envelope::<Value>::err` 的 `::<Value>` 是 turbofish：
                    // 没有 `data` 可推断泛型参数 T，必须显式指定。
                    // `.to_value()` 返回 `Result`，`.unwrap_or(Value::Null)` 兜底：
                    // 序列化这种简单结构不会失败，但也不该让一次 400 变成 500。
                    allchain_core::Envelope::<Value>::err(params.chain.clone(), "default", 0, err)
                        .to_value()
                        .unwrap_or(Value::Null),
                ),
            )
                .into_response();
        }
    };

    // `as_deref()` 把 `Option<String>` 借成 `Option<&str>`：只读不转移所有权。
    let envelope = dispatch::run_action(
        chain,
        params.network.as_deref(),
        params.rpc_url.as_deref(),
        action,
    )
    .await;

    // ── ErrorCode -> HTTP 状态码 ────────────────────────────────────────────
    // 映射原则：**按「这是谁的锅」分档，而不是按链分档**。
    // 调用方（含各类 HTTP 客户端、网关、重试中间件）只看得懂状态码，
    // 所以必须让状态码传达「该不该重试、该找谁」；具体原因仍在信封的 `error.code` 里。
    //
    //   400 INVALID_ARGUMENT  —— 请求本身有问题（地址/哈希/金额格式错、缺参数）。
    //                            重试毫无意义，必须改请求，故 400 而非 5xx。
    //   404 NOT_FOUND         —— 语法没问题，但目标不存在（账户未创建、交易/区块查不到）。
    //                            用 404 而不是 200 + 空数据，是为了让 CDN / 网关
    //                            和调用方的缓存逻辑能正确区分「查到了空」与「不存在」。
    //   502 NETWORK/RPC       —— 我们作为网关去访问上游节点，是上游出了问题。
    //                            选 502（Bad Gateway）而不是 500，因为本服务本身是健康的，
    //                            故障在下游节点；这也提示调用方可以重试
    //                            （`retryable` 对这两类正好为 true）。
    //   501 UNSUPPORTED       —— 该链没有这项能力（如给 TON 发转账）。
    //                            用 501（Not Implemented）而不是 400：请求格式完全合法，
    //                            只是这条链暂未支持，将来可能支持；
    //                            语义上「未实现」比「请求错」准确得多。
    //   500 PARSE/INTERNAL    —— 上游返回了我们解析不了的结构，或内部逻辑异常。
    //                            这不是调用方的锅，但重试通常也无济于事，归为服务端错误。
    //
    // 注意：无论状态码是多少，**响应体永远是完整信封**，
    // 成功的响应体与 CLI 打印的 JSON 逐字节一致。
    let status = match &envelope.error {
        // 借用 `&envelope.error` 而不是移动它：下面还要整体序列化 `envelope`。
        None => StatusCode::OK,
        Some(err) => match err.code {
            allchain_core::ErrorCode::InvalidArgument => StatusCode::BAD_REQUEST,
            allchain_core::ErrorCode::NotFound => StatusCode::NOT_FOUND,
            // 用 `|` 在一个分支里匹配两个变体，避免重复写同样的右值。
            allchain_core::ErrorCode::NetworkError | allchain_core::ErrorCode::RpcError => {
                StatusCode::BAD_GATEWAY
            }
            allchain_core::ErrorCode::Unsupported => StatusCode::NOT_IMPLEMENTED,
            allchain_core::ErrorCode::ParseError | allchain_core::ErrorCode::Internal => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            // 这里没有 `_ =>` 兜底分支，是**故意的**：
            // 将来给 `ErrorCode` 加新变体时，穷尽性检查会直接编译失败，
            // 逼我们明确新错误码该对应哪个状态码，而不是悄悄落进某个默认值。
        },
    };

    // 状态码 + 信封一起返回。`.into_response()` 把元组转成 axum 的 `Response`。
    (status, Json(envelope.to_value().unwrap_or(Value::Null))).into_response()
}
