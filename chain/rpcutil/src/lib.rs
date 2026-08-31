//! 新链适配器共用的极简 HTTP 工具：REST GET、JSON-RPC 2.0 POST、GraphQL POST。
//!
//! 设计目标：
//! - 只依赖 reqwest，不绑定任何一条链的官方 SDK，避免六条链各自拖入一棵依赖树；
//! - 上游错误在这一层就归类为统一的 [`SdkError`]，适配器只关心字段提取；
//! - 响应统一先反序列化为 `serde_json::Value`，由各适配器按链上真实结构取字段，
//!   这样上游字段微调时不需要维护一大批镜像结构体。
//!
//! 调用方约定（各链适配器都必须遵守，否则行为会悄悄跑偏）：
//! - `Http` 本身**不含链知识**：它只认 URL、方法名和 JSON 结构，不认 FIL / SUI / TON；
//! - 所有失败都返回 `SdkError`，且 `code` 已经归好类，适配器**不要**再包一层文案转换；
//! - 本层**不做重试**。重试策略（是否重试、退避多久）属于上层决策，工具层只保证
//!   把 `retryable` 标出来；
//! - 数值要一律走 [`loose_u64`] / [`loose_u128`]，不要自己 `as_u64()`——各链把数字
//!   写成 JSON number、十进制字符串还是 `0x` 十六进制字符串并不统一。

// `AtomicU64` 是**原子**整数：多线程并发读写也不会数据竞争。
// `Ordering` 是内存序参数，描述「本线程的操作与其它线程看到它的顺序之间允许多少重排」。
use std::sync::atomic::{AtomicU64, Ordering};
// `Duration` 用于表达超时长度，避免各处裸写秒数导致单位不一致。
use std::time::Duration;

// `allchain_core` 是跨链契约层：错误码与错误载体都从这里来，
// 这样六条链适配器的报错对上层是同一套 shape。
use allchain_core::{ErrorCode, SdkError};
// `Value` 是 serde_json 的「任意 JSON 值」枚举（Null/Bool/Number/String/Array/Object）。
// 用它做中间表示，适配器就不必为每种响应都定义结构体。
use serde_json::Value;

/// 单请求整体超时：从发出到读完整响应体的上限。
///
/// 之所以设得比较宽（25 秒）：Filecoin 的 `StateSearchMsg`、toncenter 的
/// `getBlockTransactions` 这类接口在公共节点上本来就慢，超时设短了会大面积误报。
///
/// 语法说明：`const` 项的类型必须**显式写出**，且值必须在编译期可求值。
/// `Duration::from_secs` 是 `const fn`（可在编译期执行的函数），所以这里合法。
const TIMEOUT: Duration = Duration::from_secs(25);
/// 建连超时：只覆盖 TCP/TLS 握手，与整体超时分开设是为了快速失败——
/// 端点写错时应当立刻报 `NETWORK_ERROR`，而不是让用户干等 25 秒。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// User-Agent。各链公共节点普遍按 UA 做限流与统计，带上版本号便于出问题时溯源。
///
/// 语法说明：这里嵌套了两个**编译期宏**：
/// - `env!("CARGO_PKG_VERSION")` 在编译期读取 `Cargo.toml` 的 `version` 字段，
///   展开成一个 `&'static str` 字面量（读不到会**编译失败**，这是刻意的保护）；
/// - `concat!(...)` 把若干字面量在编译期拼成一个。
///   二者结合，版本号就被**烧进二进制**，运行期零开销。
const USER_AGENT: &str = concat!("allchain-sdk/", env!("CARGO_PKG_VERSION"));

/// 一个绑定了 base URL 的 HTTP 客户端，可廉价克隆（内部 `Arc`）。
///
/// 「廉价克隆」的两层含义：
/// - `reqwest::Client` 内部用 `Arc` 持有连接池与 TLS 配置，`clone()` 只复制指针，
///   更重要的是**连接池被所有克隆共享**——这正是官方推荐复用同一个 Client 的原因
///   （每次新建 Client 都要重新建连、重新协商 TLS，慢且浪费）；
/// - `next_id` 是 `Arc<AtomicU64>`，因此**所有克隆共享同一个 JSON-RPC id 计数器**，
///   即使把客户端并发分发到多个任务，id 也不会撞车。
///
/// 语法说明：`#[derive(Clone)]` 生成 `fn clone(&self) -> Self`。
/// 这里能派生成功，是因为三个字段（`String` / `reqwest::Client` / `Arc<AtomicU64>`）
/// 都各自实现了 `Clone`；其中 `String` 是真拷贝，后两者只是引用计数 +1。
#[derive(Clone)]
pub struct Http {
    /// 基础地址，构造时已去掉末尾的 `/`。
    base: String,
    /// 复用的 reqwest 客户端（内部持有连接池）。
    client: reqwest::Client,
    /// JSON-RPC 的 `id` 自增计数器，所有克隆共享。
    ///
    /// 为什么需要它：JSON-RPC 2.0 要求每个请求带一个 `id`，响应用它做配对。
    /// 用 `Arc<AtomicU64>` 而非 `&mut self` 是为了在 `&self` 方法里也能自增——
    /// `&self` 拿不到可变访问，而原子量通过**内部可变性**（interior mutability）
    /// 绕开了这条限制，这在只读接口里是常用手法。
    next_id: std::sync::Arc<AtomicU64>,
}

impl Http {
    /// 构造客户端；`base` 末尾的 `/` 会被去掉，方便和 `path` 直接拼接。
    ///
    /// 归一化只处理**末尾**的斜杠：各链适配器传进来的 `path` 一律以 `/` 开头
    /// （如 `/getMasterchainInfo`），这样两侧约定一固定，就不会拼出
    /// `https://host//api` 这种双斜杠（不少网关会把它判成 404）。
    ///
    /// 语法说明：这里用的是 **builder 模式**——`reqwest::Client::builder()`
    /// 返回一个可链式配置的 `ClientBuilder`，最后 `.build()` 收尾。
    /// Rust 里凡是有大量可选参数的配置型 API 都爱用这套写法，
    /// 因为语言本身没有「默认参数」，靠 builder 替代。
    pub fn new(base: &str) -> Result<Self, SdkError> {
        // 整条链上的 `.await` 说明这是异步代码：`.send()` 会在等待网络时让出线程，
        // 而不会阻塞整个线程池。注意 `Client::builder().build()` 本身是同步的，
        // 只有下面真正发请求的 `send()` 才是异步。
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            // `build()` 返回 `Result<Client, reqwest::Error>`：
            // `map_err(闭包)` 保留 `Err` 这一分支、替换其中的错误值，
            // 把 reqwest 的错误类型统一翻译成 SDK 的 `SdkError`。
            // 失败原因通常是 TLS 后端初始化失败，属于内部问题，故用 `Internal`。
            .map_err(|e| {
                SdkError::new(ErrorCode::Internal, format!("构造 HTTP 客户端失败: {e}"))
            })?; // `?` 是错误传播运算符：Err 时**立即提前返回**，Ok 时把里面的值解出来。
        // `Ok(Self { .. })` 包成 `Result`。
        // 字段初始化简写：`client` 等价于 `client: client`（变量名与字段名相同）。
        Ok(Self {
            // `trim_end_matches('/')` 去掉**所有**尾部斜杠（不是只去一个），
            // 返回 `&str`；再 `.to_string()` 分配一份自有 `String` 存进结构体。
            base: base.trim_end_matches('/').to_string(),
            client,
            // `Arc::new(..)` 把计数器放上堆并返回引用计数指针，从此可以被多处共享。
            next_id: std::sync::Arc::new(AtomicU64::new(1)),
        })
    }

    /// 实际使用的 base URL，便于适配器把它回显到 [`allchain_core::StatusView::rpc_url`]。
    ///
    /// 语法说明：`&self` 是不可变借用；返回值 `&str` 的生命周期被编译器
    /// 自动绑到 `&self` 上（生命周期省略规则），含义是「这份引用不能活得比 `self` 久」。
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// REST GET，返回原始文本（用于纯文本余额、高度等接口）。
    ///
    /// 注意：本方法**不检查 HTTP 状态码**之外的内容，也不解析 JSON——
    /// 有些链（如 Arweave 网关）会直接返回纯数字文本，强行 `serde_json` 反而会失败。
    ///
    /// 语法说明：`async fn` 声明异步函数，调用它只得到一个 Future，
    /// 必须再 `.await` 才会真正执行；本方法返回 `Result<String, SdkError>`。
    pub async fn get_text(&self, path: &str) -> Result<String, SdkError> {
        // `format!` 宏拼接出完整 URL，返回 `String`。
        let url = format!("{}{}", self.base, path);
        let resp = self
            .client
            // `.get(&url)` 里传 `&String`：Rust 会做**解引用强制转换**（deref coercion）
            // 把 `&String` 自动变成 `&str`，正好匹配参数类型，不必手写 `&url[..]`。
            .get(&url)
            .send()
            .await
            // 发送阶段的失败（DNS、连接拒绝、超时）在这里被翻译成统一错误。
            // 注意与下面 `read_text` 的分工：**传输层**错误在这里，
            // **应用层**（HTTP 状态码）错误在里面。
            .map_err(|e| transport_error(&url, e))?;
        // 拿到 `Response` 后统一交给 `read_text` 读体 + 判状态码。
        read_text(resp, &url).await
    }

    /// REST GET，解析为 JSON 值。
    ///
    /// TON / Aptos 这类走 REST 的链主要用这个方法。
    pub async fn get_value(&self, path: &str) -> Result<Value, SdkError> {
        let url = format!("{}{}", self.base, path);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| transport_error(&url, e))?;
        // 先读成文本再自己 `from_str`，而不是用 reqwest 的 `.json()`：
        // 这样解析失败时手上还有**原文**可以塞进错误信息（下面 `truncate(&body)`），
        // 排查「上游返回了 HTML 错误页」这类问题时这一步能省很多时间。
        let body = read_text(resp, &url).await?;
        // `serde_json::from_str` 的返回类型无法自动推断，靠 `let value: Value` 这类
        // 显式标注（或函数签名）来确定。这里直接交给调用方的 `Result<Value, _>`。
        serde_json::from_str(&body).map_err(|e| {
            SdkError::new(
                ErrorCode::ParseError,
                format!("解析 {url} 的 JSON 失败: {e}; 原文: {}", truncate(&body)),
            )
        })
    }

    /// 发送一次 JSON-RPC 2.0 调用，返回 `result` 字段；上游 `error` 映射为 `RPC_ERROR`。
    ///
    /// 这是 FIL / CKB 这类 JSON-RPC 链的主力方法。调用方约定：
    /// - `params` 由调用方用 `json!(...)` 构造，本层不关心它是数组还是对象
    ///   （Lotus 与 CKB 都用数组，但有的节点要对象，交给适配器决定）；
    /// - HTTP 状态码对 JSON-RPC 而言**几乎总是 200**，业务错误一律在响应体的
    ///   `error` 字段里，所以真正判错必须看 `error`；
    /// - `error` 字段存在但为 `null` 是**正常**的（表示无错误），
    ///   所以判断里必须追加 `!err.is_null()`——只看 `is_some()` 会全量误报；
    /// - 本方法**不区分**「方法不存在」与「节点内部错误」，统一归 `RPC_ERROR`。
    pub async fn jsonrpc(&self, method: &str, params: Value) -> Result<Value, SdkError> {
        // `fetch_add(1, ..)` 是**读-改-写**原子操作：返回旧值并把计数器加一，
        // 两个线程同时调用也绝不会拿到同一个 id。
        // `Ordering::Relaxed` 是最宽松的内存序：只保证这个计数自身的原子性，
        // **不**与其它变量建立 happens-before 关系。对「发号器」这种
        // 只要求唯一、不要求跨变量同步的场景，Relaxed 足够且最快。
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // `json!` 宏用 JSON 字面量语法构造 `Value`：键必须是字符串字面量，
        // 值是任意实现了 `Serialize` 的东西（`&str` / `u64` / `Value` 都可以）。
        // 宏在编译期展开成构造代码，没有运行期解析开销。
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        // JSON-RPC 的端点就是 base 本身（不像 REST 要拼路径），故 clone 一份出来用于报错。
        let url = self.base.clone();
        let resp = self
            .client
            .post(&url)
            // `.json(&payload)` 一次做完两件事：序列化成 JSON 字节，
            // 并自动设置 `Content-Type: application/json` 请求头。
            .json(&payload)
            .send()
            .await
            .map_err(|e| transport_error(&url, e))?;
        let body = read_text(resp, &url).await?;
        // 类型标注 `let value: Value` 是必需的：`from_str` 是泛型函数，
        // 编译器需要知道要反序列化成什么类型。
        let value: Value = serde_json::from_str(&body).map_err(|e| {
            SdkError::new(
                ErrorCode::ParseError,
                format!("解析 {method} 响应失败: {e}; 原文: {}", truncate(&body)),
            )
        })?;
        // 语法说明：这是 **let 链**（let-chain），即 `if let Some(x) = .. && 条件`。
        // 第二个条件只在第一个模式匹配成功后才求值（短路），
        // 因此 `err` 在右侧一定已绑定好。它等价于以前必须写的
        // `if let Some(err) = .. { if !err.is_null() { .. } }` 嵌套。
        if let Some(err) = value.get("error")
            && !err.is_null()
        {
            // 上游 `error` 结构没有统一规范（有的给 `{code,message}`，有的只给字符串），
            // 因此把整个 `err` 按 `Display` 打印后交给文本启发式分类。
            return Err(classify_upstream(&format!("{method} 返回错误: {err}")));
        }
        // `value.get("result")` 返回 `Option<&Value>`（借用）。
        // `.cloned()` 把 `Option<&Value>` 变成 `Option<Value>`——这一步是必需的，
        // 因为要把值**返回出去**，而借用引用在函数结束时就失效了。
        // `.ok_or_else(闭包)`：`Some(v)` → `Ok(v)`；`None` → 调闭包生成 `Err`。
        // 用惰性版 `ok_or_else` 而非 `ok_or`，可避免在成功路径上白跑一次 `format!`。
        value.get("result").cloned().ok_or_else(|| {
            SdkError::new(
                ErrorCode::RpcError,
                format!("{method} 响应缺少 result 字段: {value}"),
            )
        })
    }

    /// 发送一次 GraphQL 查询，返回 `data`；`errors` 非空时映射为 `RPC_ERROR`。
    ///
    /// Sui 官方已下线公共 fullnode 的 JSON-RPC，GraphQL 是唯一官方入口，
    /// 因此这个方法目前主要由 Sui 适配器使用。
    ///
    /// GraphQL 与 JSON-RPC 的三个关键差异，调用方务必留意：
    /// 1. HTTP 状态码**几乎永远**是 200，业务错误放在 `errors` 数组里；
    /// 2. 允许「部分成功」——`data` 与 `errors` 可以**同时**存在
    ///    （某些字段查询失败，其余字段仍有值）。本方法采取保守策略：
    ///    只要 `errors` 非空就整体报错，避免适配器拿到残缺数据还以为成功；
    /// 3. 结果嵌套很深（如 `/address/balance/totalBalance`），
    ///    取值时推荐用 `Value::pointer` 而不是一层层 `get`。
    ///
    /// 语法说明：参数只有 `query` 一个字符串，没有 `variables`。
    /// 各链的查询条件（地址、序号）都靠 `format!` 直接拼进查询文本，
    /// 因此适配器必须自行校验插值内容（见 Sui 适配器的 `validate_address`）。
    pub async fn graphql(&self, query: &str) -> Result<Value, SdkError> {
        let url = self.base.clone();
        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "query": query }))
            .send()
            .await
            .map_err(|e| transport_error(&url, e))?;
        let body = read_text(resp, &url).await?;
        let value: Value = serde_json::from_str(&body).map_err(|e| {
            SdkError::new(
                ErrorCode::ParseError,
                format!("解析 GraphQL 响应失败: {e}; 原文: {}", truncate(&body)),
            )
        })?;
        // 逐段拆解这条判断：
        // - `value.get("errors")`           → `Option<&Value>`
        // - `.filter(闭包)`                  → 保留满足条件的值，否则变 `None`
        // - `!v.is_null()`                  → 排除 `errors: null`
        // - `!v.as_array().is_some_and(..)` → 排除 `errors: []` 空数组
        //   `as_array()` 返回 `Option<&Vec<Value>>`；`is_some_and(闭包)` 是
        //   `Option` 的短路组合子：Some 且闭包为真才返回 true。
        // 两个条件合起来等价于「errors 存在且真的有内容」。
        if let Some(errors) = value
            .get("errors")
            .filter(|v| !v.is_null() && !v.as_array().is_some_and(|a| a.is_empty()))
        {
            return Err(SdkError::new(
                ErrorCode::RpcError,
                format!("GraphQL 返回错误: {errors}"),
            ));
        }
        value
            .get("data")
            .cloned()
            // 这里用常量字符串而非整个响应体：GraphQL 的返回值可能非常大，
            // 塞进 message 会让日志爆掉，缺 data 这一事实本身就够定位了。
            .ok_or_else(|| SdkError::new(ErrorCode::RpcError, "GraphQL 响应缺少 data 字段"))
    }

    /// 发送表单（`application/x-www-form-urlencoded`）POST，解析为 JSON 值。
    ///
    /// 为什么需要它：toncenter 的 `sendBoc` 这类写接口走表单 POST 而非 JSON-RPC，
    /// 但响应同样可能是 `{ok, result}` 信封，适配器复用同一套字段提取即可。
    ///
    /// 语法说明：`params` 是借用的元组切片 `&[(&str, &str)]`——reqwest 的 `.form()`
    /// 要求参数实现 `Serialize`，而 `(&str, &str)` 元组对恰好能序列化成 `k=v&k=v` 表单体。
    pub async fn post_form(&self, path: &str, params: &[(&str, &str)]) -> Result<Value, SdkError> {
        let url = format!("{}{}", self.base, path);
        let resp = self
            .client
            .post(&url)
            .form(params)
            .send()
            .await
            .map_err(|e| transport_error(&url, e))?;
        let body = read_text(resp, &url).await?;
        // 与 `get_value` 同样的策略：自己 `from_str` 以便解析失败时把原文塞进错误。
        serde_json::from_str(&body).map_err(|e| {
            SdkError::new(
                ErrorCode::ParseError,
                format!("解析 {url} 的 JSON 失败: {e}; 原文: {}", truncate(&body)),
            )
        })
    }
}

/// 读取响应体并判定 HTTP 状态码，是 `get_text` / `get_value` / `jsonrpc` / `graphql`
/// 四个方法共用的收尾步骤。
///
/// 关键坑：**必须先读体、再判状态码**。很多网关（Cloudflare、toncenter）返回
/// 4xx/5xx 时会在响应体里放一段 JSON 说明原因（如限流的具体配额），
/// 如果直接 `error_for_status()` 把 body 丢掉，这段信息就永远看不到了。
///
/// 语法说明：`resp` 是**按值**接收的 `reqwest::Response`（不是 `&Response`），
/// 因为 `.text()` 需要消费掉 Response 本身——响应体只能被读取一次。
async fn read_text(resp: reqwest::Response, url: &str) -> Result<String, SdkError> {
    // `.status()` 只是借用读取，可以在消费 body 之前先取出来。
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| SdkError::new(ErrorCode::NetworkError, format!("读取 {url} 响应失败: {e}")))?;
    // `is_success()` 等价于「2xx」。注意 3xx 不算成功——我们从不跟随跨站重定向。
    if status.is_success() {
        return Ok(body);
    }
    // 非 2xx：把响应体裁短后塞进错误信息。
    // `.trim()` 去掉首尾空白（HTML 错误页通常有大量换行与缩进）。
    let snippet = truncate(body.trim());
    // 语法说明：Rust 的 `if / else if / else` 整体是一个**表达式**，
    // 可以求值后直接赋给变量，不需要先 `let mut code;` 再逐个分支赋值。
    let code = if status == reqwest::StatusCode::NOT_FOUND {
        // 404：地址 / 交易 / 区块查不到，是确定性结果，**不可重试**。
        ErrorCode::NotFound
    } else if status == reqwest::StatusCode::BAD_REQUEST
        || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY
    {
        // 400 / 422：请求参数有问题，重试多少次都一样，同样不可重试。
        ErrorCode::InvalidArgument
    } else {
        // 其余（401 / 403 / 429 / 5xx）笼统归为 RpcError。
        // 之所以不单独拆 429：是否重试由上层看 `retryable` 决定，
        // 而 RpcError 与 NetworkError 都标记为可重试，行为上一致。
        ErrorCode::RpcError
    };
    // `{status}` 调用 `StatusCode` 的 `Display`，打印成 `404 Not Found` 这种形式。
    Err(SdkError::new(
        code,
        format!("{url} 返回 HTTP {status}: {snippet}"),
    ))
}

/// 把 reqwest 的传输层错误翻译成统一错误码。
///
/// 与 [`read_text`] 的分工：这里只处理「请求根本没到对方」的情况
/// （连接失败、超时、DNS、TLS 握手）；对端回了什么归那边管。
///
/// 语法说明：参数 `err: reqwest::Error` 按值接收。
/// `reqwest::Error` 内部本身就用 `Box` 包着各类来源（io / hyper / serde），
/// 所以按值传递并不昂贵，而且下面还要多次调用它的判定方法。
fn transport_error(url: &str, err: reqwest::Error) -> SdkError {
    // `is_connect()` / `is_timeout()` 是 reqwest 提供的便利判定，
    // 比自己匹配 `Display` 文本可靠得多。这两类都归 `NetworkError`（可重试）。
    let code = if err.is_connect() || err.is_timeout() {
        ErrorCode::NetworkError
    } else {
        ErrorCode::RpcError
    };
    SdkError::new(code, format!("请求 {url} 失败: {err}"))
}

/// 上游错误文本启发式分类（与 core::error::classify 同思路，避免循环依赖）。
///
/// 为什么这里要**重复**一份而不用 `allchain_core::classify`：
/// 本 crate 依赖 core，core 不能反向依赖本 crate（否则形成依赖环，Cargo 会直接拒绝）。
/// 而上层的 `classify` 不认识 JSON-RPC 里 `not_found` 这类蛇形关键词，
/// 所以就地补一份轻量版本。
///
/// 注意这是**顺序敏感**的 if-else 链：NotFound 优先于 InvalidArgument。
/// 一条同时含 "not found" 与 "invalid" 的错误会被判成 NotFound。
///
/// 之所以看 `not_found`（下划线）而不只是 `not found`：Lotus / CKB 的 error message
/// 里大量使用蛇形标识符，两种写法都得覆盖。
fn classify_upstream(text: &str) -> SdkError {
    // `to_ascii_lowercase()` 只处理 ASCII，比 `to_lowercase()`（含 Unicode 转换）更快，
    // 且不会改变字符串长度；错误文本里的关键词都是英文，完全够用。
    let lower = text.to_ascii_lowercase();
    let code = if lower.contains("not found")
        || lower.contains("not_found")
        || lower.contains("does not exist")
    {
        ErrorCode::NotFound
    } else if lower.contains("invalid") || lower.contains("parse") || lower.contains("malformed") {
        ErrorCode::InvalidArgument
    } else {
        ErrorCode::RpcError
    };
    // 原文整体保留为 message，避免排查时丢失上下文。
    SdkError::new(code, text)
}

/// 把任意长文本裁到 300 字符，用于把响应体片段塞进错误信息。
///
/// 截断的必要性：上游可能返回几 MB 的 HTML 错误页，原样塞进 message 会让日志爆掉。
fn truncate(text: &str) -> String {
    // 函数内的 `const`：作用域仅限本函数，是最贴近使用点的常量定义方式。
    const MAX: usize = 300;
    // 语法说明：这里用 `chars().count()`（字符数）而不是 `text.len()`（字节数）。
    // 中文一个字符占 3 字节，用 `len()` 会让中文文本被截得远短于预期。
    if text.chars().count() <= MAX {
        text.to_string()
    } else {
        // 更重要的是：不能直接写 `&text[..MAX]` 切片。
        // `&str` 的切片按**字节**索引，且必须落在 UTF-8 字符边界上，否则直接 panic。
        // `chars().take(MAX)` 逐字符取，天然安全。
        // `collect::<String>()` 用 turbofish 语法显式指定收集目标类型。
        format!("{}...", text.chars().take(MAX).collect::<String>())
    }
}

// ---------------------------------------------------------------------------
// 值提取工具：各链数字可能是 JSON number、十进制字符串或 `0x` 十六进制字符串。
// ---------------------------------------------------------------------------

/// 从 JSON 值取 `field` 字段并解析为 u64，字段缺失时报明确错误。
///
/// 与直接用 `.get(field)` 相比，这里的价值在于**错误信息统一**：
/// 缺字段时报 `PARSE_ERROR` 并附上整个 value，一眼能看出上游结构变了。
pub fn field_u64(value: &Value, field: &str) -> Result<u64, SdkError> {
    let v = value.get(field).ok_or_else(|| {
        SdkError::new(
            ErrorCode::ParseError,
            format!("响应缺少字段 `{field}`: {value}"),
        )
    })?;
    loose_u64(v)
}

/// 宽松解析 u64：数字 / 十进制字符串 / `0x` 十六进制字符串。
///
/// 为什么必须「宽松」：同一份语义在各链上游的表示完全不同——
/// Lotus 的 `Height` 是 JSON number、Sui GraphQL 的 `networkTotalTransactions`
/// 是十进制字符串、CKB 的区块号是 `0x` 十六进制字符串。
/// 在这里统一收敛，适配器就不必各自写一遍转换。
pub fn loose_u64(value: &Value) -> Result<u64, SdkError> {
    // 对 `Value` 的**枚举变体**做模式匹配：`Value` 本身就是个枚举，
    // 所以可以直接 match 出 Number / String / 其它三大类。
    match value {
        // `as_u64()` 返回 `Option`：负数、浮点数、超过 u64 的整数都会是 `None`。
        // 常见踩坑：JSON 里的 `1.0` 也不被 `as_u64` 接受。
        Value::Number(n) => n.as_u64().ok_or_else(|| {
            SdkError::new(
                ErrorCode::ParseError,
                format!("数字超出 u64 范围或为负数: {n}"),
            )
        }),
        Value::String(s) => parse_integer_str(s)
            // 先按 u128 解析（容量最大），再收窄到 u64。
            // `.and_then(闭包)`：仅在前一步是 `Ok` 时继续，闭包自身返回 `Result`。
            // `.map_err(|_| ())` 把 `TryFromIntError` 换成单元类型 `()`——
            // 下一行会用统一文案重造错误，具体原因不重要，顺带省掉类型参数。
            .and_then(|n| u64::try_from(n).map_err(|_| ()))
            .map_err(|_| SdkError::new(ErrorCode::ParseError, format!("无法解析为 u64: {s}"))),
        // `other` 绑定剩下所有变体（Null / Bool / Array / Object）。
        other => Err(SdkError::new(
            ErrorCode::ParseError,
            format!("期望数字，实际为 {other}"),
        )),
    }
}

/// 宽松解析 u128（大余额场景，如 winston / attoFIL / nanoton）。
///
/// 与 [`loose_u64`] 的差别只在目标类型：u128 最大值约 3.4e38，
/// 足以装下任何链的余额（即使是 NEAR 那 24 位小数的 yoctoNEAR）。
///
/// 语法说明：`Value::Number::as_u128()` 是 serde_json 提供的扩展方法，
/// 只在**非负整数**上返回 `Some`；带小数点或负号的都会是 `None`。
pub fn loose_u128(value: &Value) -> Result<u128, SdkError> {
    match value {
        Value::Number(n) => n.as_u128().ok_or_else(|| {
            SdkError::new(
                ErrorCode::ParseError,
                format!("数字超出 u128 范围或为负数: {n}"),
            )
        }),
        // 字符串分支不需要 `try_from`：`parse_integer_str` 本来就返回 u128。
        Value::String(s) => parse_integer_str(s)
            .map_err(|_| SdkError::new(ErrorCode::ParseError, format!("无法解析为 u128: {s}"))),
        other => Err(SdkError::new(
            ErrorCode::ParseError,
            format!("期望数字，实际为 {other}"),
        )),
    }
}

/// 解析整数字符串，支持十进制与 `0x` / `0X` 十六进制，统一返回 u128。
///
/// 返回 `Result<u128, ()>` 而不是带具体错误类型，是刻意的：
/// 错误类型 `()` 不携带任何信息，等于告诉调用方「失败原因不重要，你自己写文案」。
/// 这样 [`loose_u64`] 与 [`loose_u128`] 能各自给出带上下文的提示。
fn parse_integer_str(s: &str) -> Result<u128, ()> {
    // `.trim()` 去掉首尾空白：不少节点返回的数字串会带换行或空格。
    let t = s.trim();
    // `strip_prefix` 返回 `Option<&str>`。
    // `.or_else(闭包)` 只在 `None` 时才调用闭包（惰性），
    // 因此只有第一个前缀没命中时才会去试 `0X`。
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        // `from_str_radix(内容, 16)`：按十六进制解析，内容里**不能**再带 `0x` 前缀。
        // `.map_err(|_| ())` 丢弃具体的 `ParseIntError`。
        u128::from_str_radix(hex, 16).map_err(|_| ())
    } else {
        // turbofish 语法 `parse::<u128>()`：显式指定 `FromStr` 的目标类型。
        // 这里其实能靠返回类型反推，但写清楚可防止将来改签名时悄悄改变行为。
        t.parse::<u128>().map_err(|_| ())
    }
}

/// 微秒级时间戳（字符串或数字）转 Unix 秒。
///
/// 各链时间戳精度五花八门：Filecoin tipset 的 `Timestamp` 是 Unix **秒**，
/// 而 NEAR / Aptos 的部分接口给的是**微秒**，统一模型 `BlockView::timestamp`
/// 则约定为秒。
///
/// 语法说明：中间结果一律抬到 `i128` 再做除法，这样既不会溢出，
/// 也避开了 i64 上负数除法的取整细节差异。
pub fn micros_to_seconds(value: &Value) -> Result<i64, SdkError> {
    let micros =
        match value {
            Value::String(s) => s.trim().parse::<i128>().map_err(|_| {
                SdkError::new(ErrorCode::ParseError, format!("非法微秒时间戳: {s}"))
            })?,
            // `n.as_i64().map(i128::from)`：把函数名当闭包传给 `map`（函数指针自动转换），
            // 把 `Option<i64>` 变成 `Option<i128>`，比写 `|v| v as i128` 更地道。
            Value::Number(n) => n.as_i64().map(i128::from).ok_or_else(|| {
                SdkError::new(ErrorCode::ParseError, format!("非法微秒时间戳: {n}"))
            })?,
            other => {
                return Err(SdkError::new(
                    ErrorCode::ParseError,
                    format!("非法微秒时间戳: {other}"),
                ));
            }
        };
    // `as i64` 是显式截断转换：此处值已在秒级范围，不会溢出。
    //
    // 注意这里是**截断**而非四舍五入：1788009379932710 微秒 → 1788009379 秒，
    // 与把时间统一取整到秒的惯例一致，各链行为才可比对。
    Ok((micros / 1_000_000) as i64)
}

/// 解析 RFC3339 / ISO-8601 字符串（如 `2026-08-29T13:19:32.051Z`）为 Unix 秒。
///
/// 不引入 chrono/time 依赖：固定截取年月日时分秒，用 Howard Hinnant 的
/// civil-from-days 公式换算，足够覆盖各链节点返回的 UTC 时间格式。
///
/// 覆盖范围与限制（调用方需知）：
/// - **只支持 UTC**。`+08:00` 这类时区偏移会被下面的 `trim_end_matches` 当成
///   尾随字母一起抹掉，结果相当于按 UTC 解释本地时间；
/// - 秒的小数部分（`.051`）直接丢弃，不做四舍五入；
/// - 只做范围校验（月 1..=12、日 1..=31），**不**校验「2 月 30 日」这类
///   日历上不存在的日期——那需要闰年与月份天数表，对本 SDK 的场景不值得。
pub fn rfc3339_to_unix(raw: &str) -> Result<i64, SdkError> {
    // 语法说明：`parse_err` 是一个捕获了 `raw` 的**闭包**，且实现了 `Fn`
    // （只读捕获，可被调用多次）。下面十几处 `ok_or_else(parse_err)?` /
    // `map_err(|_| parse_err())?` 都在复用它，避免把同一句 `format!` 抄十几遍。
    // 注意 `ok_or_else(parse_err)` 传的是闭包**本身**，而 `map_err(|_| parse_err())`
    // 是包一层再**调用**它——后者是必须的，因为 `map_err` 的闭包要接收错误参数。
    let parse_err = || SdkError::new(ErrorCode::ParseError, format!("非法 RFC3339 时间: {raw}"));
    // `split_once('T')` 返回 `Option<(&str, &str)>`：按第一个 `T` 切成日期与时间两段。
    // 它是 Rust 1.52 起才有的写法，比先 `find('T')` 再切片更不易出错。
    let (date, rest) = raw.split_once('T').ok_or_else(parse_err)?;
    // `split('-')` 返回**惰性迭代器**；`mut` 是因为下面要连续 `next()` 三次。
    let mut date_parts = date.split('-');
    // 连着三段是同一个套路：`next()` 取一段 → `None` 则报「缺字段」→
    // `parse::<i64>()` 解析 → 失败则报「非法」。`?` 把 `Err` 直接向上传播。
    let year: i64 = date_parts
        .next()
        .ok_or_else(parse_err)?
        .parse()
        .map_err(|_| parse_err())?;
    let month: i64 = date_parts
        .next()
        .ok_or_else(parse_err)?
        .parse()
        .map_err(|_| parse_err())?;
    let day: i64 = date_parts
        .next()
        .ok_or_else(parse_err)?
        .parse()
        .map_err(|_| parse_err())?;
    // `trim_end_matches(闭包)`：从尾部逐个去掉满足条件的字符。
    // 这里去掉所有 ASCII 字母，于是 `13:19:32.051Z` → `13:19:32.051`，
    // 时区标记 `Z` 被顺手抹掉（代价是 `+08:00` 的偏移也被抹掉，见函数文档）。
    // 闭包参数写作 `c: char` 是必需的：**迭代器给出的是 `char` 而非 `u8`**，
    // 因为 `trim_end_matches` 的这个重载按字符处理。
    let time = rest.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let mut time_parts = time.split(':');
    let hour: i64 = time_parts
        .next()
        .ok_or_else(parse_err)?
        .parse()
        .map_err(|_| parse_err())?;
    let minute: i64 = time_parts
        .next()
        .ok_or_else(parse_err)?
        .parse()
        .map_err(|_| parse_err())?;
    let sec_str = time_parts.next().ok_or_else(parse_err)?;
    let second: i64 = sec_str
        // 秒可能带小数（`32.051`），按 `.` 切开只取整数部分。
        .split('.')
        .next()
        // `split` 至少返回一个元素，所以 `next()` 理论上不可能为 `None`；
        // 但返回类型是 `Option`，必须处理，这里用 `unwrap_or(sec_str)` 兜底。
        .unwrap_or(sec_str)
        .parse()
        .map_err(|_| parse_err())?;

    // 语法说明：`(1..=12)` 是 **RangeInclusive**（闭区间），`..=` 表示包含右端点。
    // `.contains(&month)` 取的是**引用**——Range 的 `contains` 签名接受 `&T`。
    // 写成 `contains(&month)` 而不是 `contains(month)` 是这里最容易写错的地方。
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(parse_err());
    }
    // civil_from_days：days since 1970-01-01。
    // 算法要点：先把 3 月当作一年的开始（`month <= 2` 时借位到上一年），
    // 这样闰日落在年末，各月长度就变成了规则的 5 个月 31 天 + 2 个月 30 天循环，
    // 于是可以用整除 `(153 * m + 2) / 5` 直接算出「年内第几天」。
    let y = if month <= 2 { year - 1 } else { year };
    // 400 年一「纪元」，共 146097 天。`y - 399` 是为了让负数年份的除法
    // 也向下取整（Rust 的整数除法是**向零取整**，对负数需要这个修正）。
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // 纪元内年号 [0, 399]
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // 纪元内天数（含闰年修正）
    let days = era * 146097 + doe - 719468; // 719468 是 1970-01-01 的绝对日偏移
    // 一天固定 86400 秒：本函数只处理 UTC，不涉及闰秒。
    Ok(days * 86_400 + hour * 3600 + minute * 60 + second)
}

/// URL 编码辅助：把含 `<>` / `::` 的 Move struct tag 等放进 query/path 前转义。
///
/// 只保留 RFC 3986 的 **unreserved** 字符集（字母数字 + `-` `_` `.` `~`）不转义，
/// 其余一律转成 `%XX`，且十六进制用**大写**（与主流实现一致）。
///
/// 为什么需要它：`0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>` 这类 Move 类型标签
/// 里的 `:` 与 `<>` 在 URL 里有特殊含义，不转义会被网关截断或误解析；
/// TON 的用户友好地址含 `+` 与 `/`，其中 `+` 在 query 里会被解成空格——这是最隐蔽的坑。
///
/// 注意：本函数**不**把空格转成 `+`，而是转成 `%20`，这是更安全的做法。
pub fn url_encode(raw: &str) -> String {
    // `b"0123456789ABCDEF"` 是**字节串字面量**，类型是 `&[u8; 16]`。
    // 用字节而非字符是因为下面要按下标取，而查表操作根本不关心 UTF-8。
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    // `with_capacity` 预分配，避免逐字符 push 时反复扩容。
    // 这里按「最坏情况每个字节变成 3 个字符」估不准，所以先用 `raw.len()` 打个底。
    let mut out = String::with_capacity(raw.len());
    // `.bytes()` 按**字节**迭代。因为要编码的本质是字节流，
    // 且非 ASCII 字符本就该被逐字节转义成 UTF-8 百分号编码，用 bytes 正合适。
    for b in raw.bytes() {
        // `matches!(b, b'-' | b'_' | ..)`：宏 + 或模式。
        // 注意分支里的 `b'-'` 是 **u8 字面量**（前缀 `b`），与外层的 `b`（变量）同名但不冲突。
        let safe = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if safe {
            // 安全字符都是 ASCII，`as char` 转换无损。
            out.push(b as char);
        } else {
            out.push('%');
            // `b >> 4` 取高 4 位，`b & 0x0f` 取低 4 位，各自查表转成十六进制字符。
            // `as usize` 是因为切片下标必须是 `usize`，`u8` 不会自动转换。
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    // 无分号的最后一行 = 返回值。
    out
}

/// 单元测试模块：`#[cfg(test)]` 保证它只在 `cargo test` 时编译，正式构建里完全不存在。
#[cfg(test)]
mod tests {
    // `use super::*` 把父模块的所有条目（含私有函数）导入，于是可以直接写 `loose_u64`。
    // 测试能访问私有项是 Rust 的惯例——测试与被测试代码同处一个文件、一个模块树。
    use super::*;
    // `json!` 宏需要单独引入（它不在 `super::*` 里）。
    use serde_json::json;

    /// 覆盖数字 / 十进制字符串 / `0x` 十六进制 / 超大 u128 / 非法输入五种情形。
    #[test]
    fn parses_loose_numbers() {
        // `.unwrap()`：测试里直接断言成功，失败会 panic 从而让用例失败。
        // 生产代码里应改用 `?`，测试里 `unwrap` 是被接受且鼓励的。
        assert_eq!(loose_u64(&json!(42)).unwrap(), 42);
        assert_eq!(loose_u64(&json!("42")).unwrap(), 42);
        assert_eq!(loose_u64(&json!("0x2a")).unwrap(), 42);
        // 这条用例的价值在于验证 u128 路径不丢精度：
        // 该数值超过 u64 上限的一半，用 f64 承载必然失真。
        assert_eq!(
            loose_u128(&json!("692825625168421088907802623")).unwrap(),
            692_825_625_168_421_088_907_802_623u128
        );
        assert!(loose_u64(&json!("nope")).is_err());
    }

    /// 微秒时间戳：字符串与数字两种形态都应得到相同的秒数。
    #[test]
    fn converts_micros() {
        assert_eq!(
            micros_to_seconds(&json!("1788009379932710")).unwrap(),
            1_788_009_379
        );
        assert_eq!(
            micros_to_seconds(&json!(1_788_009_379_000_000u64)).unwrap(),
            1_788_009_379
        );
    }

    /// RFC3339 解析：含小数秒、Unix 纪元零点、闰日三种边界。
    #[test]
    fn parses_rfc3339() {
        assert_eq!(
            rfc3339_to_unix("2026-08-29T13:19:32.051Z").unwrap(),
            1_788_009_572
        );
        assert_eq!(rfc3339_to_unix("1970-01-01T00:00:00Z").unwrap(), 0);
        // 2024 是闰年，2 月 29 日必须能被正确换算。
        assert_eq!(
            rfc3339_to_unix("2024-02-29T23:59:59.999Z").unwrap(),
            1_709_251_199
        );
        assert!(rfc3339_to_unix("not-a-time").is_err());
    }

    /// Move struct tag 里的 `::` 与 `<>` 都必须被转义。
    #[test]
    fn encodes_move_struct_tag() {
        assert_eq!(
            url_encode("0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"),
            "0x1%3A%3Acoin%3A%3ACoinStore%3C0x1%3A%3Aaptos_coin%3A%3AAptosCoin%3E"
        );
    }
}
