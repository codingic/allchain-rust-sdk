//! 统一调度：把「链 + 动作」翻译成某条链适配器上的一次调用，并包装成统一信封。
//!
//! CLI / HTTP / MCP 三种接入形态共用这一层，保证返回结构与错误码完全一致。
//!
//! **为什么三形态必须共用这一层**：若 CLI、HTTP、MCP 各写一套「拼参数 -> 调适配器 -> 包装结果」，
//! 那么同一个查询在三个入口会长成三种字段名、三种错误码，上层 agent 就得写三套解析。
//! 把「参数归一化 -> 构造适配器 -> 调 trait 方法 -> 包装信封」收敛到这里之后，
//! 三种入口只剩两件事：把各自的外部输入翻译成 [`Action`]、把信封按各自协议吐出去。
//! 新增一条链时，只需要改 `build_client` 一个 `match` 分支，三形态同时受益。
//!
//! **本模块的硬约定：错误不向上抛，一律装进信封返回。**
//! 见 [`run_action`] 的签名 `-> Envelope<Value>`——连失败也是一个「正常的返回值」。
//! 这样 CLI 用退出码表达失败、HTTP 用状态码表达失败、MCP 用 `isError` 表达失败，
//! 而三者的 `error.code` 与 `error.retryable` 字段完全一致，调用方的重试策略只需写一遍。

// `Instant` 是**单调时钟**（不受系统时间回拨影响），只用来测量「两个时刻之间过了多久」，
// 不能读出当前时间。用它统计耗时比 `SystemTime::now()` 更可靠。
use std::time::Instant;

// 一次性引入 core 定义的跨链契约：
// `ChainClient` 是十条链各自实现的 trait（运行时多态的入口），
// `ChainKind` 是链标识枚举，`Envelope` / `SdkError` / `ErrorCode` 是统一输出结构，
// `TransferRequest` 是转账入参（按值整体交给适配器）。
use allchain_core::{ChainClient, ChainKind, Envelope, ErrorCode, SdkError, TransferRequest};
// `serde_json::Value` 是「任意 JSON 值」的动态类型。十条的返回体类型各不相同
// （ChainStatus / Balance / BlockInfo ...），本层统一擦除成 `Value`：
// 代价是丢失编译期类型检查，换来的是三形态共用同一个返回结构。
use serde_json::Value;

/// 统一动作集合（只读 + 转账）。
///
/// 这是三形态与 dispatch 之间的**唯一接口**：CLI 的命令行参数、HTTP 的 query / body、
/// MCP 的 `arguments` 都先被翻译成 `Action`，之后的代码路径就完全一样了。
///
/// 相比「每个动作写一个 pub 函数、让三形态分别调用」，`enum` 方案的关键好处是
/// **穷尽性检查**：新增动作时 [`run_action`] 里的 `match` 会直接编译失败，
/// 逼着我们把所有分支补齐，不会悄悄漏掉某一个形态。
///
/// 语法说明：**携带数据的枚举变体**。Rust 的 enum 变体可以像结构体一样带字段，
/// `Balance { address: String }` 同时表达了「做什么」与「需要什么参数」，
/// 于是不必再维护一张「动作名 -> 参数表」的外部映射，参数缺失由编译器保证。
/// `Option<String>` 表示该参数可缺省（如区块引用缺省即取最新）。
#[derive(Debug, Clone)]
pub enum Action {
    /// 查询链与节点状态。无参数，故写成不带字段的变体 `Status`。
    Status,
    /// 查询地址 / 账户的原生资产余额。
    Balance {
        /// 地址或账户名；NEAR 传账户名（如 `example.near`）。
        address: String,
    },
    /// 查询链头高度（最新区块高度）。无参数，故写成不带字段的变体。
    LastBlockHeight,
    /// 按高度查询区块。
    BlockByHeight {
        /// 区块高度；`u64` 而非 `String`——高度本就是数字，类型化参数把
        /// 「传了非数字」这类错误挡在编译期，调用方也不必再自己解析。
        height: u64,
    },
    /// 查询交易详情与执行状态。
    Tx {
        /// 交易哈希；NEAR 需 `<tx_hash>@<sender.near>`，TON 需 `<tx_hash>:<lt>@<address>`。
        hash: String,
    },
    /// 由公钥派生地址；纯本地计算，不访问 RPC。
    AddressFromPubkey {
        /// 公钥；格式随链而异（十六进制 / base58 / ed25519: 前缀 / RSA 模数 base64url ...）。
        pubkey: String,
    },
    /// 转账；私钥缺省时按链从环境变量读取。
    Transfer {
        /// 收款地址 / 账户；NEAR 传账户名。
        to: String,
        /// 金额字符串，原生单位（如 `0.01`）；BTC 额外支持 `10000sat` 写法。
        amount: String,
        /// 显式私钥；`None` 时回退到环境变量，见 [`resolve_private_key`]。
        private_key: Option<String>,
        /// 为 true 时只本地构造并签名、**绝不广播**，用于审计与演练。
        dry_run: bool,
        /// 源账户；NEAR 命名账户必填，其余链可从私钥自动派生。
        from: Option<String>,
    },
}

/// 按链标识构造对应适配器。
///
/// 这是**全项目唯一**的「链标识 -> 具体适配器」分派点：新增一条链只需在这里加一个分支。
///
/// 语法说明：`Box<dyn ChainClient>` 是 **trait object**（特征对象）：
/// - `dyn ChainClient` 读作「某个实现了 `ChainClient` 的具体类型，具体是哪个到运行期才知道」；
/// - `Box<..>` 把它放到堆上。必须装箱的原因是 trait object 属于**动态尺寸类型（DST）**——
///   `EthClient` 和 `BtcClient` 大小不同，编译期无法确定返回值该占多少栈空间。
///
/// 于是这里实现了**运行时多态**：十个分支返回十个不同的具体类型，
/// 但都被「擦除」成同一种 `Box<dyn ChainClient>`，调用方只按 trait 上声明的方法使用。
/// 代价是每次方法调用多一次虚表（vtable）间接跳转；对「一次调用发一个网络请求」的场景，
/// 这点开销完全可以忽略。
///
/// 参数 `network` / `rpc_url` 都是 `Option<&str>`：`None` 表示「用这条链自己的默认值」，
/// 由各链适配器决定（十链默认网络一律是 mainnet，见 `ChainKind::default_network`）。
/// 用 `&str` 而不是 `String`，是因为这里只需要**读**这两个值，借用即可，无需取得所有权。
pub fn build_client(
    chain: ChainKind,
    network: Option<&str>,
    rpc_url: Option<&str>,
) -> Result<Box<dyn ChainClient>, SdkError> {
    // 整体写成 `Ok(match chain { ... })`，因为 `match` 在 Rust 里是**表达式**：
    // 只要各分支类型一致，它的值就可以直接当返回值用（分支结尾不加分号）。
    // 各分支的 `Box::new(EthClient::new(..))` 是 `Box<EthClient>` 这类具体类型，
    // 编译器会自动**强制转换（coercion）**成 `Box<dyn ChainClient>`，无需手写 as。
    //
    // `?` 运算符：适配器构造失败（如端点地址非法）时立即把 `SdkError` 返回给调用方，
    // 等价于 `match ... { Err(e) => return Err(e), Ok(v) => v }` 的糖。
    Ok(match chain {
        ChainKind::Eth => Box::new(eth_sdk::adapter::EthClient::new(network, rpc_url)?),
        ChainKind::Btc => Box::new(btc_sdk::adapter::BtcClient::new(network, rpc_url)?),
        ChainKind::Sol => Box::new(sol_sdk::adapter::SolClient::new(network, rpc_url)?),
        ChainKind::Near => Box::new(near_sdk::adapter::NearClient::new(network, rpc_url)?),
        ChainKind::Apt => Box::new(apt_sdk::adapter::AptClient::new(network, rpc_url)?),
        ChainKind::Ar => Box::new(ar_sdk::adapter::ArClient::new(network, rpc_url)?),
        ChainKind::Ckb => Box::new(ckb_sdk::adapter::CkbClient::new(network, rpc_url)?),
        ChainKind::Fil => Box::new(fil_sdk::adapter::FilClient::new(network, rpc_url)?),
        ChainKind::Sui => Box::new(sui_sdk::adapter::SuiClient::new(network, rpc_url)?),
        ChainKind::Ton => Box::new(ton_sdk::adapter::TonClient::new(network, rpc_url)?),
    })
}

/// 执行一次统一动作，永远返回信封（不向上抛错）。
///
/// 这是整个 SDK 的**语义收敛点**：CLI / HTTP / MCP 最终都只调用这一个函数。
///
/// 三个设计要点：
/// 1. **永不抛错**。签名是 `-> Envelope<Value>` 而非 `-> Result<.., SdkError>`，
///    因为调用方需要的是「这一次的完整结果」，失败结果同样要被格式化输出；
///    让它走 `?` 提前返回或 panic，都会让上层少掉错误信息。
///    成功与否由信封的 `ok` 字段表达，退出码 / HTTP 状态码 / `isError` 由各形态自行派生。
/// 2. **`data` 与 `error` 互斥**。`Envelope` 的两个字段都是 `Option`，
///    且都带 `#[serde(skip_serializing_if = "Option::is_none")]`：
///    成功响应里根本没有 `error` 键，失败响应里根本没有 `data` 键。
///    因此不会出现「ok=false 但 data 里还带着半截数据」这种自相矛盾的响应，
///    调用方可以用「键是否存在」直接分流。
/// 3. **耗时统计覆盖失败路径**。`took_ms` 对成功与失败一视同仁，
///    调用方才能区分「超时」与「快速失败」，从而决定要不要重试。
///
/// 语法说明：`async fn` 定义异步函数——调用它**不会**立即执行函数体，
/// 而是返回一个 future，必须 `.await` 才会真正推进。
/// 各链适配器内部都有网络 IO 且都是异步的，因此本函数也必须声明为 `async`；
/// 相应地，`await` 只能写在 `async fn`（或 `async` 块）内部。
pub async fn run_action(
    chain: ChainKind,
    network: Option<&str>,
    rpc_url: Option<&str>,
    action: Action,
) -> Envelope<Value> {
    // `Instant::now()` 打一个时间点；之后调 `.elapsed()` 得到两者之间的 `Duration`。
    let started = Instant::now();
    // `chain.as_str()` 返回 `&'static str`，`.to_string()` 复制出一份自有 `String`。
    // 必须复制：信封字段是 `String`，且返回后不能再持有指向局部量的引用。
    let chain_name = chain.as_str().to_string();
    // 构造适配器失败时，真实网络名还无从得知（默认网络在适配器内部），
    // 所以先备一个退化的占位值，保证失败也能包出**结构完整**的信封。
    let fallback_network = network.unwrap_or("default").to_string();

    // 注意这里**没有**用 `?`：构造失败也是一次「完整的结果」，
    // 要带上链名与耗时一起包成信封，让调用方知道是哪条链、卡了多久。
    let client = match build_client(chain, network, rpc_url) {
        Ok(client) => client,
        Err(err) => {
            // `as_millis()` 返回 `u128`，`as u64` 是显式截断转换（cast）。
            // 单次调用不可能超过 u64 毫秒，这里截断是安全的。
            return Envelope::err(
                chain_name,
                fallback_network,
                started.elapsed().as_millis() as u64,
                err,
            );
        }
    };
    // 适配器构造成功后，才拿得到**实际生效**的网络名与端点：
    // 用户传 `None` 时，适配器会补上该链的默认网络与默认端点。
    // 响应里回填的是真实值而不是「用户说了什么」，避免调用方误判自己打到了哪个节点。
    let network_name = client.network().to_string();
    let rpc_url = client.rpc_url().to_string();

    // 显式标注 `Result<Value, SdkError>`：各分支 `to_value` 的泛型参数 T 不同，
    // 但最终都被擦除成 `Value`；写出来能让类型错误定位到这一行，而不是埋在某个分支里。
    let outcome: Result<Value, SdkError> = match action {
        // 只读分支统一走「三步流水线」：
        //   `.await`          → 推进异步网络请求，拿到适配器自己的具体类型；
        //   `.and_then(to_value)` → 仅当成功时才序列化成 JSON 值（失败则原样短路透传）；
        //   `.map(|v| with_rpc(v, &rpc_url))` → 仅当成功时才把端点补进响应。
        // 这种组合子链比层层 `match` 紧凑，且错误类型不会被改写。
        // `|v| ...` 是**闭包**（匿名函数），参数写在两条竖线之间。
        Action::Status => client
            .status()
            .await
            .and_then(to_value)
            .map(|v| with_rpc(v, &rpc_url)),
        Action::Balance { address } => client
            .balance(&address)
            .await
            .and_then(to_value)
            .map(|v| with_rpc(v, &rpc_url)),
        // 链头高度：只取一个数字，走 `last_block_height`。
        Action::LastBlockHeight => client
            .last_block_height()
            .await
            .and_then(to_value)
            .map(|v| with_rpc(v, &rpc_url)),
        // 按高度查块：类型化的 `u64` 高度直接透传给 `block_by_height`，
        // 不再有「引用是高度还是哈希」的运行时猜测。
        Action::BlockByHeight { height } => client
            .block_by_height(height)
            .await
            .and_then(to_value)
            .map(|v| with_rpc(v, &rpc_url)),
        Action::Tx { hash } => client
            .tx(&hash)
            .await
            .and_then(to_value)
            .map(|v| with_rpc(v, &rpc_url)),
        Action::AddressFromPubkey { pubkey } => client
            .address_from_pubkey(&pubkey)
            .await
            .and_then(to_value)
            .map(|v| with_rpc(v, &rpc_url)),
        Action::Transfer {
            to,
            amount,
            private_key,
            dry_run,
            from,
        } => {
            // 写操作只对已实现本地签名的链开放，其余链在协议层明确返回 UNSUPPORTED。
            // 这是**能力检查**而非参数校验，判定放在 core 的 `ChainKind::supports_transfer()`
            // 统一维护，避免十条链各自返回五花八门的报错文案。
            if !chain.supports_transfer() {
                // `format!("{}", chain)` 会调用 `ChainKind` 的 `Display` 实现，
                // 得到 "eth" 这类短名而不是 `Debug` 的 `Eth`。
                Err(SdkError::unsupported(format!(
                    "{} 暂未实现本地签名转账（只读查询与地址派生可用）",
                    chain
                )))
            } else {
                // 私钥解析是纯本地行为，与网络无关，因此放在发起转账**之前**：
                // 私钥缺失时连一次网络请求都不必发，也避免把无效请求打到节点上。
                match resolve_private_key(chain, private_key.as_deref()) {
                    Ok(key) => client
                        .transfer(TransferRequest {
                            to,
                            amount,
                            private_key: key,
                            dry_run,
                            from,
                        })
                        .await
                        .and_then(to_value)
                        .map(|v| with_rpc(v, &rpc_url)),
                    Err(err) => Err(err),
                }
            }
        }
    };

    // 再次打点：耗时覆盖「构造适配器 + 执行动作 + 序列化」全过程，成功失败都计入。
    let took_ms = started.elapsed().as_millis() as u64;
    // 结果分流。互斥性由 `Envelope::ok` / `Envelope::err` 两个构造器保证：
    // 成功时 `data = Some(..)`、`error = None`，失败时正好相反。
    match outcome {
        Ok(data) => Envelope::ok(chain_name, network_name, took_ms, data),
        Err(err) => Envelope::err(chain_name, network_name, took_ms, err),
    }
}

/// 把任意可序列化的结果转成 `serde_json::Value`。
///
/// 语法说明：`<T: serde::Serialize>` 是**泛型参数 + trait 约束**，读作
/// 「对任意实现了 `Serialize` 的类型 T」。这是**编译期静态分派**：
/// 编译器为每个实际用到的 T 各生成一份机器码（单态化），没有虚表开销。
/// 十条链返回的结构体类型各不相同，正是靠这个泛型函数统一擦除成 `Value`。
///
/// 序列化失败在本项目里几乎不可能（都是我们自己定义的结构体），
/// 但仍然转成 `Internal` 错误而不是 `unwrap()`：panic 会让 HTTP / MCP 进程整体挂掉，
/// 而一个 `INTERNAL` 错误码只影响这一次调用。
fn to_value<T: serde::Serialize>(value: T) -> Result<Value, SdkError> {
    // `map_err` 只改写错误分支、保留 `Ok` 分支；闭包中的 `{e}` 是**内联格式化捕获**，
    // 直接取用同名的局部变量，不必写 `format!(".. {}", e)`。
    serde_json::to_value(value)
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("结果序列化失败: {e}")))
}

/// 把实际使用的端点补进响应的 `extra`（VPN/代理场景下便于核对打到哪个节点）。
///
/// **为什么必须回填端点**：查询类响应本身不带端点信息，而同一个 chain + network 组合
/// 在不同网络环境下可能命中完全不同的节点（自建节点 / 公共节点 / 代理 / 内网镜像）。
/// 把端点写进响应，调用方才能解释「为什么余额和区块浏览器对不上」这类问题——
/// 连的是测试网镜像还是主网节点，看一眼 `rpc_url` 就知道。
///
/// 语法说明：
/// - `mut value: Value` 里的 `mut` 表示把参数在函数体内重新绑定为**可变**，
///   这样能原地插入字段再原样返回，省掉一次克隆；
/// - `if let Some(obj) = value.as_object_mut()` 是「只关心一种模式」的简写 match。
///   `as_object_mut()` 只在 `Value` 确实是 JSON 对象时返回 `Some(&mut Map)`；
///   若是数组或标量则整个插入被安全跳过——**宁可少一个字段，也不为了加字段改变响应类型**。
fn with_rpc(mut value: Value, rpc_url: &str) -> Value {
    if let Some(obj) = value.as_object_mut() {
        // `Map::insert` 会返回被替换掉的旧值（`Option<Value>`），这里直接忽略：
        // 适配器返回的结构体里本来就没有 `rpc_url` 字段，不会有覆盖发生。
        obj.insert("rpc_url".to_string(), Value::from(rpc_url));
    }
    value
}

/// 解析链标识，统一错误信息。
///
/// 三形态都要做「字符串 -> `ChainKind`」这一步，错误文案必须一致，
/// 否则 agent 在 CLI 上看到一种提示、在 MCP 上看到另一种，排障成本翻倍。
///
/// 语法说明：`Option::ok_or_else(..)` 把 `None` 转成 `Err(..)`、`Some(v)` 转成 `Ok(v)`。
/// 用 `ok_or_else`（惰性闭包）而不是 `ok_or`（立即求值）：构造错误串要 `format!` 分配内存，
/// 成功路径上不该付这份代价。闭包 `|| ...` 只在真的失败时才被调用。
pub fn parse_chain(raw: &str) -> Result<ChainKind, SdkError> {
    ChainKind::parse(raw).ok_or_else(|| {
        SdkError::invalid_argument(format!(
            "不支持的链: {raw}（可选 eth / btc / sol / near / apt / ar / ckb / fil / sui / ton）"
        ))
    })
}

/// 各链签名私钥的环境变量名（与单链 CLI 一致）。
///
/// 六条新链返回空串 `""`：它们尚未支持本地签名转账，
/// [`run_action`] 里的 `chain.supports_transfer()` 会先把它们拦下来，
/// 因此**永远走不到**这里。留空串而不是 `unreachable!()`，是为了让 `match` 保持穷尽、
/// 将来某条链接入签名时只改这一处，而不是让 panic 在某个深夜发生。
fn private_key_env(chain: ChainKind) -> &'static str {
    match chain {
        ChainKind::Eth => "ETH_SECRET_KEY",
        ChainKind::Btc => "BTC_WIF",
        ChainKind::Sol => "SOL_KEYPAIR",
        ChainKind::Near => "NEAR_SECRET_KEY",
        // 六条新链暂不支持本地签名转账，不会走到环境变量解析。
        ChainKind::Apt
        | ChainKind::Ar
        | ChainKind::Ckb
        | ChainKind::Fil
        | ChainKind::Sui
        | ChainKind::Ton => "",
    }
}

/// 私钥解析：显式参数优先，否则读对应链的环境变量。
///
/// 优先级设计：**调用时显式传入 > 环境变量**。
/// 显式优先，是为了让「一次性、指定身份的操作」不被 shell 里残留的环境变量带偏；
/// 环境变量兜底，是为了让常驻进程（如 `acli mcp`）不必把私钥写进每一次调用的参数里。
///
/// 语法说明：`Some(key) if !key.trim().is_empty()` 是**带守卫（match guard）的模式**：
/// 只有同时满足「有值」且「去掉首尾空白后非空」才进这个分支，否则落到 `_` 去读环境变量。
/// 这样 `--private-key ""` 不会被误当成有效私钥。
fn resolve_private_key(chain: ChainKind, explicit: Option<&str>) -> Result<String, SdkError> {
    match explicit {
        Some(key) if !key.trim().is_empty() => Ok(key.trim().to_string()),
        _ => {
            let env = private_key_env(chain);
            // `std::env::var` 返回 `Result<String, VarError>`。
            // 这里用 `map_err` 把「变量不存在」与「不是合法 Unicode」两种系统级错误
            // 统一成一条可读的 `INVALID_ARGUMENT`：调用方不必理解 `VarError` 是什么。
            // `|_|` 表示「用不上这个错误值」，只按「失败了」处理。
            std::env::var(env).map_err(|_| {
                SdkError::invalid_argument(format!(
                    "缺少私钥：请用 --private-key 传入，或设置环境变量 {env}（{}）",
                    chain
                ))
            })
        }
    }
}

/// 能力清单，供 `/v1/chains` 与 MCP 的 `chain_catalog` 工具使用；能力按链真实声明。
///
/// 刻意**不硬编码**这张表，而是遍历 `ChainKind::ALL` 并调用各链自己声明的
/// `capabilities()` / `decimals()` / `default_network()` / `supports_transfer()`：
/// 新增链时无需修改这里，清单自动同步，也就不会出现「文档说支持、实际返回 UNSUPPORTED」。
///
/// 语法说明：
/// - `.iter()` 借出每个元素的引用（`&ChainKind`），而不是把数组**移动**进迭代；
/// - `|c| json!({ ... })` 是闭包，`json!` 是 serde_json 的宏，写法与 JSON 字面量几乎一致，
///   值会自动转成 `Value`；
/// - `.collect()` 的目标类型由左边的 `let chains: Vec<Value>` 反推出来，
///   这正是 Rust 类型推断的便利之处，无需写成 `collect::<Vec<Value>>()`（turbofish）。
pub fn chain_catalog() -> Value {
    let chains: Vec<Value> = ChainKind::ALL
        .iter()
        .map(|c| {
            serde_json::json!({
                "chain": c.as_str(),
                "symbol": c.symbol(),
                "unit": c.unit_name(),
                "decimals": c.decimals(),
                "default_network": c.default_network(),
                "capabilities": c.capabilities(),
                "supports_transfer": c.supports_transfer(),
            })
        })
        .collect();
    // 注意 `json!` 对值表达式是**取引用**调用 `to_value(&x)`，
    // 所以这里把 `chains` 交给宏之后仍然可以紧接着调用 `chains.len()`，
    // 不会发生「所有权已转移」的借用错误。
    serde_json::json!({ "chains": chains, "count": chains.len() })
}
