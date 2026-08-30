//! acli：全链统一入口。
//!
//! 三种接入形态共用 [`dispatch`] 这一层，返回结构与错误码完全一致：
//!
//! ```bash
//! acli status  --chain btc                       # 命令行（默认 JSON）
//! acli balance --chain eth --address 0x...       # 查询余额
//! acli transfer --chain eth --to 0x... --amount 0.01 --dry-run   # 转账（dry-run 只签名不广播）
//! acli serve   --port 8787                       # 本地 HTTP 服务
//! acli mcp                                       # MCP stdio 服务器
//! ```
//!
//! **为什么默认输出 JSON 而不是 text**：本工具的主要消费者是 agent 而不是人类，
//! agent 只能可靠地解析结构化数据；`--format text` 只是给人排障时的旁路输出。
//! 更关键的是，JSON 输出与 HTTP、MCP 的响应**结构完全一致**（都是统一信封），
//! 三形态之间复制样本不需要任何转换，agent 的解析逻辑也只需写一份。
//!
//! **退出码约定**：
//! - `0` 成功；
//! - `1` 业务失败（链返回错误、参数非法、查不到交易等）——详情在信封的 `error` 里；
//! - 其它非零值来自进程级故障（端口被占用、stdio 中断等），由 `anyhow` 打印错误链。
//!   退出码只给 shell 一个粗粒度信号，**细粒度原因要看 `error.code` 与 `error.retryable`**。

// `mod xxx;` 声明**模块**，编译器据此去找同目录下的 `xxx.rs` 一起编译。
// 三个模块都写成私有（`mod` 而非 `pub mod`）：它们只是本二进制内部的三种接入形态，
// 没有对外暴露的必要。
mod dispatch;
mod http;
mod mcp;

// clap 的四个派生宏，正好对应命令行的四种语法成分：
// `Parser`     -> 根命令（整个 `Cli`）
// `Subcommand` -> 子命令枚举（`Command`）
// `Args`       -> 可复用的一组参数（`ChainArgs`，供多个子命令 flatten 共用）
// `ValueEnum`  -> 把枚举直接当命令行取值用（`Format`）
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::Value;

// 只把 `Action` 引入作用域：本文件的职责就是把命令行翻译成它，之后交给 dispatch 执行。
use dispatch::Action;

// 注意：clap 派生类型上的 `///` **不是普通文档**——
// clap_derive 会把 `///` 的内容搬进命令行 help（结构体/枚举级 -> about，字段/变体级 -> help）。
// 所以在这几个派生类型上，`///` 属于「会改变 `--help` 输出」的行为改动，
// 纯解释性说明一律写成 `//`。
//
// 另有一个坑：`#[command(about = "...")]` 显式指定的 about 会被**类型级 doc 注释覆盖**，
// 因为派生宏把 doc 生成的 `.about(..)` 排在显式属性之后。
// 因此这里刻意不给 `Cli` 加 `///`，以免悄悄改掉启动横幅。
#[derive(Parser)]
#[command(
    name = "acli",
    version,
    about = "全链统一接口：一套调用操作 eth / btc / sol / near / apt / ar / ckb / fil / sui / ton"
)]
struct Cli {
    // `#[command(subcommand)]` 表示这个字段装的是子命令；
    // clap 要求被标注的字段类型必须派生 `Subcommand`。
    // 子命令必填：不给 `acli` 传子命令时会打印帮助并以非零码退出。
    #[command(subcommand)]
    command: Command,
}

/// 输出格式。默认 JSON——本工具面向 agent，结构化优先。
///
/// 语法说明：`#[derive(ValueEnum)]` 让枚举可以直接作为 `--format` 的取值：
/// clap 自动把变体名转成 kebab-case 的词（`Json` -> `json`），
/// 并在用户输错时列出全部候选项。
/// 两个细节：`ValueEnum` **枚举级**的 `///` 不会被用作文案（只有变体级会），
/// 所以这里的说明可以放心写；变体上则一个 `///` 都不加。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Json,
    Text,
}

/// 选链与连接参数，所有查询类子命令共用。
///
/// 语法说明：`#[derive(Args)]` 把一组字段打包成**可复用的参数组**，
/// 由各子命令用 `#[command(flatten)]` 平铺进来，相当于「参数继承」：
/// `chain / network / rpc_url / format` 只在这里定义一次，改一处全站生效。
#[derive(Args, Debug)]
struct ChainArgs {
    /// 链标识：eth / btc / sol / near / apt / ar / ckb / fil / sui / ton
    // `#[arg(short, long)]`：`short` 自动生成短选项 `-c`（取字段名首字母），
    // `long` 生成长选项 `--chain`。下面 `rpc_url` 只写了 `long`——
    // 短选项在多链、多参数场景下容易撞车，索性只保留长名。
    #[arg(short, long)]
    chain: String,

    /// 网络名；十链默认均为 mainnet，可显式指定 testnet / devnet / sepolia 等
    // `Option<String>` 表示「可缺省」：clap 据此把它变成可选参数（不传即 `None`），
    // 而不是必填项。`None` 时不由我们猜，交给适配器套用该链自己的默认网络。
    #[arg(short, long)]
    network: Option<String>,

    /// 自定义端点；对 BTC 而言是 Esplora 索引器地址
    #[arg(long)]
    rpc_url: Option<String>,

    /// 输出格式
    // `value_enum` 告诉 clap 用 `Format` 的 `ValueEnum` 实现来解析取值；
    // `default_value_t = Format::Json` 用**类型化的默认值**（`t` 即 typed），
    // 比写 `default_value = "json"` 的字符串版本更安全：拼错会编译失败。
    #[arg(long, value_enum, default_value_t = Format::Json)]
    format: Format,
}

// 子命令枚举。这里同样只用 `//` 写说明，原因见上面的 `Cli`：
// `#[derive(Subcommand)]` 会把**枚举级** doc 注释当成父命令的 about 生成出来，
// 且排在 `#[command(about = ..)]` 之后，等于把 `acli --help` 的横幅悄悄改掉。
// 各变体上的 `///` 是该子命令的 help 文案，属于既有内容，保持原样。
//
// 变体携带的字段就是该子命令的**具名参数**：`Balance { chain, address }`
// 说明 `acli balance` 除了共用参数外，还要一个 `--address`。
// `Option<String>` 字段即「可选参数」，不给就解析成 `None`。
#[derive(Subcommand)]
enum Command {
    /// 查询链与节点状态
    Status {
        // `flatten` 把 `ChainArgs` 的四个字段**平铺**进本子命令，
        // 用户看到的是 `--chain / --network / --rpc-url / --format` 四个平级选项，
        // 而代码里只写一行。这是 clap 版的「组合优于继承」。
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// 查询地址 / 账户余额
    // `alias` 是**隐藏别名**：`acli getbalance` 与 `acli balance` 等价。
    // 保留它是为了迁就 bitcoin-cli / 老脚本的习惯，不额外出现在帮助列表里。
    #[command(alias = "getbalance")]
    Balance {
        #[command(flatten)]
        chain: ChainArgs,
        /// 地址或账户名（NEAR 传账户名）
        #[arg(long)]
        address: String,
    },
    /// 查询链头高度（最新区块高度）
    BlockHeight {
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// 按高度查询区块
    BlockByHeight {
        #[command(flatten)]
        chain: ChainArgs,
        /// 区块高度（数字），如 `19000000`
        #[arg(long)]
        height: u64,
    },
    /// 查询交易
    Tx {
        #[command(flatten)]
        chain: ChainArgs,
        /// 交易哈希；NEAR 需形如 <tx_hash>@<sender.near>，TON 需形如 <tx_hash>:<lt>@<address>
        #[arg(long)]
        hash: String,
    },
    /// 由公钥派生地址（纯本地计算，不联网）
    // `name = "address-from-pubkey"` 显式指定子命令名（默认 kebab-case 结果相同，
    // 写出来是为了与并列出现的 `alias` 一起自解释）；
    // 别名 `getaddressfrompubkey` 则照顾从其它工具迁移过来的调用方。
    #[command(name = "address-from-pubkey", alias = "getaddressfrompubkey")]
    AddressFromPubkey {
        #[command(flatten)]
        chain: ChainArgs,
        /// 公钥：ETH/BTC 为十六进制（BTC 需压缩格式），
        /// SOL 为 base58 或 64 位十六进制，NEAR 为 ed25519:<base58>，
        /// APT/SUI 为十六进制（SUI 可加 ed25519:/secp256k1: 前缀），
        /// CKB 为 33 字节压缩公钥，FIL 为 65 字节未压缩公钥，AR 为 RSA 模数 base64url
        #[arg(long)]
        pubkey: String,
    },
    /// 转账（本地签名；--dry-run 只签名不广播）
    Transfer {
        #[command(flatten)]
        chain: ChainArgs,
        /// 收款地址 / 账户；NEAR 传账户名
        #[arg(long)]
        to: String,
        /// 金额，原生单位（如 0.01）；BTC 还支持 10000sat 写法
        #[arg(long)]
        amount: String,
        /// 私钥（ETH 十六进制 / BTC WIF / SOL JSON 数组或 base58 / NEAR ed25519:...）；
        /// 缺省时读环境变量：ETH_SECRET_KEY / BTC_WIF / SOL_KEYPAIR / NEAR_SECRET_KEY
        // 私钥用 `Option` + 环境变量兜底，而不是必填项：
        // 常驻进程（如 `acli serve`）不该要求每次调用都把私钥写在命令行上
        // ——命令行参数是同机其他用户 `ps` 一眼可见的。
        #[arg(long)]
        private_key: Option<String>,
        /// 仅本地构造并签名，不广播
        // `bool` 字段在 clap 里是 **flag**：出现即 true，不写即 false，不接值。
        #[arg(long)]
        dry_run: bool,
        /// 源账户；NEAR 命名账户必填，其余链自动从私钥派生
        #[arg(long)]
        from: Option<String>,
    },
    /// 列出支持的链、精度与能力
    // `chains` 不接受 `ChainArgs`：它是「查 SDK 自身的能力」而不是「查某条链」，
    // 加 `--chain` 反而误导。只保留 `--format`。
    Chains {
        #[arg(long, value_enum, default_value_t = Format::Json)]
        format: Format,
    },
    /// 启动本地 HTTP 服务
    Serve {
        // `default_value = "127.0.0.1"` 用字符串给默认值：默认只监听回环地址，
        // **不对外暴露**——这台机器上跑的 HTTP 服务没有任何鉴权。
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        // `default_value_t = 8787` 是类型化默认值，写法与 `Format::Json` 那处一致。
        #[arg(long, default_value_t = 8787)]
        port: u16,
    },
    /// 以 MCP stdio 服务器运行（供 agent 直接接入）
    // 无字段：MCP 模式下没有命令行参数，全部输入都来自 stdin 上的 JSON-RPC。
    Mcp,
}

/// 进程入口。
///
/// 语法说明：`#[tokio::main]` 是**属性宏**（attribute macro），它会把下面的
/// `async fn main` 改写成普通同步 `fn main`：内部建好 tokio 多线程运行时，
/// 再 `block_on(..)` 我们的异步函数体。
/// Rust 的入口函数由操作系统直接调用，**必须是同步的**，所以没有这个宏就写不了 `async fn main`。
///
/// 返回 `anyhow::Result<()>`：返回 `Err` 时 anyhow 会打印整条错误链并以退出码 1 结束。
/// 注意这条路径只用于**进程级故障**（端口占用、stdio 中断）；
/// 业务失败有自己的退出码通路，见下面的 `exit_code`。
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `Cli::parse()` 由 `#[derive(Parser)]` 生成：读取 `std::env::args_os()` 并解析。
    // 解析失败（未知子命令、缺必填参数）时它**直接打印帮助并退出进程**，不会返回到这里；
    // `--help` / `--version` 也在这里被处理掉。
    let cli = Cli::parse();

    // 每个分支都产出一个 `i32` 退出码，`match` 本身是表达式，故可直接赋值。
    // 穷尽性由编译器保证：给 `Command` 加一个子命令却忘了在这里处理，编译就失败。
    let exit_code = match cli.command {
        // 查询类分支统一走 `run(..)`：把子命令字段翻译成 `Action`，`.await` 等结果。
        // 这里刻意不写任何链相关逻辑，保证 CLI 与 HTTP / MCP 的语义完全一致。
        Command::Status { chain } => run(chain, Action::Status).await,
        Command::Balance { chain, address } => run(chain, Action::Balance { address }).await,
        Command::BlockHeight { chain } => run(chain, Action::LastBlockHeight).await,
        Command::BlockByHeight { chain, height } => {
            run(chain, Action::BlockByHeight { height }).await
        }
        Command::Tx { chain, hash } => run(chain, Action::Tx { hash }).await,
        Command::AddressFromPubkey { chain, pubkey } => {
            run(chain, Action::AddressFromPubkey { pubkey }).await
        }

        Command::Transfer {
            chain,
            to,
            amount,
            private_key,
            dry_run,
            from,
        } => {
            // 字段**按所有权移动**进 `Action::Transfer`，不需要 `.clone()`：
            // 它们是从 `cli.command` 解构出来的自有值，之后也不会再用到。
            // 若写成 `to: to.clone()` 就白白多一次堆分配。
            run(
                chain,
                Action::Transfer {
                    to,
                    amount,
                    private_key,
                    dry_run,
                    from,
                },
            )
            .await
        }

        Command::Chains { format } => {
            // 能力清单是**纯本地**计算的：不建适配器、不发网络请求，因此不需要 `async`。
            let payload = dispatch::chain_catalog();
            match format {
                // `?` 把 `serde_json::Error` 自动转成 `anyhow::Error` 向上抛——
                // 能自动转换是因为 `anyhow::Error` 实现了 `From<E: std::error::Error>`。
                Format::Json => println!("{}", serde_json::to_string_pretty(&payload)?),
                Format::Text => println!("{}", render_catalog_text(&payload)),
            }
            // 分支末尾的 `0` **不带分号**，它就是本分支的值（成功退出码）。
            0
        }

        // `serve` / `mcp` 是**常驻模式**：正常情况下函数永不返回（一直监听），
        // 只在端口被占用、stdin 关闭等故障时才以 `Err` 返回，`?` 交给 anyhow 打印。
        Command::Serve { host, port } => {
            http::serve(host, port).await?;
            0
        }

        Command::Mcp => {
            mcp::serve_stdio().await?;
            0
        }
    };

    // 非零退出码时调用 `std::process::exit` 立即终止进程，跳过返回 `Ok(())`。
    // 为什么不用 `return Err(..)`：业务失败不是一个「错误对象」，
    // 完整信息已经以信封的形式打印到 stdout 了，这里只需要给 shell 一个可判断的信号。
    // 注意 `exit` 不会执行析构，因此它必须放在**所有输出完成之后**。
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// 执行一次查询并输出；失败时返回退出码 1。
///
/// 职责边界：本函数**只做两件事**——把 `ChainArgs` 翻译成 dispatch 认识的参数、
/// 把信封按 `--format` 渲染出去。所有链相关的判断都在 dispatch 里。
/// 新增子命令时照抄这个模式即可，不要把业务逻辑挪进来。
async fn run(args: ChainArgs, action: Action) -> i32 {
    // **解构结构体**：把 `args` 的四个字段按所有权拆成独立变量，之后 `args` 整体不可再用。
    // 这里选择「按值解构」而不是 `let ChainArgs { ref chain, .. } = args` 的借用法：
    // 拆出来的 `chain` 后面会被 `parse_chain` 借用、`network` / `rpc_url` 也要转成 `Option<&str>`，
    // 直接拿所有权最省事，也不用处处写 `&args.` 前缀。
    let ChainArgs {
        chain,
        network,
        rpc_url,
        format,
    } = args;

    // 链标识解析失败是这里**唯一**会提前返回的分支：此时连一个合法的 `ChainKind` 都没有，
    // 信封也无从构造，只能手工渲染错误。
    let chain = match dispatch::parse_chain(&chain) {
        Ok(c) => c,
        Err(err) => {
            // 注意这里的 `&chain` 借用的仍是上面的 `String`：
            // 变量遮蔽要到整个 `let` 语句**求值并绑定完成后**才生效，
            // 所以初始化表达式内部看到的是旧绑定。
            //
            // 错误信息走 **stderr**：stdout 必须保持纯净，
            // 这样 `acli balance --chain eth --address 0x.. | jq .` 才不会被报错文案打断。
            eprintln!("{}", render_error(&chain, err, format));
            return 1;
        }
    };

    // `as_deref()`：`Option<String>` -> `Option<&str>`，把内部字符串**借**出去而不转移所有权，
    // dispatch 只读不拷贝，本函数的 `network` / `rpc_url` 之后仍可使用。
    let envelope =
        dispatch::run_action(chain, network.as_deref(), rpc_url.as_deref(), action).await;
    // 先把 `ok` 取出来：`bool` 实现了 `Copy`，所以这里是**复制**而非移动，
    // `envelope` 依然完整。好处是下面「渲染输出」与「判定退出码」两件事互不干扰，
    // 也不必在借用 `envelope` 之后再去回读字段。
    let ok = envelope.ok;

    match format {
        // JSON 用 `println!`（自动补换行），text 用 `print!`——
        // 因为 `render_text` 生成的每一行都已经自带 `\n`，再补一个就多出空行。
        Format::Json => println!("{}", envelope.to_json_pretty()),
        Format::Text => print!("{}", render_text(&envelope)),
    }

    // `if ok { 0 } else { 1 }` 整体是表达式，直接作为返回值（末尾无分号）。
    // 注意这个返回值**不是错误**：退出码 1 只是告诉 shell「这次查询没成」，
    // 真正的失败原因在 stdout 的信封 `error` 字段里。
    if ok { 0 } else { 1 }
}

/// 把统一信封渲染成对齐的 key : value 文本。
///
/// 只服务于 `--format text`：给人快速扫一眼用，**不是机器契约**，
/// 字段顺序与缩进随时可能调整；程序化消费请一律走 JSON。
fn render_text(envelope: &allchain_core::Envelope<Value>) -> String {
    // `let mut out`：声明为可变绑定，后面要不断 `push_str` 追加内容。
    let mut out = format!(
        "# chain: {} | network: {} | {}ms\n",
        envelope.chain, envelope.network, envelope.took_ms
    );

    // 对两个 `Option` 做**元组模式匹配**，一次性表达优先级：
    //   (Some(data), _) -> 有数据就渲染数据（成功时 `error` 必为 None，故用 `_` 忽略）；
    //   (_, Some(err))  -> 没数据但有错误，渲染错误三件套；
    //   _               -> 兜底分支（两者都为 None，正常情况下不会出现）。
    // 用 `_` 而不是逐个枚举全部组合，是为了只突出「优先展示 data」这一条规则。
    match (&envelope.data, &envelope.error) {
        (Some(data), _) => {
            if let Some(obj) = data.as_object() {
                // 先算出最长键的长度，所有行按它左对齐，输出才整齐。
                // `.map(..)` 把键映射成长度，`.max()` 是迭代器方法，直接得到 `Option<usize>`；
                // `.unwrap_or(0)` 处理空对象的情形。
                let width = obj.keys().map(|k| k.len()).max().unwrap_or(0);
                // 直接 `for` 遍历 `&Map`：serde_json 的 `Map` 为引用实现了 `IntoIterator`，
                // 每次给出 `(&String, &Value)` 这样的键值引用对，不会移动任何东西。
                for (key, value) in obj {
                    // 格式串 `{key:width$}`：`width` 是**命名参数**，宽度取自同名变量；
                    // 结尾的 `$` 表示这是变量宽度而非字面量。
                    // 注意 `len()` 数的是字节数：中文键会对不齐，
                    // 这里的键都是英文字段名，故可接受。
                    out.push_str(&format!("{key:width$} : {}\n", render_value(value)));
                }
            } else {
                out.push_str(&format!("{data}\n"));
            }
        }
        (_, Some(err)) => {
            // 固定输出这三个字段，与 JSON 信封里的 `error` 对象一一对应：
            // `code` 给机器判断、`message` 给人看、`retryable` 决定要不要重试。
            out.push_str(&format!("error_code : {}\n", err.code.as_str()));
            out.push_str(&format!("message    : {}\n", err.message));
            out.push_str(&format!("retryable  : {}\n", err.retryable));
        }
        _ => out.push_str("(无数据)\n"),
    }
    // 最后一行不带分号 = 返回值，把 `out` 的所有权交回调用方。
    out
}

/// 渲染「链标识本身就解析失败」的错误。
///
/// 这种情况拿不到合法的 `ChainKind`，也没跑过任何请求，
/// 无法像 `render_text` 那样从信封取值，只能手工拼一个**结构一致**的输出：
/// 同样是 `error_code` / `message` / `retryable` 三行，
/// 让调用方无论在哪种失败路径下看到的字段都一样。
fn render_error(chain: &str, err: allchain_core::SdkError, format: Format) -> String {
    match format {
        Format::Json => {
            // `Envelope::<Value>::err` 里的 `::<Value>` 叫 **turbofish**：
            // 调用关联函数时无法从实参反推泛型参数 T（没有 `data` 可推断），必须显式写出。
            // 第一个参数 `chain` 传的是**原始输入字符串**：
            // 未知链也要如实回显，用户才能一眼看出自己输错了什么。
            allchain_core::Envelope::<Value>::err(chain, "default", 0, err).to_json_pretty()
        }
        Format::Text => format!(
            "# chain: {chain}\nerror_code : {}\nmessage    : {}\nretryable  : {}\n",
            err.code.as_str(),
            err.message,
            err.retryable
        ),
    }
}

/// 把单个 JSON 值压成一行可读文本；长数组只显示长度，避免刷屏。
///
/// 语法说明：`Value::Array(items) if items.len() > 3` 是**带守卫（guard）的匹配**：
/// 只有元素超过 3 个的数组才折叠成 `[N 项]`；
/// 守卫不成立时会继续往下尝试后面的分支，最终落到 `other` 按默认方式打印。
/// **分支顺序很重要**：`other => ..` 必须放最后，否则会把上面所有分支都吞掉（编译器会警告）。
fn render_value(value: &Value) -> String {
    match value {
        // `null` 打印成 `-`：在对齐的表格里，字面量 `null` 容易被误读成字符串 "null"。
        Value::Null => "-".to_string(),
        // 字符串**去掉 JSON 的引号**：这里的输出是给人看的，不要求能被解析回去。
        // `s` 是 `&String`，`.clone()` 复制出一份自有 `String` 以满足返回类型。
        Value::String(s) => s.clone(),
        Value::Array(items) if items.len() > 3 => format!("[{} 项]", items.len()),
        other => other.to_string(),
    }
}

/// 把链清单渲染成定宽列表格的文本：一行表头 + 每行一条链。
///
/// 语法说明：格式串里的 `{:<6}` 表示**左对齐**且最小宽度 6
/// （`<` 左对齐、`^` 居中、省略则按类型默认——数字默认右对齐）。
/// 表头与数据行必须用同一套宽度，列才会对齐。
fn render_catalog_text(payload: &Value) -> String {
    let mut out =
        String::from("chain  symbol  decimals  unit        default_network  capabilities\n");
    // `payload.get("chains")` 得到 `Option<&Value>`，`.and_then(|c| c.as_array())`
    // 再把它变成 `Option<&Vec<Value>>`：任一步为 `None`，整体就是 `None`。
    // 这就是 `Option` 的**短路组合**，比层层嵌套 `if let` 清爽得多。
    if let Some(chains) = payload.get("chains").and_then(|c| c.as_array()) {
        for chain in chains {
            out.push_str(&format!(
                "{:<6} {:<7} {:<9} {:<11} {:<16} {}\n",
                // `chain["chain"]`：`serde_json::Value` 实现了 `Index<&str>`，
                // 键不存在时返回**静态的 `Value::Null`** 而不是 panic，
                // 所以下面可以统一用 `unwrap_or(..)` 给出兜底值。
                chain["chain"].as_str().unwrap_or("-"),
                chain["symbol"].as_str().unwrap_or("-"),
                chain["decimals"].as_u64().unwrap_or(0),
                chain["unit"].as_str().unwrap_or("-"),
                chain["default_network"].as_str().unwrap_or("-"),
                // 能力数组 -> 逗号分隔的字符串，一条链式调用走完：
                //   `.as_array()`         取数组（不是数组则整体为 None）
                //   `.map(..)`            只在是数组时才做变换，None 直接透传
                //   `.iter()`             逐项借用
                //   `.filter_map(..)`     「过滤 + 转换」一步完成：非字符串元素被丢弃
                //   `.collect::<Vec<_>>()` turbofish 里的 `_` 让编译器自己推断元素类型
                //   `.join(",")`          拼接成单个字符串
                //   `.unwrap_or_default()` 任一步失败就给空串（`String::default()`）
                chain["capabilities"]
                    .as_array()
                    .map(|c| c
                        .iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(","))
                    .unwrap_or_default(),
            ));
        }
    }
    out
}
