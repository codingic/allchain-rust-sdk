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

mod dispatch;
mod http;
mod mcp;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::Value;

use dispatch::Action;

#[derive(Parser)]
#[command(
    name = "acli",
    version,
    about = "全链统一接口：一套调用操作 eth / btc / sol / near / apt / ar / ckb / fil / sui / ton"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// 输出格式。默认 JSON——本工具面向 agent，结构化优先。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Json,
    Text,
}

/// 选链与连接参数，所有查询类子命令共用。
#[derive(Args, Debug)]
struct ChainArgs {
    /// 链标识：eth / btc / sol / near / apt / ar / ckb / fil / sui / ton
    #[arg(short, long)]
    chain: String,

    /// 网络名；十链默认均为 mainnet，可显式指定 testnet / devnet / sepolia 等
    #[arg(short, long)]
    network: Option<String>,

    /// 自定义端点；对 BTC 而言是 Esplora 索引器地址
    #[arg(long)]
    rpc_url: Option<String>,

    /// 输出格式
    #[arg(long, value_enum, default_value_t = Format::Json)]
    format: Format,
}

#[derive(Subcommand)]
enum Command {
    /// 查询链与节点状态
    Status {
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// 查询地址 / 账户余额
    #[command(alias = "getbalance")]
    Balance {
        #[command(flatten)]
        chain: ChainArgs,
        /// 地址或账户名（NEAR 传账户名）
        #[arg(long)]
        address: String,
    },
    /// 查询区块（省略 reference 时取最新）
    Block {
        #[command(flatten)]
        chain: ChainArgs,
        /// 区块引用：高度为数字，哈希为十六进制；SOL 必须传 slot
        #[arg(long)]
        reference: Option<String>,
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
        #[arg(long)]
        private_key: Option<String>,
        /// 仅本地构造并签名，不广播
        #[arg(long)]
        dry_run: bool,
        /// 源账户；NEAR 命名账户必填，其余链自动从私钥派生
        #[arg(long)]
        from: Option<String>,
    },
    /// 列出支持的链、精度与能力
    Chains {
        #[arg(long, value_enum, default_value_t = Format::Json)]
        format: Format,
    },
    /// 启动本地 HTTP 服务
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 8787)]
        port: u16,
    },
    /// 以 MCP stdio 服务器运行（供 agent 直接接入）
    Mcp,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Command::Status { chain } => run(chain, Action::Status).await,
        Command::Balance { chain, address } => run(chain, Action::Balance { address }).await,
        Command::Block { chain, reference } => run(chain, Action::Block { reference }).await,
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
            let payload = dispatch::chain_catalog();
            match format {
                Format::Json => println!("{}", serde_json::to_string_pretty(&payload)?),
                Format::Text => println!("{}", render_catalog_text(&payload)),
            }
            0
        }

        Command::Serve { host, port } => {
            http::serve(host, port).await?;
            0
        }

        Command::Mcp => {
            mcp::serve_stdio().await?;
            0
        }
    };

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// 执行一次查询并输出；失败时返回退出码 1。
async fn run(args: ChainArgs, action: Action) -> i32 {
    let ChainArgs {
        chain,
        network,
        rpc_url,
        format,
    } = args;

    let chain = match dispatch::parse_chain(&chain) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("{}", render_error(&chain, err, format));
            return 1;
        }
    };

    let envelope =
        dispatch::run_action(chain, network.as_deref(), rpc_url.as_deref(), action).await;
    let ok = envelope.ok;

    match format {
        Format::Json => println!("{}", envelope.to_json_pretty()),
        Format::Text => print!("{}", render_text(&envelope)),
    }

    if ok { 0 } else { 1 }
}

/// 把统一信封渲染成对齐的 key : value 文本。
fn render_text(envelope: &allchain_core::Envelope<Value>) -> String {
    let mut out = format!(
        "# chain: {} | network: {} | {}ms\n",
        envelope.chain, envelope.network, envelope.took_ms
    );

    match (&envelope.data, &envelope.error) {
        (Some(data), _) => {
            if let Some(obj) = data.as_object() {
                let width = obj.keys().map(|k| k.len()).max().unwrap_or(0);
                for (key, value) in obj {
                    out.push_str(&format!("{key:width$} : {}\n", render_value(value)));
                }
            } else {
                out.push_str(&format!("{data}\n"));
            }
        }
        (_, Some(err)) => {
            out.push_str(&format!("error_code : {}\n", err.code.as_str()));
            out.push_str(&format!("message    : {}\n", err.message));
            out.push_str(&format!("retryable  : {}\n", err.retryable));
        }
        _ => out.push_str("(无数据)\n"),
    }
    out
}

fn render_error(chain: &str, err: allchain_core::SdkError, format: Format) -> String {
    match format {
        Format::Json => {
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

fn render_value(value: &Value) -> String {
    match value {
        Value::Null => "-".to_string(),
        Value::String(s) => s.clone(),
        Value::Array(items) if items.len() > 3 => format!("[{} 项]", items.len()),
        other => other.to_string(),
    }
}

fn render_catalog_text(payload: &Value) -> String {
    let mut out =
        String::from("chain  symbol  decimals  unit        default_network  capabilities\n");
    if let Some(chains) = payload.get("chains").and_then(|c| c.as_array()) {
        for chain in chains {
            out.push_str(&format!(
                "{:<6} {:<7} {:<9} {:<11} {:<16} {}\n",
                chain["chain"].as_str().unwrap_or("-"),
                chain["symbol"].as_str().unwrap_or("-"),
                chain["decimals"].as_u64().unwrap_or(0),
                chain["unit"].as_str().unwrap_or("-"),
                chain["default_network"].as_str().unwrap_or("-"),
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
