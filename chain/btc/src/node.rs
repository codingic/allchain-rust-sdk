//! 网络选择、认证方式与 JSON-RPC 客户端构造。
//!
//! 说明：本模块是**早先的单链 CLI 遗留**，与 `network.rs` 功能重叠
//! （它只支持 mainnet / testnet / regtest 三个网络，且只探测 macOS 路径）。
//! 现行链路统一走 `backend::node_config` + `NetworkArg::default_cookie`，
//! 那里覆盖五个网络且同时探测 macOS 与 Linux 两条路径。
//! 保留本文件是为了不破坏可能存在的外部引用。

use std::path::PathBuf;

use anyhow::{Context, Result};
use bitcoincore_rpc::{Auth, Client};
// 直接导入 `ValueEnum` 这个 trait 本身，于是下面可以简写成 `ValueEnum`
// 而不必每次都写 `clap::ValueEnum`。
use clap::ValueEnum;

/// 预置网络选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
    Regtest,
}

impl NetworkArg {
    /// 比特币核心各网络的默认 RPC 端口。
    pub fn default_rpc_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "http://127.0.0.1:8332",
            NetworkArg::Testnet => "http://127.0.0.1:18332",
            NetworkArg::Regtest => "http://127.0.0.1:18443",
        }
    }

    /// 各网络默认的 cookie 文件路径（macOS 数据目录）。
    ///
    /// 注意这里**不检查文件是否存在**——只拼出路径。是否可用由调用方
    /// （下面的 `connect`）用 `.filter(|p| p.exists())` 判断。
    pub fn default_cookie_path(self) -> Option<PathBuf> {
        // 取不到 HOME 时直接返回 None（而不是 panic）。
        let home = std::env::var_os("HOME")?;
        let dir = match self {
            NetworkArg::Mainnet => "Bitcoin",
            NetworkArg::Testnet => "Bitcoin/testnet3",
            NetworkArg::Regtest => "Bitcoin/regtest",
        };
        // `PathBuf::from(home).join(..).join(..)` 链式拼接，
        // 分隔符由平台决定，不必手写 `/`。
        Some(
            PathBuf::from(home)
                .join("Library/Application Support")
                .join(dir)
                .join(".cookie"),
        )
    }

    /// 映射到 rust-bitcoin 的 `Network`（用于地址编码）。
    pub fn network(self) -> bitcoin::Network {
        match self {
            NetworkArg::Mainnet => bitcoin::Network::Bitcoin,
            NetworkArg::Testnet => bitcoin::Network::Testnet,
            NetworkArg::Regtest => bitcoin::Network::Regtest,
        }
    }

    /// 网络短名。
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Testnet => "testnet",
            NetworkArg::Regtest => "regtest",
        }
    }
}

/// 构造 bitcoind RPC 客户端。
///
/// 认证优先级：显式 `--user/--pass` > `--cookie` > 该网络默认 cookie 文件。
///
/// 这三种方式对应 bitcoind 的三种认证配置：
/// - `UserPass`  —— `rpcuser` / `rpcpassword`，适合远程节点；
/// - `CookieFile` —— 本地数据目录下的 `.cookie`，bitcoind 默认方式；
/// - `None`      —— 无认证，仅用于 regtest 这类完全可信的本地环境。
pub fn connect(
    rpc_url: &str,
    user: Option<&str>,
    pass: Option<&str>,
    cookie: Option<&str>,
    network: NetworkArg,
) -> Result<Client> {
    // `if let (Some(u), Some(p)) = (user, pass)`：对**元组**做模式匹配，
    // 一次性确认两个 `Option` 都是 `Some` 并同时取出内部值。
    // 只有 user / pass **同时**给出才走这条路——只给一个是配置错误，落到下面报错。
    if let (Some(u), Some(p)) = (user, pass) {
        return Client::new(rpc_url, Auth::UserPass(u.to_string(), p.to_string()))
            .context("连接 bitcoind 失败（用户密码认证）");
    }

    let cookie_path = cookie
        // `&str` → `PathBuf`。
        .map(PathBuf::from)
        // `or_else(闭包)`：前者为 `None` 时**才**调用闭包去探测默认路径
        // （惰性求值，与 `or(..)` 的无条件求值相对）。
        .or_else(|| network.default_cookie_path())
        // 拼出来的路径未必存在，过滤掉不存在的，避免后面读文件时才报错。
        .filter(|p| p.exists());

    match cookie_path {
        Some(path) => {
            // `.display()` 得到一个可用于打印的包装类型，
            // 它不要求路径是合法 UTF-8；`.to_string()` 再转成 `String` 供 `format!` 使用。
            let display = path.display().to_string();
            Client::new(rpc_url, Auth::CookieFile(path))
                .with_context(|| format!("连接 bitcoind 失败（cookie: {display}）"))
        }
        // 走到这里说明三种认证方式都不可用，只能无认证连接；
        // 失败时把「应该怎么配」写进错误信息里，省去用户查文档。
        None => Client::new(rpc_url, Auth::None).with_context(|| {
            format!(
                "连接 bitcoind 失败：未找到认证信息。请用 --user/--pass 或 --cookie 指定，\
                 默认 cookie 路径为 {}",
                network
                    .default_cookie_path()
                    .map(|p| p.display().to_string())
                    // 连默认路径都拼不出来（没有 HOME），退化成空串而不是 panic。
                    .unwrap_or_default()
            )
        }),
    }
}
