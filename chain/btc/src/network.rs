//! 网络选择（mainnet / testnet / testnet4 / signet / regtest）与默认端点。
//!
//! 领域说明：BTC 的「网络」不只影响默认端口，它还会**改变地址的编码方式**——
//! 同一个公钥在主网是 `bc1q...`、在测试网是 `tb1q...`、在 signet 是 `tb1q...`
//! （hrp 不同），传统地址的版本字节也不同。所以解析地址时必须带上网络校验，
//! 否则会出现「把主网地址发到测试网」这类事故。

// `PathBuf` 是可增长、跨平台的路径类型（相对 `&str` 路径，它处理了分隔符与编码）。
use std::path::PathBuf;

// rust-bitcoin 的 `Network` 枚举：地址编码、WIF 前缀都由它决定。
use bitcoin::Network;

/// CLI 可选网络。
///
/// 语法说明：`clap::ValueEnum` 让 clap 能把本枚举直接当 `--network` 的参数值解析；
/// 其余 derive 的用途见 core 的 `chain.rs`。
///
/// 领域说明：testnet 与 testnet4 是两代不同的测试网（testnet3 历史悠久、币值混乱，
/// testnet4 是 2024 年重启的干净版本）；signet 是**签名测试网**，
/// 出块由签名者控制因而更稳定；regtest 是完全本地的私链，可随时挖块。
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NetworkArg {
    /// 比特币主网。
    Mainnet,
    /// 传统测试网（testnet3）。
    Testnet,
    /// 新一代测试网（testnet4）。
    Testnet4,
    /// 签名测试网。
    Signet,
    /// 本地私链（regtest）。
    Regtest,
}

impl NetworkArg {
    /// 映射到 rust-bitcoin 的 [`Network`]。
    ///
    /// 这一层映射存在的意义：CLI 的参数名（如 `testnet4`）与 rust-bitcoin 的
    /// 变体名（`Testnet4`）保持一一对应，改动时只需改这一处。
    pub fn network(self) -> Network {
        match self {
            NetworkArg::Mainnet => Network::Bitcoin,
            NetworkArg::Testnet => Network::Testnet,
            NetworkArg::Testnet4 => Network::Testnet4,
            NetworkArg::Signet => Network::Signet,
            NetworkArg::Regtest => Network::Regtest,
        }
    }

    /// 网络短名，与 CLI 参数、JSON 输出保持一致。
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Testnet => "testnet",
            NetworkArg::Testnet4 => "testnet4",
            NetworkArg::Signet => "signet",
            NetworkArg::Regtest => "regtest",
        }
    }

    /// Esplora REST 端点（mempool.space 兼容实现，用于地址 / UTXO / 费率查询与广播）。
    ///
    /// ⚠️ **这不是 bitcoind 的 JSON-RPC 端点**。地址类查询（余额、UTXO）
    /// 必须有索引器支持，BTC 全节点本身做不到，因此默认指向公共索引器。
    /// regtest 没有公共索引器，只能指向本地部署的实例。
    pub fn esplora_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://mempool.space/api",
            NetworkArg::Testnet => "https://mempool.space/testnet/api",
            NetworkArg::Testnet4 => "https://mempool.space/testnet4/api",
            NetworkArg::Signet => "https://mempool.space/signet/api",
            NetworkArg::Regtest => "http://127.0.0.1:3000/api",
        }
    }

    /// bitcoind JSON-RPC 默认端口。
    ///
    /// 各网络端口固定：主网 8332、testnet3 18332、testnet4 48332、
    /// signet 38332、regtest 18443。注意 RPC 端口与 P2P 端口是两套。
    pub fn node_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "http://127.0.0.1:8332",
            NetworkArg::Testnet => "http://127.0.0.1:18332",
            NetworkArg::Testnet4 => "http://127.0.0.1:48332",
            NetworkArg::Signet => "http://127.0.0.1:38332",
            NetworkArg::Regtest => "http://127.0.0.1:18443",
        }
    }

    /// 区块浏览器基址，用于拼接交易 / 地址链接。
    pub fn explorer_base(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://mempool.space",
            NetworkArg::Testnet => "https://mempool.space/testnet",
            NetworkArg::Testnet4 => "https://mempool.space/testnet4",
            NetworkArg::Signet => "https://mempool.space/signet",
            NetworkArg::Regtest => "http://127.0.0.1:3000",
        }
    }

    /// bitcoind 数据目录下该网络对应的子目录（cookie 探测用）。
    ///
    /// 主网直接用数据目录根，其余网络各自一个子目录。
    /// 主网返回空串是刻意的：`PathBuf::join("")` 会原样返回自身，
    /// 于是下面的探测逻辑不必为主网单独分支。
    fn datadir_subdir(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "",
            NetworkArg::Testnet => "testnet3",
            NetworkArg::Testnet4 => "testnet4",
            NetworkArg::Signet => "signet",
            NetworkArg::Regtest => "regtest",
        }
    }

    /// 探测 bitcoind 的 `.cookie` 文件（macOS 与 Linux 两条常见路径），不存在返回 None。
    ///
    /// 领域说明：bitcoind 默认不设固定密码，而是在数据目录里写一个
    /// `__cookie__:随机密码` 格式的 `.cookie` 文件供本地 RPC 使用，
    /// 每次启动都会轮换。因此**运行时读取**比让用户手抄密码安全得多。
    pub fn default_cookie(self) -> Option<PathBuf> {
        // `var_os("HOME")` 返回 `Option<OsString>`：`?` 在取不到时直接返回 None，
        // 把「没有 HOME 环境变量」与「文件不存在」合并为同一种结果。
        // 用 `var_os` 而非 `var()`：路径可能不是合法 UTF-8，前者不做校验。
        let home = PathBuf::from(std::env::var_os("HOME")?);
        let sub = self.datadir_subdir();
        // `[..]` 数组 → `.into_iter()` 得到**按值**的迭代器（Rust 2021 起），
        // 每个元素是 `PathBuf` 本身而非引用。
        [
            home.join("Library/Application Support/Bitcoin").join(sub),
            home.join(".bitcoin").join(sub),
        ]
        .into_iter()
        // 各自追加 `.cookie` 文件名。
        .map(|dir| dir.join(".cookie"))
        // `find(闭包)` 返回第一个满足条件的元素（`Option<PathBuf>`）——
        // 短路求值：命中第一个就不再往后查，省一次 stat 系统调用。
        .find(|path| path.is_file())
    }
}

/// 实现 `Display`，使 `NetworkArg` 支持 `{}` 打印。
///
/// 语法说明：`impl Trait for Type` 是 trait 实现块，与上面的 `impl NetworkArg`
/// （固有实现块）是两回事。方法签名必须与 trait 定义完全一致。
impl std::fmt::Display for NetworkArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `write_str` 比 `write!` 略快：没有格式串解析的开销。
        f.write_str(self.as_str())
    }
}
