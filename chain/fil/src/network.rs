//! Filecoin 预置网络与 JSON-RPC 端点。
//!
//! 关于端点选择：Filecoin 没有官方公共节点，这里默认用 Glif 提供的公共 RPC。
//! 公共节点的两个已知限制，写适配器时必须考虑：
//! 1. **限流**：匿名访问有 QPS 上限，频繁调用会拿到 429；
//! 2. **方法不全**：Glif 不提供 `Filecoin.ChainGetReceipt` 等部分方法，
//!    因此查交易回执要改走 `StateSearchMsg`（见 `adapter::tx`）。
//! 自建 Lotus 节点时用 `Localnet` 或直接传自定义 URL 即可绕开这两点。

use allchain_core::SdkError;

/// 命令行 / HTTP 请求里可选的 Filecoin 网络。
///
/// 与 `core::ChainKind` 不同，`ChainKind` 区分的是「哪条链」，
/// 而这里的 `NetworkArg` 区分的是「同一条链上的哪个网络」。
/// 十链 crate 都沿用这个命名，是为了让 `acli` 门面能用同一套代码分发。
///
/// 语法说明：`#[derive(..., Copy, ...)]` 中的 `Copy` 让枚举可以自动按位复制，
/// 于是构造函数可以写 `self`（按值）而不用担心所有权被转移走。
/// 枚举没有字段、只存一个判别值，天然满足 `Copy` 的前提。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkArg {
    /// 主网。地址前缀 `f`，链上资产为真实 FIL。
    Mainnet,
    /// Calibration 校准测试网。
    ///
    /// 这是 Filecoin 目前**唯一**在维护的公共测试网，币可从水龙头免费领取。
    /// 老文档里常说的 `testnet` 在本 crate 中被映射到 Calibration，
    /// 这样调用方沿用旧习惯也不会报错。
    Calibration,
    /// 本地自建节点（通常是 `lotus daemon` 或 `forest`）。
    Localnet,
}

impl NetworkArg {
    /// Lotus JSON-RPC 端点。
    ///
    /// 语法说明：返回值 `&'static str`。`'static` 是**生命周期**标注，
    /// 表示这份字符串引用在整个程序运行期间都有效——这里是编译进二进制的字面量，
    /// 天然满足，所以不需要分配 `String`。
    pub fn rpc_url(self) -> &'static str {
        // `match self` 强制**穷尽所有变体**：将来加网络忘了补分支就编译失败，
        // 这正是 Rust 相对 switch 的安全之处。
        match self {
            // 三个端点都指向 `/rpc/v1`：Lotus 的 v1 版本 JSON-RPC 路径，
            // 所有 `Filecoin.*` 方法都挂在它下面（v0 是遗留的、已不推荐）。
            NetworkArg::Mainnet => "https://api.node.glif.io/rpc/v1",
            NetworkArg::Calibration => "https://api.calibration.node.glif.io/rpc/v1",
            // Lotus 默认监听 1234 端口。
            NetworkArg::Localnet => "http://127.0.0.1:1234/rpc/v1",
        }
    }

    /// 网络短名，会原样出现在所有 View 的 `network` 字段里。
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Calibration => "calibration",
            NetworkArg::Localnet => "localnet",
        }
    }

    /// 地址网络前缀：主网 `f`，其余 `t`。
    ///
    /// 这是 Filecoin 地址规范里的一条硬规则：**测试网地址一律以 `t` 开头**，
    /// 主网以 `f` 开头。因此同一个公钥在主网与测试网会派生出两个不同的字符串，
    /// 前缀之外的部分完全相同。这样一来，即使手滑把主网地址发给测试网节点，
    /// 节点也会直接拒绝，不会静默转错账。
    pub fn address_prefix(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "f",
            // 用 `|` 在一个分支里匹配多个变体，避免写两遍同样的返回值。
            NetworkArg::Calibration | NetworkArg::Localnet => "t",
        }
    }
}

/// 解析网络名，缺省主网。
///
/// 语法说明：参数 `Option<&str>` 表示「调用方可以不给」。
/// 用 `Option` 而不是空字符串 `""` 表达缺省，语义更明确，
/// 也杜绝了「传了个空格当合法值」这种歧义。
pub fn parse(raw: Option<&str>) -> Result<NetworkArg, SdkError> {
    // 三步链式处理，把「没传 / 传了空串 / 传了带空格的值」统一成一种判断：
    // - `raw.map(str::trim)`：只对 `Some` 内部的值做 trim（`str::trim` 直接作为函数传入，
    //   它接受 `&str` 返回 `&str`，正好匹配）；
    // - `.filter(|s| !s.is_empty())`：把空串也变成 `None`；
    // 于是「未指定」与「指定了空串」落到同一个分支。
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        // `None | Some("mainnet")`：或模式，两种输入都给主网。
        // 这样缺省即主网，与 `core::ChainKind::default_network` 的约定一致。
        None | Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("testnet") | Some("calibration") => Ok(NetworkArg::Calibration),
        Some("localnet") | Some("devnet") => Ok(NetworkArg::Localnet),
        // `other` 绑定剩余的一切，用于报错时回显用户的原始输入。
        Some(other) => Err(SdkError::invalid_argument(format!(
            "FIL 不支持的网络: {other}（可选 mainnet / calibration / localnet）"
        ))),
    }
}
