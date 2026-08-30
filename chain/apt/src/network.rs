//! Aptos 预置网络与 REST 端点。
//!
//! Aptos 官方为每条网络提供独立的 REST 网关域名，路径统一带 `/v1` 前缀，
//! 因此本模块只需给出 base URL，适配器里拼 `/accounts/...` 这类相对路径即可。

use allchain_core::SdkError;

/// 支持的网络。`localnet` 指向本地起的 aptos-node（默认 8080 端口）。
///
/// 语法说明：这里派生了 `Copy`，所以枚举可以**按值传递而不转移所有权**——
/// `net.as_str()` 之后再 `net.rpc_url()` 依然合法（见 `adapter.rs` 的构造函数）。
/// 如果去掉 `Copy`，第二次使用就会触发「use of moved value」编译错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
    Devnet,
    /// 本地节点。域名是回环地址，无 TLS，便于 `aptos node run-localnet` 调试。
    Localnet,
}

impl NetworkArg {
    /// 该网络的 REST v1 base URL。
    ///
    /// 语法说明：`self`（不带 `&`）按值接收，靠 `Copy` 避免所有权转移；
    /// 返回 `&'static str` 是编译进二进制的字符串字面量，零分配。
    pub fn rpc_url(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "https://api.mainnet.aptoslabs.com/v1",
            NetworkArg::Testnet => "https://api.testnet.aptoslabs.com/v1",
            NetworkArg::Devnet => "https://api.devnet.aptoslabs.com/v1",
            NetworkArg::Localnet => "http://127.0.0.1:8080/v1",
        }
    }

    /// 网络短名，与 CLI `--network` 参数取值一致。
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Testnet => "testnet",
            NetworkArg::Devnet => "devnet",
            NetworkArg::Localnet => "localnet",
        }
    }
}

/// 解析网络名，缺省主网。
///
/// 语法说明：参数 `Option<&str>` 表达「调用方可能没给网络」；
/// 与之相对，`&str` 无法表达「没给」，用空字符串代替又容易被误传。
pub fn parse(raw: Option<&str>) -> Result<NetworkArg, SdkError> {
    // 一段典型的三段式链式调用，逐段拆开：
    // 1. `raw.map(str::trim)`：`Option<&str>` → `Option<&str>`，把内部字符串去掉首尾空白。
    //    注意这里传的是**函数路径** `str::trim` 而非闭包 `|s| s.trim()`，两者等价但前者更短。
    // 2. `.filter(|s| !s.is_empty())`：把空串的 `Some("")` 也变成 `None`。
    //    闭包参数是 `&&str`（因为 `map` 拿到的是引用），`s.is_empty()` 会自动解引用。
    // 3. 结果交给 `match`，于是 `None` 同时覆盖了「没传」和「传了空白串」两种情形。
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(NetworkArg::Mainnet),
        Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("testnet") => Ok(NetworkArg::Testnet),
        Some("devnet") => Ok(NetworkArg::Devnet),
        Some("localnet") => Ok(NetworkArg::Localnet),
        // `Some(other)`：绑定变量捕获未匹配到的值，用于拼进错误信息。
        // 这条分支必须放最后，否则会抢走上面所有分支。
        Some(other) => Err(SdkError::invalid_argument(format!(
            "APT 不支持的网络: {other}（可选 mainnet / testnet / devnet / localnet）"
        ))),
    }
}
