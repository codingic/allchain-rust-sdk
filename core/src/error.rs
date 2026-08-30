//! 统一错误码：让调用方能程序化判断失败原因，而不必解析中文错误文本。
//!
//! 设计意图：十链适配器的上游报错形态各异（JSON-RPC error、REST 4xx、GraphQL errors、
//! 各链 SDK 自己的 `anyhow::Error`），如果原样透出，调用方就得按链写十套分支。
//! 本模块把所有这些收敛成**七个稳定错误码 + 一个 `retryable` 标志**，
//! 上层只需判断 `code` 与 `retryable` 两个字段即可决定「重试 / 报错 / 提示用户」。

use serde::{Deserialize, Serialize};

/// 跨链统一的错误分类。
///
/// 只保留**对调用方决策有意义**的区分度：不区分「哪条链出的问题」，
/// 只区分「这是谁的锅、要不要重试」。
///
/// 语法说明：
/// - `#[derive(..., Copy, ...)]` 里的 `Copy` 表示赋值/传参时**自动按位复制**，
///   不再转移所有权。枚举没有字段、只存一个判别值，天然满足 `Copy` 的前提。
/// - `PartialEq` / `Eq` 让枚举可以用 `==` 比较（测试里大量依赖这一点）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
// serde 属性：把变体名从 `InvalidArgument` 转成 `INVALID_ARGUMENT` 再序列化。
// 与 `chain.rs` 里用的 `rename_all = "lowercase"` 是同一类开关，只是命名风格不同。
// 大写蛇形是错误码的事实标准，也天然避开了与字段名的大小写冲突。
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// 参数缺失或格式非法（地址、哈希、金额等）。
    InvalidArgument,
    /// 目标不存在（账户未创建、交易/区块查不到）。
    NotFound,
    /// 节点返回错误（RPC 层拒绝、执行失败）。
    RpcError,
    /// 网络层故障（超时、连接失败、DNS）。
    NetworkError,
    /// 响应解析失败（上游结构变更、编码异常）。
    ParseError,
    /// 该链不支持此能力。
    Unsupported,
    /// 未归类的内部错误。
    Internal,
}

/// 固有实现块：给 [`ErrorCode`] 挂上一组工具方法。
impl ErrorCode {
    /// 错误码的稳定字符串形式，与 serde 序列化结果保持一致。
    ///
    /// 语法说明：
    /// - `self`（不带 `&`）按值接收；因为枚举实现了 `Copy`，调用后原值仍可用。
    /// - 返回值 `&'static str`：`'static` 是**生命周期**标注，表示这段字符串
    ///   在整个进程运行期都有效（此处是编译进二进制的字面量，当然成立）。
    pub fn as_str(self) -> &'static str {
        // `match` 强制穷尽所有变体：少写一个分支就编译失败，
        // 这正是「加错误码时不会忘了补字符串」的保障。
        match self {
            ErrorCode::InvalidArgument => "INVALID_ARGUMENT",
            ErrorCode::NotFound => "NOT_FOUND",
            ErrorCode::RpcError => "RPC_ERROR",
            ErrorCode::NetworkError => "NETWORK_ERROR",
            ErrorCode::ParseError => "PARSE_ERROR",
            ErrorCode::Unsupported => "UNSUPPORTED",
            ErrorCode::Internal => "INTERNAL",
        }
    }

    /// 是否值得重试。只有瞬态故障返回 true，参数类错误重试无意义。
    ///
    /// 语法说明：`matches!(值, 模式..)` 是标准库宏，等价于
    /// `match 值 { 模式 => true, _ => false }`，只是更短。末尾的 `!` 表示宏而非函数。
    pub fn retryable(self) -> bool {
        matches!(self, ErrorCode::NetworkError | ErrorCode::RpcError)
    }
}

/// 统一错误载体。
///
/// 注意这里**只派生了 `Serialize`、没有 `Deserialize`**：错误是本 SDK 的产出物，
/// 只需要向外输出，不需要从 JSON 还原；少一个派生就少一份约束。
/// 同理也没有 `PartialEq`——两个错误的 `message` 是否相同并不重要，
/// 比较 `code` 就够了，避免误把文案当契约。
///
/// 语法说明：`#[derive(Serialize)]` 让它可以被 `serde_json::to_value` 直接处理。
#[derive(Debug, Clone, Serialize)]
pub struct SdkError {
    /// 机器可读的错误分类。程序化判断（重试 / 提示 / 告警）一律看这个字段。
    pub code: ErrorCode,
    /// 面向人类的描述，可能含上游原文。文案会随版本调整，**不要**用它做分支判断。
    pub message: String,
    /// 是否值得重试。由 `code.retryable()` 在构造时算出并缓存，避免调用方每次自己判断。
    pub retryable: bool,
}

/// 固有实现块：构造器族。
///
/// 刻意只暴露 `new` + 三个便捷构造 + `with_source`，而不暴露「直接改 `code`」的口子：
/// `retryable` 必须与 `code` 保持一致，若允许外部随意改字段，这个不变量就守不住了。
impl SdkError {
    /// 底层构造器。`retryable` 由错误码推导，不允许外部传入不一致的值。
    ///
    /// 语法说明：`impl Into<String>` 让调用方既能传 `&str` 字面量，
    /// 也能传已经分配好的 `String`（后者不会再多分配一次）。
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            // `.into()` 完成 `&str` / `String` -> `String` 的转换，目标类型由字段类型推断。
            message: message.into(),
            // 委托给 `ErrorCode::retryable()`，保证「码」与「是否可重试」永远一致。
            retryable: code.retryable(),
        }
    }

    /// 便捷构造：参数非法。
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        // `Self::new(..)` 调用同 impl 块里的另一个关联函数（类似其它语言的静态方法）。
        Self::new(ErrorCode::InvalidArgument, message)
    }

    /// 便捷构造：目标不存在。
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    /// 便捷构造：该链不支持此能力。
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unsupported, message)
    }

    /// 附带一段上游原始错误，便于排查但不污染 message。
    ///
    /// 语法说明：`mut self` 表示**按值接收一份可变副本**，改完再 `return self` 交回去，
    /// 这是 Rust 里 builder（链式构造）模式的经典写法，与 `&mut self -> ()`
    /// 那种「原地修改」风格相对：链式写法可以写成
    /// `SdkError::not_found("x").with_source(e)` 一气呵成。
    ///
    /// 参数类型 `impl std::fmt::Display` 表示「任何实现了 `Display` 的类型」，
    /// 比 `impl Into<String>` 更宽松——不一定非得是字符串，能打印就行。
    pub fn with_source(mut self, source: impl std::fmt::Display) -> Self {
        // 内联捕获 `{source}` 自动取用同名变量。
        // 上游原文放在括号里作为补充说明，主 message 仍是 SDK 自己的说法，
        // 这样日志可读，而调用方按前缀匹配也不会被上游文案带偏。
        self.message = format!("{}（上游: {source}）", self.message);
        // 返回自身，支持继续链式调用。这一行**没有分号**，是返回值。
        self
    }
}

/// 实现 `Display` trait，让 `SdkError` 支持 `{}` 格式化与 `to_string()`。
///
/// 语法说明：`impl Trait for Type` 是 **trait 实现块**，与上面的 `impl SdkError`
/// （固有实现块）是两回事：固有方法必须用 `SdkError::xxx` / `err.xxx` 调用，
/// 而 trait 方法可以被任何「把 `SdkError` 当 `Display` 用」的泛型代码调用。
impl std::fmt::Display for SdkError {
    // trait 方法签名必须照抄 trait 定义，不能自创。
    // `&mut Formatter<'_>` 中的 `'_` 是**匿名生命周期**：
    // 「这里有个生命周期参数，但我懒得给它起名，编译器你推断」。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `write!` 宏把格式化结果写进 `f`；它返回 `fmt::Result`，
        // 这一步出错（如底层 IO 失败）时用 `?` 或直接返回都可以，这里直接返回。
        write!(f, "[{}] {}", self.code.as_str(), self.message)
    }
}

/// 实现标准库的 `Error` trait，把 `SdkError` 纳入 Rust 的错误生态：
/// 之后就能放进 `anyhow::Error`、`Box<dyn std::error::Error>`，或被 `?` 自动转换。
///
/// 语法说明：`Error` 除了 `source()` 外的方法都有默认实现，
/// 所以这个 impl 块**函数体是空的**——声明「我是一个错误类型」即可。
/// 空块 `{}` 不能省略，那是语法的一部分。
impl std::error::Error for SdkError {}

/// 把各链 SDK 抛出的 `anyhow::Error` 归类为统一错误码。
///
/// 分类基于错误文本的特征词匹配，属于启发式：适配器若有更精确的信息，
/// 应自行构造 [`SdkError`] 而不是走这里。
///
/// 实现 `From` 的额外收益：适配器里可以直接写 `some_anyhow_call()?`，
/// `?` 运算符会自动调用这里的 `from` 完成转换，不用手写 `map_err`。
impl From<anyhow::Error> for SdkError {
    fn from(err: anyhow::Error) -> Self {
        // `{err:?}` 用 `Debug` 格式化。`anyhow` 的 `Debug` 实现会打印
        // **整条错误链**（含 source），比 `Display` 只打印最外层信息量大得多，
        // 特征词匹配才更准。
        classify(&format!("{err:?}"))
    }
}

/// 供需要字符串输入的场景复用同一套分类规则。
///
/// 注意 `classify` 是**顺序敏感**的 if-else 链：先判 NotFound、再判 Network、
/// 再判 InvalidArgument、最后 ParseError，兜底才落到 RpcError。
/// 调整关键词时要留意顺序，例如一个同时含 "timeout" 与 "invalid" 的文本，
/// 会先被判成 NetworkError。
pub fn classify(text: &str) -> SdkError {
    // 统一转小写，让后续所有关键词只写小写即可。
    // `to_ascii_lowercase` 只处理 ASCII，比 `to_lowercase`（含 Unicode 全角转换）更快，
    // 对错误文本里的英文关键词完全够用。
    let lower = text.to_ascii_lowercase();
    // Rust 的 `if / else if / else` 是一套**表达式**，整体有值，
    // 所以能直接赋值给 `code`，不需要先声明 `let mut code`。
    let code = if contains_any(
        // `&lower`：`lower` 是 `String`，`&String` 会**自动解引用强制转换**（deref coercion）
        // 成 `&str`，正好匹配参数类型。
        // `&[..]` 是数组字面量的借用，即切片 `&[&str]`。
        &lower,
        &[
            "does not exist",
            "not found",
            "doesn't exist",
            "unknown account",
            "unknown block",
            "不存在",
            "未找到",
        ],
    ) {
        ErrorCode::NotFound
    } else if contains_any(
        &lower,
        &[
            "timeout",
            "timed out",
            "connect",
            "dns",
            "connection refused",
            "超时",
            "连接",
            "网络",
        ],
    ) {
        ErrorCode::NetworkError
    } else if contains_any(
        &lower,
        &[
            "invalid",
            "expected",
            "parse",
            "malformed",
            "非法",
            "解析",
            "格式",
        ],
    ) {
        ErrorCode::InvalidArgument
    } else if contains_any(&lower, &["deserialize", "serde", "decode", "解码"]) {
        ErrorCode::ParseError
    } else {
        // 兜底：来自节点、但说不清是哪类问题的一律归为 RpcError（可重试）。
        ErrorCode::RpcError
    };
    // 原始文本整体作为 message 保留，避免排查时丢失上下文。
    SdkError::new(code, text)
}

/// 私有辅助函数：判断 `haystack` 是否包含 `needles` 中的任意一个。
///
/// 参数用 `&[&str]`（切片）而不是 `Vec<&str>` 或 `[&str; N]`：
/// - `&[T]` 可以是任意长度，且不取得所有权；
/// - 调用方既能传数组字面量的借用，也能传 `Vec` 的借用（`&vec` 会自动转成切片）。
///   这样上层的四组关键词长度各不相同也不会有问题。
fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    // `.iter()` 产生 `&&str` 的迭代器；`.any(|n| ..)` 是**短路**的：
    // 命中第一个就立即返回 true，不再遍历剩下的。
    // `|n| ...` 是闭包语法，竖线里是参数列表。
    needles.iter().any(|n| haystack.contains(n))
}

/// 单元测试模块：`#[cfg(test)]` 保证它只在 `cargo test` 时编译，正式构建里不存在。
///
/// 这里的用例同时也是 `classify` 的**行为契约**：关键词表一旦调整，
/// 分类结果变了就会立刻失败，避免无声地改变调用方的重试策略。
#[cfg(test)]
mod tests {
    use super::*;

    /// 账户不存在 → NotFound，且不可重试。
    #[test]
    fn classifies_not_found() {
        let err = classify("handler error: [account foo.near does not exist while viewing]");
        assert_eq!(err.code, ErrorCode::NotFound);
        // `assert!(!err.retryable)`：账户不存在是确定性结果，重试没有意义。
        assert!(!err.retryable);
    }

    /// 网络类故障 → NetworkError，且可重试。
    #[test]
    fn classifies_network_as_retryable() {
        let err = classify("error sending request: connection timeout");
        assert_eq!(err.code, ErrorCode::NetworkError);
        assert!(err.retryable);
    }

    /// 中文关键词同样生效：`非法` 命中 InvalidArgument。
    #[test]
    fn classifies_invalid_argument() {
        let err = classify("非法以太坊地址: 0xzz（期望 0x + 40 位十六进制）");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert!(!err.retryable);
    }

    /// 没有任何特征词时，兜底为 RpcError（保守地按「可重试」处理）。
    #[test]
    fn unknown_falls_back_to_rpc_error() {
        assert_eq!(classify("节点拒绝了请求").code, ErrorCode::RpcError);
    }
}
