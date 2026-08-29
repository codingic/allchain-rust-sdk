//! 统一错误码：让调用方能程序化判断失败原因，而不必解析中文错误文本。

use serde::{Deserialize, Serialize};

/// 跨链统一的错误分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
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
    pub fn retryable(self) -> bool {
        matches!(self, ErrorCode::NetworkError | ErrorCode::RpcError)
    }
}

/// 统一错误载体。
#[derive(Debug, Clone, Serialize)]
pub struct SdkError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl SdkError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: code.retryable(),
        }
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unsupported, message)
    }

    /// 附带一段上游原始错误，便于排查但不污染 message。
    pub fn with_source(mut self, source: impl std::fmt::Display) -> Self {
        self.message = format!("{}（上游: {source}）", self.message);
        self
    }
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for SdkError {}

/// 把各链 SDK 抛出的 `anyhow::Error` 归类为统一错误码。
///
/// 分类基于错误文本的特征词匹配，属于启发式：适配器若有更精确的信息，
/// 应自行构造 [`SdkError`] 而不是走这里。
impl From<anyhow::Error> for SdkError {
    fn from(err: anyhow::Error) -> Self {
        classify(&format!("{err:?}"))
    }
}

/// 供需要字符串输入的场景复用同一套分类规则。
pub fn classify(text: &str) -> SdkError {
    let lower = text.to_ascii_lowercase();
    let code = if contains_any(
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
        ErrorCode::RpcError
    };
    SdkError::new(code, text)
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_not_found() {
        let err = classify("handler error: [account foo.near does not exist while viewing]");
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(!err.retryable);
    }

    #[test]
    fn classifies_network_as_retryable() {
        let err = classify("error sending request: connection timeout");
        assert_eq!(err.code, ErrorCode::NetworkError);
        assert!(err.retryable);
    }

    #[test]
    fn classifies_invalid_argument() {
        let err = classify("非法以太坊地址: 0xzz（期望 0x + 40 位十六进制）");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert!(!err.retryable);
    }

    #[test]
    fn unknown_falls_back_to_rpc_error() {
        assert_eq!(classify("节点拒绝了请求").code, ErrorCode::RpcError);
    }
}
