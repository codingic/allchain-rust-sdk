//! 统一响应信封：三种接入形态（CLI / HTTP / MCP）返回完全一致的结构。

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ErrorCode, SdkError};

/// 失败时的错误体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl From<SdkError> for ErrorBody {
    fn from(err: SdkError) -> Self {
        Self {
            code: err.code,
            message: err.message,
            retryable: err.retryable,
        }
    }
}

/// 统一信封。
///
/// 成功时 `ok=true` 且 `data` 有值；失败时 `ok=false` 且 `error` 有值，两者互斥。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub ok: bool,
    /// 链短名；无法识别时为 `"unknown"`。
    pub chain: String,
    pub network: String,
    pub took_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl<T: Serialize> Envelope<T> {
    pub fn ok(chain: impl Into<String>, network: impl Into<String>, took_ms: u64, data: T) -> Self {
        Self {
            ok: true,
            chain: chain.into(),
            network: network.into(),
            took_ms,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(
        chain: impl Into<String>,
        network: impl Into<String>,
        took_ms: u64,
        err: SdkError,
    ) -> Self {
        Self {
            ok: false,
            chain: chain.into(),
            network: network.into(),
            took_ms,
            data: None,
            error: Some(err.into()),
        }
    }

    pub fn to_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| {
            format!("{{\"ok\":false,\"error\":{{\"code\":\"INTERNAL\",\"message\":\"序列化失败: {e}\",\"retryable\":false}}}}")
        })
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| self.to_json())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_envelope_omits_error_key() {
        let env = Envelope::ok("eth", "sepolia", 12, serde_json::json!({"a": 1}));
        let v = env.to_value().unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["chain"], "eth");
        assert!(v.get("error").is_none(), "成功响应不应包含 error 键");
        assert_eq!(v["data"]["a"], 1);
    }

    #[test]
    fn err_envelope_omits_data_key() {
        let env: Envelope<Value> =
            Envelope::err("near", "testnet", 3, SdkError::not_found("账户不存在"));
        let v = env.to_value().unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "NOT_FOUND");
        assert_eq!(v["error"]["retryable"], false);
        assert!(v.get("data").is_none(), "失败响应不应包含 data 键");
    }
}
