//! 新链适配器共用的极简 HTTP 工具：REST GET、JSON-RPC 2.0 POST、GraphQL POST。
//!
//! 设计目标：
//! - 只依赖 reqwest，不绑定任何一条链的官方 SDK，避免六条链各自拖入一棵依赖树；
//! - 上游错误在这一层就归类为统一的 [`SdkError`]，适配器只关心字段提取；
//! - 响应统一先反序列化为 `serde_json::Value`，由各适配器按链上真实结构取字段，
//!   这样上游字段微调时不需要维护一大批镜像结构体。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use allchain_core::{ErrorCode, SdkError};
use serde_json::Value;

const TIMEOUT: Duration = Duration::from_secs(25);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const USER_AGENT: &str = concat!("allchain-sdk/", env!("CARGO_PKG_VERSION"));

/// 一个绑定了 base URL 的 HTTP 客户端，可廉价克隆（内部 `Arc`）。
#[derive(Clone)]
pub struct Http {
    base: String,
    client: reqwest::Client,
    next_id: std::sync::Arc<AtomicU64>,
}

impl Http {
    /// 构造客户端；`base` 末尾的 `/` 会被去掉，方便和 `path` 直接拼接。
    pub fn new(base: &str) -> Result<Self, SdkError> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|e| {
                SdkError::new(ErrorCode::Internal, format!("构造 HTTP 客户端失败: {e}"))
            })?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            client,
            next_id: std::sync::Arc::new(AtomicU64::new(1)),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// REST GET，返回原始文本（用于纯文本余额、高度等接口）。
    pub async fn get_text(&self, path: &str) -> Result<String, SdkError> {
        let url = format!("{}{}", self.base, path);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| transport_error(&url, e))?;
        read_text(resp, &url).await
    }

    /// REST GET，解析为 JSON 值。
    pub async fn get_value(&self, path: &str) -> Result<Value, SdkError> {
        let url = format!("{}{}", self.base, path);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| transport_error(&url, e))?;
        let body = read_text(resp, &url).await?;
        serde_json::from_str(&body).map_err(|e| {
            SdkError::new(
                ErrorCode::ParseError,
                format!("解析 {url} 的 JSON 失败: {e}; 原文: {}", truncate(&body)),
            )
        })
    }

    /// 发送一次 JSON-RPC 2.0 调用，返回 `result` 字段；上游 `error` 映射为 `RPC_ERROR`。
    pub async fn jsonrpc(&self, method: &str, params: Value) -> Result<Value, SdkError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let url = self.base.clone();
        let resp = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| transport_error(&url, e))?;
        let body = read_text(resp, &url).await?;
        let value: Value = serde_json::from_str(&body).map_err(|e| {
            SdkError::new(
                ErrorCode::ParseError,
                format!("解析 {method} 响应失败: {e}; 原文: {}", truncate(&body)),
            )
        })?;
        if let Some(err) = value.get("error")
            && !err.is_null()
        {
            return Err(classify_upstream(&format!("{method} 返回错误: {err}")));
        }
        value.get("result").cloned().ok_or_else(|| {
            SdkError::new(
                ErrorCode::RpcError,
                format!("{method} 响应缺少 result 字段: {value}"),
            )
        })
    }

    /// 发送一次 GraphQL 查询，返回 `data`；`errors` 非空时映射为 `RPC_ERROR`。
    pub async fn graphql(&self, query: &str) -> Result<Value, SdkError> {
        let url = self.base.clone();
        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "query": query }))
            .send()
            .await
            .map_err(|e| transport_error(&url, e))?;
        let body = read_text(resp, &url).await?;
        let value: Value = serde_json::from_str(&body).map_err(|e| {
            SdkError::new(
                ErrorCode::ParseError,
                format!("解析 GraphQL 响应失败: {e}; 原文: {}", truncate(&body)),
            )
        })?;
        if let Some(errors) = value
            .get("errors")
            .filter(|v| !v.is_null() && !v.as_array().is_some_and(|a| a.is_empty()))
        {
            return Err(SdkError::new(
                ErrorCode::RpcError,
                format!("GraphQL 返回错误: {errors}"),
            ));
        }
        value
            .get("data")
            .cloned()
            .ok_or_else(|| SdkError::new(ErrorCode::RpcError, "GraphQL 响应缺少 data 字段"))
    }
}

async fn read_text(resp: reqwest::Response, url: &str) -> Result<String, SdkError> {
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| SdkError::new(ErrorCode::NetworkError, format!("读取 {url} 响应失败: {e}")))?;
    if status.is_success() {
        return Ok(body);
    }
    let snippet = truncate(body.trim());
    let code = if status == reqwest::StatusCode::NOT_FOUND {
        ErrorCode::NotFound
    } else if status == reqwest::StatusCode::BAD_REQUEST
        || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY
    {
        ErrorCode::InvalidArgument
    } else {
        ErrorCode::RpcError
    };
    Err(SdkError::new(
        code,
        format!("{url} 返回 HTTP {status}: {snippet}"),
    ))
}

fn transport_error(url: &str, err: reqwest::Error) -> SdkError {
    let code = if err.is_connect() || err.is_timeout() {
        ErrorCode::NetworkError
    } else {
        ErrorCode::RpcError
    };
    SdkError::new(code, format!("请求 {url} 失败: {err}"))
}

/// 上游错误文本启发式分类（与 core::error::classify 同思路，避免循环依赖）。
fn classify_upstream(text: &str) -> SdkError {
    let lower = text.to_ascii_lowercase();
    let code = if lower.contains("not found")
        || lower.contains("not_found")
        || lower.contains("does not exist")
    {
        ErrorCode::NotFound
    } else if lower.contains("invalid") || lower.contains("parse") || lower.contains("malformed") {
        ErrorCode::InvalidArgument
    } else {
        ErrorCode::RpcError
    };
    SdkError::new(code, text)
}

fn truncate(text: &str) -> String {
    const MAX: usize = 300;
    if text.chars().count() <= MAX {
        text.to_string()
    } else {
        format!("{}...", text.chars().take(MAX).collect::<String>())
    }
}

// ---------------------------------------------------------------------------
// 值提取工具：各链数字可能是 JSON number、十进制字符串或 `0x` 十六进制字符串。
// ---------------------------------------------------------------------------

/// 从 JSON 值取 `field` 字段并解析为 u64，字段缺失时报明确错误。
pub fn field_u64(value: &Value, field: &str) -> Result<u64, SdkError> {
    let v = value.get(field).ok_or_else(|| {
        SdkError::new(
            ErrorCode::ParseError,
            format!("响应缺少字段 `{field}`: {value}"),
        )
    })?;
    loose_u64(v)
}

/// 宽松解析 u64：数字 / 十进制字符串 / `0x` 十六进制字符串。
pub fn loose_u64(value: &Value) -> Result<u64, SdkError> {
    match value {
        Value::Number(n) => n.as_u64().ok_or_else(|| {
            SdkError::new(
                ErrorCode::ParseError,
                format!("数字超出 u64 范围或为负数: {n}"),
            )
        }),
        Value::String(s) => parse_integer_str(s)
            .and_then(|n| u64::try_from(n).map_err(|_| ()))
            .map_err(|_| SdkError::new(ErrorCode::ParseError, format!("无法解析为 u64: {s}"))),
        other => Err(SdkError::new(
            ErrorCode::ParseError,
            format!("期望数字，实际为 {other}"),
        )),
    }
}

/// 宽松解析 u128（大余额场景，如 winston / attoFIL / nanoton）。
pub fn loose_u128(value: &Value) -> Result<u128, SdkError> {
    match value {
        Value::Number(n) => n.as_u128().ok_or_else(|| {
            SdkError::new(
                ErrorCode::ParseError,
                format!("数字超出 u128 范围或为负数: {n}"),
            )
        }),
        Value::String(s) => parse_integer_str(s)
            .map_err(|_| SdkError::new(ErrorCode::ParseError, format!("无法解析为 u128: {s}"))),
        other => Err(SdkError::new(
            ErrorCode::ParseError,
            format!("期望数字，实际为 {other}"),
        )),
    }
}

fn parse_integer_str(s: &str) -> Result<u128, ()> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16).map_err(|_| ())
    } else {
        t.parse::<u128>().map_err(|_| ())
    }
}

/// 微秒级时间戳（字符串或数字）转 Unix 秒。
pub fn micros_to_seconds(value: &Value) -> Result<i64, SdkError> {
    let micros =
        match value {
            Value::String(s) => s.trim().parse::<i128>().map_err(|_| {
                SdkError::new(ErrorCode::ParseError, format!("非法微秒时间戳: {s}"))
            })?,
            Value::Number(n) => n.as_i64().map(i128::from).ok_or_else(|| {
                SdkError::new(ErrorCode::ParseError, format!("非法微秒时间戳: {n}"))
            })?,
            other => {
                return Err(SdkError::new(
                    ErrorCode::ParseError,
                    format!("非法微秒时间戳: {other}"),
                ));
            }
        };
    Ok((micros / 1_000_000) as i64)
}

/// 解析 RFC3339 / ISO-8601 字符串（如 `2026-08-29T13:19:32.051Z`）为 Unix 秒。
///
/// 不引入 chrono/time 依赖：固定截取年月日时分秒，用 Howard Hinnant 的
/// civil-from-days 公式换算，足够覆盖各链节点返回的 UTC 时间格式。
pub fn rfc3339_to_unix(raw: &str) -> Result<i64, SdkError> {
    let parse_err = || SdkError::new(ErrorCode::ParseError, format!("非法 RFC3339 时间: {raw}"));
    let (date, rest) = raw.split_once('T').ok_or_else(parse_err)?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts
        .next()
        .ok_or_else(parse_err)?
        .parse()
        .map_err(|_| parse_err())?;
    let month: i64 = date_parts
        .next()
        .ok_or_else(parse_err)?
        .parse()
        .map_err(|_| parse_err())?;
    let day: i64 = date_parts
        .next()
        .ok_or_else(parse_err)?
        .parse()
        .map_err(|_| parse_err())?;
    let time = rest.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let mut time_parts = time.split(':');
    let hour: i64 = time_parts
        .next()
        .ok_or_else(parse_err)?
        .parse()
        .map_err(|_| parse_err())?;
    let minute: i64 = time_parts
        .next()
        .ok_or_else(parse_err)?
        .parse()
        .map_err(|_| parse_err())?;
    let sec_str = time_parts.next().ok_or_else(parse_err)?;
    let second: i64 = sec_str
        .split('.')
        .next()
        .unwrap_or(sec_str)
        .parse()
        .map_err(|_| parse_err())?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(parse_err());
    }
    // civil_from_days：days since 1970-01-01。
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Ok(days * 86_400 + hour * 3600 + minute * 60 + second)
}

/// URL 编码辅助：把含 `<>` / `::` 的 Move struct tag 等放进 query/path 前转义。
pub fn url_encode(raw: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        let safe = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if safe {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_loose_numbers() {
        assert_eq!(loose_u64(&json!(42)).unwrap(), 42);
        assert_eq!(loose_u64(&json!("42")).unwrap(), 42);
        assert_eq!(loose_u64(&json!("0x2a")).unwrap(), 42);
        assert_eq!(
            loose_u128(&json!("692825625168421088907802623")).unwrap(),
            692_825_625_168_421_088_907_802_623u128
        );
        assert!(loose_u64(&json!("nope")).is_err());
    }

    #[test]
    fn converts_micros() {
        assert_eq!(
            micros_to_seconds(&json!("1788009379932710")).unwrap(),
            1_788_009_379
        );
        assert_eq!(
            micros_to_seconds(&json!(1_788_009_379_000_000u64)).unwrap(),
            1_788_009_379
        );
    }

    #[test]
    fn parses_rfc3339() {
        assert_eq!(
            rfc3339_to_unix("2026-08-29T13:19:32.051Z").unwrap(),
            1_788_009_572
        );
        assert_eq!(rfc3339_to_unix("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            rfc3339_to_unix("2024-02-29T23:59:59.999Z").unwrap(),
            1_709_251_199
        );
        assert!(rfc3339_to_unix("not-a-time").is_err());
    }

    #[test]
    fn encodes_move_struct_tag() {
        assert_eq!(
            url_encode("0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"),
            "0x1%3A%3Acoin%3A%3ACoinStore%3C0x1%3A%3Aaptos_coin%3A%3AAptosCoin%3E"
        );
    }
}
