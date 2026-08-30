//! 统一响应信封：三种接入形态（CLI / HTTP / MCP）返回完全一致的结构。
//!
//! 设计意图：CLI 文本输出、HTTP 响应体、MCP 工具返回值共用同一个 [`Envelope`]，
//! 调用方只写一份解析逻辑。数据具体类型由泛型参数 `T` 在编译期单态化展开，
//! 没有 `Box<dyn ...>`（trait object）那种运行期虚表开销。

use serde::{Deserialize, Serialize};
// `Value` 是「任意 JSON 值」的树，用来承载结构不固定的数据。
use serde_json::Value;

// `crate::{..}` 表示从本 crate 的根模块（即 lib.rs）引入类型。
use crate::{ErrorCode, SdkError};

/// 失败时的错误体。
///
/// 字段与 [`SdkError`] 一一对应，区别在于 `code` 是枚举 [`ErrorCode`]，
/// 序列化后是 `"NOT_FOUND"` 这类稳定字符串，调用方可直接 switch，不必匹配中文文案。
///
/// 语法说明：这里派生了 `Clone` 但**没有** `Copy`——`String` 的数据在堆上，
/// 无法按位复制，只能显式 `clone()`。这是 `Copy` 与 `Clone` 的分界线。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    /// 跨链统一的错误分类，序列化为 `SCREAMING_SNAKE_CASE`。
    pub code: ErrorCode,
    /// 面向人类的描述；程序化判断请一律看 `code`。
    pub message: String,
    /// 是否值得重试。只有网络 / 节点类瞬态故障为 `true`。
    pub retryable: bool,
}

/// 为 [`SdkError`] 实现 `From` trait，让它能一步转成 [`ErrorBody`]。
///
/// 语法说明：`impl From<A> for B` 之后，标准库会自动补上反向的 `Into<B> for A`，
/// 于是需要 `ErrorBody` 的地方都能写 `err.into()`，或被 `?` 自动转型。
impl From<SdkError> for ErrorBody {
    // trait 方法签名必须与 trait 定义完全一致；`Self` 即 `ErrorBody`。
    fn from(err: SdkError) -> Self {
        // `err` 是按值传入的，所以三个字段可以直接**移动**出来，之后 `err` 不可再用。
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
///
/// 语法说明：`Envelope<T>` 的 `<T>` 是**泛型参数**，编译器为每种实际用到的 `T`
/// 各生成一份机器码（单态化），运行期无额外开销，代价是编译产物略大。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// 冗余一个布尔位，是为了让调用方不必先判断 `error` 键是否存在就能分流。
    pub ok: bool,
    /// 链短名；无法识别时为 `"unknown"`。
    ///
    /// 用 `String` 而非 [`crate::ChainKind`]：信封是**跨层**结构，
    /// 遇到未知链或门面层尚未注册的链时，仍要能把错误包回去交给调用方，
    /// 此时用枚举就表达不了了。
    pub chain: String,
    /// 网络名。与 `chain` 同理保持为字符串，避免解析失败时无法构造信封。
    pub network: String,
    /// 本次调用耗时（毫秒），便于调用方做超时与性能统计。
    pub took_ms: u64,
    /// `skip_serializing_if` 让值为 `None` 时**整个键都不出现**在 JSON 里，
    /// 而不是输出 `"data": null`。于是成功响应里根本没有 `error` 键，
    /// 调用方可以用「键是否存在」分流。引号里是函数路径，serde 会调用
    /// `Option::is_none(&字段)` 决定是否跳过；它只影响序列化，
    /// 反序列化时键缺失依然还原成 `None`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// 失败时的错误体。与 `data` 互斥：成功响应里该键根本不存在，
    /// 因此判断失败的正确写法是 `if let Some(e) = env.error`，而不是 `if !env.ok`
    /// 后再去 `unwrap()`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

/// 带约束的 impl 块：只有 `T` 可序列化时，下面这些方法才存在。
///
/// 语法说明：`impl<T: Serialize>` 等价于 `impl<T> ... where T: Serialize`。
/// 好处是对不满足约束的 `T`，方法直接「不存在」，而不是在调用时才报深层错误。
impl<T: Serialize> Envelope<T> {
    /// 构造成功信封。
    ///
    /// 语法说明：`impl Into<String>` 是泛型参数 + trait 约束，调用方可传 `&str`、
    /// `String`、`Cow<str>` 等任意能转成 `String` 的类型；写死 `String` 会让调用方
    /// 多一次 `.to_string()` 分配，写死 `&str` 又接不住 `String`。
    pub fn ok(chain: impl Into<String>, network: impl Into<String>, took_ms: u64, data: T) -> Self {
        Self {
            ok: true,
            // `.into()` 的目标类型由字段类型反推，无需 turbofish。
            chain: chain.into(),
            network: network.into(),
            // 字段名与变量名同名时的简写，等价于 `took_ms: took_ms`。
            took_ms,
            // 字段是 `Option<T>` 而参数是 `T`，故用 `Some(..)` 装箱。
            data: Some(data),
            error: None,
        }
    }

    /// 构造失败信封。`err` 按值接收：一个错误不该被复用两次。
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
            // 靠上面实现的 `From<SdkError> for ErrorBody` 完成转换。
            error: Some(err.into()),
        }
    }

    /// 序列化为 [`Value`]，便于调用方转发前再加工。
    ///
    /// 返回 `Result` 而非直接 `unwrap()`：序列化失败是否致命应由调用方决定。
    /// `&self` 是不可变借用，方法结束后 `self` 仍可用（对比 `&mut self` 与 `self`）。
    pub fn to_value(&self) -> Result<Value, serde_json::Error> {
        // 最后一个表达式不带分号 = 返回值。
        serde_json::to_value(self)
    }

    /// 序列化为紧凑 JSON 字符串。
    ///
    /// 设计取舍：信封是给外部看的最终产物，**不能因序列化失败就 panic**，
    /// 否则连「出错了」都传达不出去，因此失败时退化为手工拼的最小错误 JSON。
    pub fn to_json(&self) -> String {
        // `unwrap_or_else(闭包)` 惰性求值：只有失败时才调用，且能拿到错误信息 `e`。
        serde_json::to_string(self).unwrap_or_else(|e| {
            // `{e}` 是内联捕获，自动取用同名变量；`\"` 转义引号，`{{`/`}}` 转义大括号。
            // 这里宁可硬编码也不再调用序列化器——它刚失败过，同路径很可能再失败。
            format!("{{\"ok\":false,\"error\":{{\"code\":\"INTERNAL\",\"message\":\"序列化失败: {e}\",\"retryable\":false}}}}")
        })
    }

    /// 序列化为带缩进的 JSON，供 CLI 打印给人看。
    pub fn to_json_pretty(&self) -> String {
        // 二级降级：漂亮输出失败再退回紧凑输出。`|_|` 表示用不上错误信息。
        serde_json::to_string_pretty(self).unwrap_or_else(|_| self.to_json())
    }
}

/// 单元测试：`#[cfg(test)]` 保证只在 `cargo test` 时编译；`use super::*` 导入外层条目。
#[cfg(test)]
mod tests {
    use super::*;

    /// 成功响应必须省略 `error` 键——`skip_serializing_if` 的验收点。
    #[test]
    fn ok_envelope_omits_error_key() {
        // 类型推断：由 `data` 实参推得 `T = Value`。
        let env = Envelope::ok("eth", "sepolia", 12, serde_json::json!({"a": 1}));
        let v = env.to_value().unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["chain"], "eth");
        // `Value` 的下标访问很宽容：键不存在会返回 `Null` 而非 panic，
        // 所以必须用 `get(..).is_none()` 才能真正验证「键不存在」。
        assert!(v.get("error").is_none(), "成功响应不应包含 error 键");
        assert_eq!(v["data"]["a"], 1);
    }

    /// 失败响应的对称验收：省略 `data` 键。
    #[test]
    fn err_envelope_omits_data_key() {
        // `err` 的 `data` 恒为 `None`，编译器无从推断 `T`，必须显式标注类型。
        let env: Envelope<Value> =
            Envelope::err("near", "testnet", 3, SdkError::not_found("账户不存在"));
        let v = env.to_value().unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "NOT_FOUND");
        assert_eq!(v["error"]["retryable"], false);
        assert!(v.get("data").is_none(), "失败响应不应包含 data 键");
    }
}
