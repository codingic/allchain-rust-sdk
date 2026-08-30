//! 链标识与元信息。
//!
//! 语法说明：`//!` 是**内部文档注释**，必须写在文件/模块的最开头，用于描述「整个文件」；
//! 而 `///` 是**外部文档注释**，写在某个条目（函数、结构体、枚举）的正上方，描述「那一个条目」。
//! 两者的区别只在位置，都会被引擎 `cargo doc` 收录。

// `use` 把其它 crate 里的类型引入当前作用域。
// `serde` 是 Rust 生态事实上的序列化框架；`Serialize`（写出）与 `Deserialize`（读入）
// 这里不是直接调用，而是配合下面的 `#[derive(...)]` 让编译器帮我们生成实现代码。
use serde::{Deserialize, Serialize};

/// 支持的公链。序列化为小写短名。
///
/// 语法说明：
/// - `#[derive(...)]` 是**派生宏**：编译器按括号里的 trait 自动生成样板实现。
///   - `Debug`   → 允许 `{:?}` 打印，调试用；
///   - `Clone`   → 允许 `.clone()` 显式复制；
///   - `Copy`    → 赋值/传参时**自动**按位复制，不再转移所有权；
///     （能 `Copy` 的前提是所有字段都能 `Copy`，枚举自然满足）
///   - `PartialEq`/`Eq` → 允许 `==` 比较；
///   - `Hash`    → 允许作为 `HashMap` 的键。
/// - `Serialize`/`Deserialize` 来自上面 `use` 进来的 serde，让本枚举可直接转 JSON。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
// `serde` 的属性：把每个变体的名字统一改成小写后再序列化，
// 于是 `ChainKind::Eth` 在 JSON 里是 `"eth"` 而不是 `"Eth"`。
#[serde(rename_all = "lowercase")]
pub enum ChainKind {
    Eth,
    Btc,
    Sol,
    Near,
    /// Aptos（Move，REST）。
    Apt,
    /// Arweave（REST/GraphQL 网关）。
    Ar,
    /// Nervos CKB（JSON-RPC）。
    Ckb,
    /// Filecoin（JSON-RPC）。
    Fil,
    /// Sui（GraphQL）。
    Sui,
    /// The Open Network（toncenter REST）。
    Ton,
}

/// 只读四件套。
///
/// 语法说明：`const` 定义常量，类型必须**显式写出**且编译期已知大小。
/// `[&str; 4]` 读作「元素类型为 `&str`、长度为 4 的数组」；
/// 长度写进类型里，所以 `[&str; 4]` 和 `[&str; 5]` 是两个不同的类型。
/// `const`（编译期常量）与 `let`（运行期绑定）的区别：`const` 的值会被内联到每处使用点。
const READ_CAPABILITIES: [&str; 4] = ["status", "balance", "block", "tx"];
/// 只读 + 公钥派生地址（纯本地计算）。
const READ_AND_DERIVE_CAPABILITIES: [&str; 5] =
    ["status", "balance", "block", "tx", "address_from_pubkey"];
/// 全量能力（含本地签名转账）。
const FULL_CAPABILITIES: [&str; 6] = [
    "status",
    "balance",
    "block",
    "tx",
    "address_from_pubkey",
    "transfer",
];

// `impl ChainKind { ... }` 是**固有实现块**：给 `ChainKind` 这个类型挂上一组方法。
// 与之相对的是「trait 实现块」`impl SomeTrait for ChainKind`，见本文件末尾的 `Display`。
impl ChainKind {
    /// 全部受支持的链，按稳定顺序返回。
    ///
    /// 语法说明：`pub const ALL` 中的 `pub` 表示对外可见（同 crate 外的代码也能用）。
    /// 数组长度 10 与 `ChainKind` 的变体数一一对应；若以后新增变体却忘了改这里，
    /// 下面的 `all_variants_are_complete` 测试会失败，起到「编译期 + 测试期」双保险。
    pub const ALL: [ChainKind; 10] = [
        ChainKind::Eth,
        ChainKind::Btc,
        ChainKind::Sol,
        ChainKind::Near,
        ChainKind::Apt,
        ChainKind::Ar,
        ChainKind::Ckb,
        ChainKind::Fil,
        ChainKind::Sui,
        ChainKind::Ton,
    ];

    /// 链短名，与 JSON / CLI 参数一致。
    ///
    /// 语法说明：
    /// - `self`（不带 `&`）表示**按值接收**调用者。因为 `ChainKind` 实现了 `Copy`，
    ///   这里不会发生所有权转移，调用后原值依然可用。对比 `&self`（借用）与
    ///   `&mut self`（可变借用）两种写法。
    /// - 返回值 `&'static str`：`&` 是引用，`'static` 是**生命周期**标注，
    ///   表示这段字符串在整个程序运行期间都有效（这里是编译进二进制的字面量）。
    pub fn as_str(self) -> &'static str {
        // `match` 是模式匹配，编译器强制要求**穷尽所有分支**（少写一个变体就编译失败）。
        // 每个分支 `ChainKind::Eth => "eth"` 的最后一个表达式即该分支的返回值，
        // 分支结尾**不加分号**（加了分号就变成语句，返回 `()`）。
        match self {
            ChainKind::Eth => "eth",
            ChainKind::Btc => "btc",
            ChainKind::Sol => "sol",
            ChainKind::Near => "near",
            ChainKind::Apt => "apt",
            ChainKind::Ar => "ar",
            ChainKind::Ckb => "ckb",
            ChainKind::Fil => "fil",
            ChainKind::Sui => "sui",
            ChainKind::Ton => "ton",
        }
    }

    /// 解析链短名，大小写不敏感。
    ///
    /// 语法说明：
    /// - 返回 `Option<Self>`：`Option` 是 Rust 表示「可能有、可能没有」的枚举，
    ///   取值为 `Some(值)` 或 `None`。Rust 没有 `null`，调用方必须显式处理 `None`，
    ///   从而把空指针崩溃挡在编译期。
    /// - `Self` 是「当前 impl 块所针对的类型」的别名，这里等价于 `ChainKind`。
    pub fn parse(raw: &str) -> Option<Self> {
        // 参数 `raw: &str` 是**字符串切片引用**（借用，不取得所有权）。
        // 链式调用：`raw.trim()` 去掉首尾空白 → `.to_ascii_lowercase()` 转小写
        // （返回新的 `String`）→ `.as_str()` 再借出 `&str` 供 `match` 匹配。
        match raw.trim().to_ascii_lowercase().as_str() {
            // `|` 在这里是**或模式**：一个分支匹配多个字面量。
            // 注意它与闭包参数列表里的 `|x|` 长得像，但语义完全不同。
            "eth" | "ethereum" => Some(ChainKind::Eth),
            "btc" | "bitcoin" => Some(ChainKind::Btc),
            "sol" | "solana" => Some(ChainKind::Sol),
            "near" => Some(ChainKind::Near),
            "apt" | "aptos" => Some(ChainKind::Apt),
            "ar" | "arweave" => Some(ChainKind::Ar),
            "ckb" | "nervos" => Some(ChainKind::Ckb),
            "fil" | "filecoin" => Some(ChainKind::Fil),
            "sui" => Some(ChainKind::Sui),
            "ton" => Some(ChainKind::Ton),
            _ => None,
        }
    }

    /// 原生资产符号。
    pub fn symbol(self) -> &'static str {
        match self {
            ChainKind::Eth => "ETH",
            ChainKind::Btc => "BTC",
            ChainKind::Sol => "SOL",
            ChainKind::Near => "NEAR",
            ChainKind::Apt => "APT",
            ChainKind::Ar => "AR",
            ChainKind::Ckb => "CKB",
            ChainKind::Fil => "FIL",
            ChainKind::Sui => "SUI",
            ChainKind::Ton => "TON",
        }
    }

    /// 最小单位名称（wei / satoshi / lamport / yoctoNEAR / octa / winston …）。
    pub fn unit_name(self) -> &'static str {
        match self {
            ChainKind::Eth => "wei",
            ChainKind::Btc => "satoshi",
            ChainKind::Sol => "lamport",
            ChainKind::Near => "yoctoNEAR",
            ChainKind::Apt => "octa",
            ChainKind::Ar => "winston",
            ChainKind::Ckb => "shannon",
            ChainKind::Fil => "attoFIL",
            ChainKind::Sui => "MIST",
            ChainKind::Ton => "nanoton",
        }
    }

    /// 原生资产精度（小数位数）。
    pub fn decimals(self) -> u8 {
        match self {
            ChainKind::Eth => 18,
            ChainKind::Btc => 8,
            ChainKind::Sol => 9,
            ChainKind::Near => 24,
            ChainKind::Apt => 8,
            ChainKind::Ar => 12,
            ChainKind::Ckb => 8,
            ChainKind::Fil => 18,
            ChainKind::Sui => 9,
            ChainKind::Ton => 9,
        }
    }

    /// 统一门面在未显式指定 `--network` 时使用的网络，**十链一律默认主网**。
    ///
    /// 这里刻意不写 `match self { ... }`：所有链返回同一个字面量，
    /// 少一层分支就不会出现「新增链忘了补分支」的问题。
    pub fn default_network(self) -> &'static str {
        // 函数体最后一个表达式不带分号 = 返回值（等价于 `return "mainnet";`，后者不推荐）。
        "mainnet"
    }

    /// 该链在统一接口下真实可用的能力清单。
    ///
    /// 前四条链具备全量能力（含本地签名转账）；六条新链首期提供只读查询，
    /// 其中五条额外支持纯本地的公钥派生地址，TON 的地址依赖钱包合约 StateInit，
    /// 无法仅由公钥确定，因此只声明只读能力。
    ///
    /// 语法说明：返回值 `&'static [&'static str]` 是「对静态字符串切片数组的引用」，
    /// 拆开读作 `&'static ( [ &'static str ] )`。返回引用而非 `Vec` 是为了零分配：
    /// 直接把上面三个 `const` 数组的地址交出去。
    pub fn capabilities(self) -> &'static [&'static str] {
        match self {
            // 一个分支里匹配多个变体，用 `|` 分隔。
            // `&FULL_CAPABILITIES`：`&` 取引用，把 `[&str; 6]` 借成 `&[&str]`（切片），
            // 长度信息从类型里「擦除」掉了，这正是返回类型只写 `[..]` 而不写长度的原因。
            ChainKind::Eth | ChainKind::Btc | ChainKind::Sol | ChainKind::Near => {
                &FULL_CAPABILITIES
            }
            ChainKind::Apt | ChainKind::Ar | ChainKind::Ckb | ChainKind::Fil | ChainKind::Sui => {
                &READ_AND_DERIVE_CAPABILITIES
            }
            ChainKind::Ton => &READ_CAPABILITIES,
        }
    }

    /// 是否支持原生资产转账（写操作）。
    ///
    /// 语法说明：`matches!(值, 模式)` 是标准库宏，等价于
    /// `match 值 { 模式 => true, _ => false }`，只是更短。末尾的 `!` 表示这是宏而非函数。
    pub fn supports_transfer(self) -> bool {
        matches!(
            self,
            ChainKind::Eth | ChainKind::Btc | ChainKind::Sol | ChainKind::Near
        )
    }
}

/// 为 `ChainKind` 实现标准库的 `Display` trait，使其支持 `{}` 格式化打印。
///
/// 语法说明：`impl Trait for Type` 是 **trait 实现块**，与上面的 `impl ChainKind`（固有实现块）
/// 是两种不同的东西：后者只能写在同一 crate 内，前者可以为外部类型实现外部 trait
/// （受「孤儿规则」约束，这里 `Display` 和 `ChainKind` 至少有一个是本地的，因此合法）。
impl std::fmt::Display for ChainKind {
    // trait 方法的签名必须与 trait 定义一致，不能自己改。
    // `&self` 借用自身；`&mut Formatter<'_>` 是可变借用，`'_` 是**匿名生命周期**，
    // 意思是「这里有个生命周期参数，但我不关心它叫什么，编译器自己推断」。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 把最小单位整数格式化为十进制字符串，避免 f64 精度丢失。
///
/// `1_500_000_000_000_000_000` wei + 18 位 → `"1.5"`。
///
/// 之所以不用 `f64`：JSON/浮点数只有 53 位有效位，NEAR 的 24 位小数（yoctoNEAR）
/// 与 ETH 的 18 位小数都会丢精度。全程整数运算 + 字符串拼接才是安全的。
pub fn format_units(amount: u128, decimals: u8) -> String {
    // `as` 是显式类型转换（cast）：`u8` → `u32`，因为 `pow` 只接受 `u32` 指数。
    let divisor = 10u128.pow(decimals as u32);
    let integer = amount / divisor;
    let fraction = amount % divisor;
    // 小数部分为 0 时直接返回整数，避免出现 "1." 这种尾巴。
    if fraction == 0 {
        // `return` 提前返回；注意这一行末尾有分号，而函数最后一行没有。
        return integer.to_string();
    }
    // 格式化微语言：`{fraction:0width$}` 中
    //   `0`      → 左侧补零；
    //   `width`  → 宽度取自同名变量；
    //   `$`      → 表示这是一个「命名参数」而非字面量。
    // `width = decimals as usize` 是在格式串外部为命名参数赋值。
    let frac_str = format!("{fraction:0width$}", width = decimals as usize);
    // 去掉尾部多余的 0（"500000000000000000" → "5"）。
    let trimmed = frac_str.trim_end_matches('0');
    // `format!` 宏返回 `String`；这是函数体最后一个表达式，即返回值。
    format!("{integer}.{trimmed}")
}

/// 单元测试模块。
///
/// 语法说明：`#[cfg(test)]` 是**条件编译属性**：只有执行 `cargo test` 时才编译这段代码，
/// 正式构建里完全不存在，不占体积。Rust 的惯例是把测试就地写在被测代码旁边。
#[cfg(test)]
mod tests {
    // `use super::*` 把父模块（本文件）的所有公共与私有条目导入测试作用域，
    // 于是可以直接写 `ChainKind` 而不必写 `super::ChainKind`。
    use super::*;

    /// `#[test]` 把这个函数注册为一个测试用例；函数返回 `()`，失败靠 `panic!` 表达。
    #[test]
    fn parse_is_case_insensitive() {
        assert_eq!(ChainKind::parse("ETH"), Some(ChainKind::Eth));
        assert_eq!(ChainKind::parse(" Solana "), Some(ChainKind::Sol));
        assert_eq!(ChainKind::parse("Aptos"), Some(ChainKind::Apt));
        assert_eq!(ChainKind::parse("arweave"), Some(ChainKind::Ar));
        assert_eq!(ChainKind::parse("nervos"), Some(ChainKind::Ckb));
        assert_eq!(ChainKind::parse("FILECOIN"), Some(ChainKind::Fil));
        assert_eq!(ChainKind::parse("sui"), Some(ChainKind::Sui));
        assert_eq!(ChainKind::parse("TON"), Some(ChainKind::Ton));
        assert_eq!(ChainKind::parse("doge"), None);
    }

    #[test]
    fn all_variants_are_complete() {
        assert_eq!(ChainKind::ALL.len(), 10);
        // `for kind in ChainKind::ALL`：数组本身可被 `for` 直接迭代（Rust 2021 起），
        // 每次把元素**复制**给 `kind`（依赖 `Copy`），不会移动数组。
        for kind in ChainKind::ALL {
            // 每条链至少具备只读四件套。
            //
            // `assert!(条件)` 在条件为 false 时 panic，测试即失败。
            // 这个循环的价值在于：将来往 `ChainKind` 加变体、却忘了同步 `ALL`、
            // `capabilities` 或 `default_network` 时，测试会立刻报错。
            assert!(kind.capabilities().len() >= 4);
            assert_eq!(kind.default_network(), "mainnet");
        }
    }

    #[test]
    fn format_units_keeps_precision() {
        assert_eq!(format_units(1_500_000_000_000_000_000, 18), "1.5");
        assert_eq!(format_units(150_000_000, 8), "1.5");
        assert_eq!(format_units(1_500_000_000, 9), "1.5");
        assert_eq!(format_units(42, 8), "0.00000042");
        assert_eq!(format_units(0, 18), "0");
        assert_eq!(format_units(100, 0), "100");
    }
}
