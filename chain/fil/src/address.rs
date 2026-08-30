//! Filecoin 地址编解码（仅实现协议 1：secp256k1 的 f1/t1 地址），纯本地实现。
//!
//! 流程（Filecoin Address Protocol）：
//! 1. payload = blake2b-256(65 字节未压缩 secp256k1 公钥) 的前 20 字节；
//! 2. checksum = blake2b-256(protocol_byte || payload) 的前 4 字节；
//! 3. 小写无填充 RFC4648 base32 编码 `protocol_byte || payload || checksum`；
//! 4. 拼上网络前缀（主网 f / 测试网 t）与协议号 1。
//!
//! **实现校正（读代码时请以代码为准）**：上面第 1、2 步描述的是「先算 blake2b-256
//! 再截断」，而本文件的实际实现是直接用**可变长度输出**的 blake2b
//! （`Blake2bVar::new(20)` / `Blake2bVar::new(4)`）。这两者**不等价**：
//! BLAKE2b 的参数块里编码了输出长度，所以 blake2b-160(x) ≠ blake2b-256(x)[..20]。
//! Filecoin 规范用的正是可变长度版本，因此本实现与官方一致，
//! 上面那份描述只是措辞不够精确。
//!
//! 另外注意第 3、4 步的实际顺序：协议号 `1` 是以 **ASCII 字符**直接拼在
//! 网络前缀后面的，`base32` 编码的**只有** `payload(20) + checksum(4)` 共 24 字节。
//! 也就是说协议号**不在** base32 的编码范围里，这是最容易理解错的一点。
//!
//! 只实现协议 1 的原因：f1（secp256k1）是绝大多数钱包与交易所使用的类型，
//! 也是唯一能由「公钥」纯本地推导的类型。f3（BLS）需要 BLS 公钥与曲线运算，
//! f0/f2/f4 根本不是公钥哈希，无从派生。

// `Blake2bVar` 是**可变输出长度**的 BLAKE2b（区别于固定长度的 `Blake2b<U32>`）。
// 本 crate 用的是 blake2 crate 的 `variable` 风格 API，输出长度在**运行期**给定。
use blake2::Blake2bVar;
// `Update` 提供 `.update(data)` 喂数据，`VariableOutput` 提供 `.finalize_variable(..)`
// 收尾。Rust 的 digest 生态把「输入」与「输出」拆成两个 trait，
// 必须两个都引入才能完整使用——少引入一个会报「方法不存在」。
use blake2::digest::{Update, VariableOutput};

// `hexutil` 提供宽松的十六进制解码（允许 0x 前缀、大小写不敏感）。
use allchain_core::{ErrorCode, SdkError, hexutil};

/// RFC4648 base32 字母表（小写，`a-z` + `2-7`）。
///
/// Filecoin 用的是这套标准字母表（与 BTC 的 bech32 自创字母表不同），
/// 且**不用填充符** `=`。
///
/// 语法说明：`b"..."` 是**字节串字面量**，类型是 `&[u8; 32]`。
/// 用字节而非 `&str` 是因为下面要遍历比较 `u8`，省掉一次 `as u8` 转换。
const B32_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

/// 计算指定输出长度的 blake2b（Filecoin 直接用可变长度输出，**不是** 256 位截断）。
///
/// `out_len` 的合法范围是 1..=64 字节（BLAKE2b 的规范上限）。
/// 本文件只用两个长度：20（payload）与 4（checksum）。
fn blake2b_var(data: &[u8], out_len: usize) -> Vec<u8> {
    // `Blake2bVar::new(out_len)` 返回 `Result`：长度越界会失败。
    // 这里两个调用点传的都是编译期常量，不可能越界，所以用 `expect` 直接 panic
    // ——在这类「程序员错误」上 panic 是 Rust 的惯例，比返回错误更诚实。
    let mut hasher = Blake2bVar::new(out_len).expect("输出长度 1..=64 合法");
    // `Update::update` 可多次调用（流式输入）；这里只喂一次。
    hasher.update(data);
    // `vec![0u8; out_len]` 造一个填满 0 的缓冲区。`vec!` 宏的这个重载是
    // 「元素值; 长度」，注意与 `vec![a, b, c]`（列举元素）区分。
    let mut out = vec![0u8; out_len];
    // `finalize_variable(&mut out)` 把摘要写进**调用方提供的**缓冲区，
    // 而不是返回一个新 `Vec`——这样零额外分配，是 digest 生态的常见设计。
    hasher
        .finalize_variable(&mut out)
        .expect("输出缓冲长度匹配");
    out
}

/// f1 地址 payload：blake2b-160（20 字节）。
///
/// 输入是**完整原始字节**（本 crate 要求 65 字节未压缩公钥），
/// 不含任何前缀或长度标记。
fn f1_payload(pubkey: &[u8]) -> Vec<u8> {
    blake2b_var(pubkey, 20)
}

/// checksum：blake2b-32（4 字节），输入为 protocol_byte || payload。
///
/// 注意 protocol_byte 是**数值** `0x01`（一个字节），不是 ASCII 字符 `'1'`。
/// 它参与哈希但不参与 base32 编码，这两个 `1` 完全是两回事，
/// 是手写 Filecoin 地址时最常搞混的地方。
fn f1_checksum(payload: &[u8]) -> Vec<u8> {
    // 预分配 1 + payload.len() 字节，避免 push 过程中扩容。
    let mut input = Vec::with_capacity(1 + payload.len());
    input.push(0x01);
    // `extend_from_slice` 把另一段切片的内容**拷贝**进来。
    // 与 `extend(iter)` 的区别：这个版本按 `Copy` 语义批量 memcpy，更快。
    input.extend_from_slice(payload);
    blake2b_var(&input, 4)
}

/// 标准 RFC4648 base32 编码（小写、无填充，MSB 优先）。
///
/// 算法：维护一个位缓冲区 `acc`，每喂进一个字节就凑够 5 位吐出一个字符。
/// 5 与 8 的最小公倍数是 40，所以每 5 字节恰好产出 8 个字符。
///
/// 语法说明里的两个细节：
/// - `acc` 用 `u32` 而不是 `u8`：最多需要在里面暂存 4 + 8 = 12 位，u8 装不下；
/// - 末尾不足 5 位时**左移补齐**（`(acc << (5 - bits)) & 31`），
///   这是 base32 与 base64 的共同约定，右侧补的是 0。
fn base32_encode(data: &[u8]) -> String {
    // 每 5 字节 → 8 字符，故容量按 `len * 8 / 5` 向上取整估。
    // `saturating_mul` 是**饱和**乘法：溢出时停在 `usize::MAX` 而非 panic 或回绕。
    // `div_ceil` 是向上取整除法（Rust 1.73 起稳定）。
    let mut out = String::with_capacity(data.len().saturating_mul(8).div_ceil(5));
    let mut acc = 0u32; // 位缓冲区（未输出的高位）
    let mut bits = 0u32; // 缓冲区里当前攒了多少位
    // `for &byte in data`：对 `&[u8]` 迭代得到 `&u8`，用 `&byte` 模式**解构**出 `u8` 副本
    // （u8 是 `Copy`，所以这里只是复制，不涉及所有权转移）。
    for &byte in data {
        // 把新字节接到低位：`u32::from(byte)` 把 u8 无符号扩展成 u32（不会符号扩展）。
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        // 只要攒够 5 位就吐字符，可能一次吐多个（8 位进来时吐 1 个，余 3 位）。
        while bits >= 5 {
            bits -= 5;
            // `acc >> bits` 把要取的那 5 位移到最低位，`& 31`（即 `0b11111`）截出来。
            // `as usize` 是因为下标必须是 usize；`as char` 是因为字母表元素是 ASCII。
            out.push(B32_ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    // 处理残余位：24 字节 = 192 位，192 % 5 = 2，所以 f1 地址**总是**走到这个分支，
    // 补 3 个 0 位后多产出 1 个字符（这也是 f1 地址长度固定 41 字符的原因）。
    if bits > 0 {
        out.push(B32_ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// 标准 RFC4648 base32 解码（大小写不敏感、允许无填充）。
///
/// 与编码严格互逆，但不做「残余位必须为 0」的校验（宽松策略）：
/// 多出来的那 3 个填充位直接丢弃。这样既能解标准编码，也不会误拒某些实现。
fn base32_decode(raw: &str) -> Result<Vec<u8>, SdkError> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    // 容量按「每 8 字符 → 5 字节」估算，`* 5 / 8` 是向下取整。
    let mut out = Vec::with_capacity(raw.len() * 5 / 8);
    // 按 `char` 迭代而非 `bytes`：base32 字母表都是 ASCII，两者等价，
    // 但用 char 才能拿到字符本身用于报错回显。
    for c in raw.chars() {
        // 查字母表找下标。
        // `.iter()` 产生 `&u8`；闭包参数写 `|&a|` 是**解构模式**，
        // 把 `&u8` 直接解成 `u8`，于是比较时不用再写 `*a == ...`。
        // `c.to_ascii_lowercase() as u8`：先转小写（实现大小写不敏感），再转 u8。
        let value = B32_ALPHABET
            .iter()
            // `position` 返回第一个满足条件的**下标**，找不到则是 `None`。
            .position(|&a| a == c.to_ascii_lowercase() as u8)
            // `ok_or_else(闭包)`：`None` → `Err(闭包())`。惰性求值，
            // 成功路径上不会执行 `format!`。
            .ok_or_else(|| SdkError::invalid_argument(format!("非法 base32 字符: {c}")))?;
        acc = (acc << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            // 与编码对称：右移取高 8 位；`as u8` 直接截断低位以外的部分。
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

/// 由 65 字节未压缩 secp256k1 公钥派生 f1/t1 地址。
///
/// **只接受未压缩公钥**（65 字节，以 `0x04` 开头）。这一点与某些文档里
/// 「压缩或非压缩均可」的说法不同：本实现强制 65 字节，是因为
/// Filecoin / Lotus 的官方实现固定对未压缩形式取哈希，
/// 若允许 33 字节压缩公钥，会派生出一个**完全不同且不被链承认**的地址。
/// 宁可报错也不静默产出错误地址，这是这里刻意的选择。
pub fn f1_from_pubkey(pubkey_hex: &str, is_mainnet: bool) -> Result<String, SdkError> {
    // `hexutil::decode_hex` 允许 `0x` 前缀、大小写不敏感，返回 `Vec<u8>`。
    // `?` 把 `INVALID_ARGUMENT` 直接向上传播。
    let bytes = hexutil::decode_hex(pubkey_hex)?;
    if bytes.len() != 65 {
        return Err(SdkError::invalid_argument(format!(
            "FIL f1 地址需要 65 字节未压缩 secp256k1 公钥，实际 {} 字节",
            bytes.len()
        )));
    }
    // 注意：**不校验**首字节是否为 `0x04`（未压缩标志）。
    // 长度已经是 65，若首字节不对，产出的地址在链上根本不存在，
    // 属于调用方传错数据的范畴，这里不做过度防御。
    let payload = f1_payload(&bytes);
    encode_f1(&payload, is_mainnet)
}

/// 由 20 字节 payload 组装 f1/t1 地址。
///
/// 注意：协议号以 ASCII 数字 `1` 直接拼接，**不参与** base32 编码；
/// base32 只承载 `payload(20) + checksum(4)`。
fn encode_f1(payload: &[u8], is_mainnet: bool) -> Result<String, SdkError> {
    if payload.len() != 20 {
        return Err(SdkError::invalid_argument("f1 payload 必须为 20 字节"));
    }
    let checksum = f1_checksum(payload);

    // 20 + 4 = 24 字节 → base32 后固定 39 字符，
    // 加上前缀与协议号共 41 字符，这就是 f1 地址的长度恒为 41 的原因。
    let mut raw = Vec::with_capacity(24);
    raw.extend_from_slice(payload);
    raw.extend_from_slice(&checksum);
    let prefix = if is_mainnet { "f" } else { "t" };
    // `format!("{prefix}1{}", ..)` 里的 `1` 是字面量 ASCII 字符，不是 protocol_byte 0x01。
    Ok(format!("{prefix}1{}", base32_encode(&raw)))
}

/// 解析并校验任意 Filecoin 地址，返回（协议号, payload, 是否主网）。
///
/// - f0/t0 为 ID 地址，payload 以十进制字符串原样返回；
/// - f1/t1 校验 blake2b checksum；
/// - f2/t2（Actor）、f3/t3（BLS）、f4/t4（委托）只做格式校验不做深度解析。
///
/// 返回值里 payload 的语义**随协议号而变**，调用方务必注意：
/// - 协议 0：payload 是十进制数字字符串的 **ASCII 字节**（如 `t01` → `[0x31]`），
///   不是整数的二进制编码。想拿数字就 `String::from_utf8` 后再 `parse`；
/// - 协议 1：payload 是 20 字节公钥哈希；
/// - 协议 2..=4：payload 是地址体的原始 ASCII 字节，未做任何解码。
///
/// 语法说明：返回 `Result<(u8, Vec<u8>, bool), SdkError>`，
/// 其中 `( .. )` 是**元组**（tuple）：长度固定、元素类型可以各不相同。
/// 这是 Rust 里返回「多个值」最轻量的方式。
pub fn inspect(raw: &str) -> Result<(u8, Vec<u8>, bool), SdkError> {
    let t = raw.trim();
    // `chars()` 返回惰性迭代器；`mut` 是因为要连续 `next()` 取出前两个字符。
    let mut chars = t.chars();
    let network_ch = chars
        .next()
        // 空字符串时 `next()` 返回 `None`，这里转成明确错误，避免 panic。
        .ok_or_else(|| SdkError::invalid_argument("空地址"))?;
    // 语法说明：`match` 的分支必须是**表达式**。这里第三个分支要在返回前做点别的，
    // 就用 `{ return Err(..); }` 块——块的最后一个表达式是 `()`（因为 `return` 的类型是
    // 「永不返回」的 `!`），编译器知道这条分支不会产出值，因此合法。
    let is_mainnet = match network_ch {
        'f' => true,
        't' => false,
        _ => {
            return Err(SdkError::invalid_argument(format!(
                "FIL 地址必须以 f/t 开头: {t}"
            )));
        }
    };
    let protocol_ch = chars
        .next()
        .ok_or_else(|| SdkError::invalid_argument("地址缺少协议号"))?;
    // `to_digit(10)` 返回 `Option<u32>`：非 ASCII 数字字符（含全角数字）一律 `None`。
    let protocol = protocol_ch
        .to_digit(10)
        .ok_or_else(|| SdkError::invalid_argument(format!("非法协议号: {protocol_ch}")))?
        // `as u8` 是**截断转换**：值来自 `to_digit(10)`，范围只有 0..=9，不会丢信息。
        as u8;
    // 语法说明：`&t[2..]` 按**字节**切片，且必须落在 UTF-8 字符边界上，
    // 否则直接 panic。这里安全的前提是：第 0 个字符是 `f`/`t`（1 字节），
    // 第 1 个字符刚被 `to_digit(10)` 确认是 ASCII 数字（也是 1 字节），
    // 所以字节下标 2 必然是合法边界。若哪天改成允许非 ASCII 前缀，这里就会炸。
    let body = &t[2..];
    if body.is_empty() {
        return Err(SdkError::invalid_argument("地址体为空"));
    }
    match protocol {
        0 => {
            // ID 地址：协议号后面就是账户的十进制序号（如 `f02345` 的 `2345`）。
            // `body.bytes().all(闭包)`：所有字节都满足条件才为真。
            // `.bytes()` 而非 `.chars()` 是因为只可能是 ASCII 数字。
            if !body.bytes().all(|b| b.is_ascii_digit()) {
                return Err(SdkError::invalid_argument("f0 ID 地址必须为纯数字"));
            }
            // 原样保留**字符串字节**，不做整数转换——ID 可能大到超过 u64。
            Ok((0, body.as_bytes().to_vec(), is_mainnet))
        }
        1 => {
            let decoded = base32_decode(body)?;
            if decoded.len() != 24 {
                return Err(SdkError::invalid_argument(format!(
                    "f1 地址解码后应为 24 字节（payload20+checksum4），实际 {} 字节",
                    decoded.len()
                )));
            }
            // `decoded[0..20]` 是切片；`.to_vec()` 拷贝一份成为自有 `Vec<u8>`
            // ——必须拷贝，否则借用的是 `decoded` 的局部内存。
            let payload = decoded[0..20].to_vec();
            // 这里借用 `decoded` 的尾部区间，与上面的 payload 不冲突
            // （一个已拷贝走，一个只读借用）。
            let checksum = &decoded[20..24];
            // `.as_slice()` 把 `Vec<u8>` 借用成 `&[u8]`，才能与 `&[u8]` 用 `!=` 比较。
            // 直接写 `f1_checksum(&payload) != checksum` 会因为 `Vec<u8>` vs `&[u8]`
            // 类型不匹配而编译失败——这是初学 Rust 极常见的报错。
            if f1_checksum(&payload).as_slice() != checksum {
                return Err(SdkError::new(
                    ErrorCode::InvalidArgument,
                    "f1 地址校验和错误",
                ));
            }
            Ok((1, payload, is_mainnet))
        }
        // 语法说明：`2..=4` 是**范围模式**（range pattern），一次匹配多个值。
        // 这是 `2 | 3 | 4` 的简写，同样要求编译器能验证穷尽性。
        2..=4 => {
            // 仅做字符集粗校验，保证不会把明显垃圾发给节点。
            //
            // 为什么不做深度解析：f2（Actor）与 f3（BLS）的 payload 是原始字节的
            // base32 编码，f4（委托）则是一套可变长度的 sub-address 规范，
            // 校验规则各不相同且与本项目能力无关。这里只挡住
            // 「含空格、标点等非 base32 字符」这类明显输入错误，
            // 真正的有效性交给节点判断（节点会返回明确的 not found）。
            if body.bytes().any(|b| !b.is_ascii_alphanumeric()) {
                return Err(SdkError::invalid_argument(format!(
                    "f{protocol} 地址含非法字符"
                )));
            }
            Ok((protocol, body.as_bytes().to_vec(), is_mainnet))
        }
        // `other` 兜底：Filecoin 目前只定义到协议 4。
        other => Err(SdkError::invalid_argument(format!(
            "未知地址协议号: {other}"
        ))),
    }
}

/// 单元测试模块：`#[cfg(test)]` 保证它只在 `cargo test` 时编译。
#[cfg(test)]
mod tests {
    use super::*;

    /// 用一个主网**真实地址**做往返验证，是这份手写实现最重要的保障：
    /// 纯单元测试（自己编自己解）无法发现「算法整体理解错了」的问题，
    /// 只有对拍公认正确的第三方地址才行。
    #[test]
    fn decodes_real_f1_address() {
        // 主网真实 f1 地址，验证 base32 + checksum 实现。
        let addr = "f12xpw7zzjiltyzyjzeolqe535ahpbaiivheh3lpq";
        let (protocol, payload, mainnet) = inspect(addr).unwrap();
        assert_eq!(protocol, 1);
        assert!(mainnet);
        assert_eq!(payload.len(), 20);
        // 重新编码应得到同一地址。
        assert_eq!(encode_f1(&payload, true).unwrap(), addr);
    }

    /// 篡改任意一个字符都应被 checksum 挡住。
    #[test]
    fn rejects_bad_f1_checksum() {
        // `String::from` 造一份可变的副本。
        let mut s = String::from("f12xpw7zzjiltyzyjzeolqe535ahpbaiivheh3lpq");
        // `replace_range(范围, 替换串)`：按**字节**下标替换。
        // 这里替换的是地址体第 3 个字符（下标 4 起始，单字节 ASCII）。
        s.replace_range(4..5, "a");
        assert!(inspect(&s).is_err());
    }

    /// ID 地址的 payload 保留为十进制字符串字节，且零填充合法（`t01`）。
    #[test]
    fn accepts_id_address() {
        let (protocol, id, mainnet) = inspect("f02345").unwrap();
        assert_eq!(protocol, 0);
        assert!(mainnet);
        // 注意断言方式：payload 是 ASCII 字节，需先 `from_utf8` 再比字符串。
        assert_eq!(String::from_utf8(id).unwrap(), "2345");
        assert!(inspect("t01").is_ok());
    }

    /// 非 65 字节公钥必须被拒绝（33 字节压缩公钥也在拒绝之列）。
    #[test]
    fn rejects_wrong_pubkey_length() {
        // `"ab".repeat(33)` = 66 个十六进制字符 = 33 字节，即压缩公钥长度。
        assert!(f1_from_pubkey(&"ab".repeat(33), true).is_err());
    }
}
