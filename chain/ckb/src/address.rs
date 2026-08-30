//! CKB 地址（RFC 0021）与 lock script 的编解码，纯本地实现，不依赖 ckb-sdk。
//!
//! 地址 payload 的**首字节是格式类型**，一共四种：
//!
//! | 首字节 | 名称            | payload 结构                            | bech32 变体 | 状态     |
//! |--------|-----------------|-----------------------------------------|-------------|----------|
//! | `0x00` | Full（ckb2021） | `code_hash(32) \| hash_type(1) \| args` | **bech32m** | 现行标准 |
//! | `0x01` | Short           | `code_hash_index(1) \| args`            | bech32      | 已废弃   |
//! | `0x02` | FullData        | `code_hash(32) \| args`                 | bech32      | 已废弃   |
//! | `0x04` | FullType        | `code_hash(32) \| args`                 | bech32      | 已废弃   |
//!
//! 为什么要自己写：官方 `ckb-sdk` 会拖入 ckb-types / molecule / secp256k1 整棵依赖树，
//! 而我们只需要「地址 ↔ lock script」这一件事。真正用到的零件只有 **bech32 / bech32m**
//! （把字节转成带校验和的可读字符串），不到 200 行，自己实现比引入依赖更划算。
//!
//! 三个极易踩的坑，代码里都已显式处理：
//! 1. **ckb2021 的 `0x00` 型必须用 bech32m**（常量 `0x2bc830a3`），另外三种用 bech32
//!    （常量 `1`）。危险之处在于二者**算法完全一致、只有常量不同**，所以编错时
//!    「自己编码、自己解码」永远通过，只有对方钱包会拒绝——必须有外部实现对拍才抓得到。
//! 2. **地址 payload 里没有 molecule**。molecule 只用于交易内部的 Script 序列化；
//!    地址是字段直接拼起来的**扁平结构**，没有长度前缀、也没有偏移量。
//! 3. `hash_type` 的取值是 **0/1/2/4**（data / type / data1 / data2），不是 0/1/2/3。
//!    这个跳号来自 CKB 协议的历史演进，照「连续枚举」写会错。

// 哈希一律走 **CKB 官方 crate `ckb-hash`**，而不是通用的 `blake2`。
// 这不是偷懒，而是踩过坑后的选择——详见 `Cargo.toml` 里的说明与下方 `ckb_blake160` 的注释。
// 简单说：`new_blake2b()` 一次性把「无密钥 + 32 字节输出 + personalization」三个约束固定住，
// 让「写错哈希」这件事在类型层面就不可能发生。
use ckb_hash::new_blake2b;

use allchain_core::{ErrorCode, SdkError, hexutil};

/// 系统锁 secp256k1_blake160_sighash_all 的 code_hash（主网/测试网相同）。
///
/// 领域说明：`code_hash` 是「锁定脚本的代码」的哈希，指向链上某个已部署的 cell。
/// 这个常量就是官方 secp256k1 单签锁脚本的 blake2b-256 摘要。
/// 主网与测试网**共用**同一个值（系统脚本在两个网络上的二进制完全相同），
/// 区分网络靠的是地址 hrp，而不是 code_hash。
///
/// 语法说明：`pub const`，类型 `[u8; 32]` 是**编译期已知大小的定长数组**。
/// 初值由下面的 `const fn hex_literal_32` 在**编译期**算出来，
/// 因此这里不存在运行期解析十六进制的开销，也不存在解析失败的可能。
pub const SECP256K1_BLAKE160_CODE_HASH: [u8; 32] =
    hex_literal_32("9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8");

/// CKB blake2b 使用 personalization `ckb-default-hash`；blake160 取前 20 字节。
///
/// 领域说明：CKB 全网的哈希函数都是 Blake2b，但带一个固定的
/// **personalization**（个性化串）`ckb-default-hash`，
/// 作用相当于给哈希函数加了个「域名」，避免与其它用途的 Blake2b 撞车。
/// `blake160` = 取该 Blake2b 输出的**前 20 字节**（不是 32 字节全要）。
/// 这 20 字节就是 lock script 的 `args`，也就是我们常说的「公钥哈希」。
///
/// ⚠️ 两个极易写错的点（历史上本函数就是在这里算错过，务必留意）：
/// 1. 必须是**无密钥**模式。`blake2::Blake2bMac` 是带密钥变体，
///    即使把密钥传成 `&[]`，它仍会把一个 128 字节的**全零块**当作密钥块吸收进哈希状态，
///    导致「空密钥 ≠ 无密钥」——这会让派生出的地址与链上不符（资金会打到无人控制的地址）。
/// 2. 必须**先算满 32 字节再截断到 20**，不能一步算出 20 字节。
///    BLAKE2 把「输出长度」写进参数块参与整个运算，所以
///    `blake2b_20(x)` 与 `blake2b_32(x)[..20]` 是**两个完全不同的值**。
///    这跟「先算 SHA-256 再截断」的习惯不同，是 BLAKE2 特有的行为。
///
/// 语法说明：返回 `[u8; 20]` 是**定长数组**（栈上分配、编译期已知大小），
/// 不是 `Vec<u8>`（堆上、长度运行期可变）。定长数组实现了 `Copy`，
/// 所以 `let a = f(); let b = a;` 之后 `a` 仍可用，不会被移走。
pub fn ckb_blake160(data: &[u8]) -> [u8; 20] {
    // `new_blake2b()` 内部等价于
    // `Blake2bBuilder::new(32).personal(b"ckb-default-hash").build()`，
    // 即「输出 32 字节 + personalization = ckb-default-hash + 无密钥」三件事一次到位。
    let mut hasher = new_blake2b();
    // `update` 可多次调用做增量哈希。它是 `blake2b_rs::Blake2b` 的**固有方法**，
    // 不是 trait 方法，因此无需像 `blake2` 那样先 `use digest::Update`。
    // 参数类型是 `&[u8]`（字节切片）：`&Vec<u8>`、`&[u8; N]` 都能自动转成它。
    hasher.update(data);
    // `finalize(&mut [u8])` 把结果写进**调用方提供的缓冲区**，
    // 输出长度由缓冲区长度决定。这里必须给 32 字节，才能与官方定义一致。
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    // 截断到前 20 字节。
    //
    // `copy_from_slice` 在**长度不等时会 panic**；这里 `out` 是 20 字节、
    // `digest[..20]` 也是 20 字节，长度由类型保证，所以可以直接用。
    // 对比 `try_into()`：那会返回 `Result`，适合长度来自运行期数据的场合
    // （见 `parse_lock_json` 里的写法）。
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    out
}

/// 解析后的锁脚本。
///
/// 领域说明：Cell 模型里，谁能花掉一个 cell 由 **lock script** 决定。
/// 一个 script 由三元组唯一确定：
/// - `code_hash`：指向链上已部署的脚本代码；
/// - `hash_type`：说明 `code_hash` 是怎么匹配代码的（data / type / data1 / data2）；
/// - `args`：传给脚本的参数（单签场景就是 blake160(压缩公钥)）。
///
/// 语法说明：`args` 用 `Vec<u8>` 而非 `[u8; 20]`：虽然单签固定 20 字节，
/// 但 CKB 允许多签、自定义锁等任意长度的 args，用 `Vec` 才能通用。
/// `code_hash` 则是恒定的 32 字节，用定长数组更精确。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockScript {
    /// 脚本代码的 blake2b-256 摘要，恒 32 字节。
    pub code_hash: [u8; 32],
    /// 0=data, 1=type, 2=data1, 4=data2。注意**跳号**：没有 3。
    pub hash_type: u8,
    /// 脚本参数；单签场景为 blake160(压缩公钥)，长度可变。
    pub args: Vec<u8>,
}

impl LockScript {
    /// 标准 secp256k1_blake160 单签锁脚本，args 为 blake160(压缩公钥)。
    ///
    /// `hash_type` 取 **1（type）**：系统脚本是按「type script 的 code_hash」匹配的。
    pub fn sighash_blake160(args: [u8; 20]) -> Self {
        Self {
            code_hash: SECP256K1_BLAKE160_CODE_HASH,
            hash_type: 1,
            // `args.to_vec()`：定长数组 `[u8; 20]` → `Vec<u8>`，需要一次堆分配 + 拷贝。
            // 因为 `Self` 无法在编译期知道 args 的长度，这一步无法省掉。
            args: args.to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// bech32（BIP-173）/ bech32m（BIP-350）
//
// 三步走：
//   1. 把 payload 字节流按 5 bit 一组重新切分（8→5 位转换）；
//   2. 用 BCH 码算出 6 个 5-bit 校验字符，追加到数据后面；
//   3. 用固定字母表把每个 5-bit 值转成一个字符，前面拼上 `hrp + "1"`。
// 校验和的作用是让「打错一个字符」的地址几乎必然被拒绝，
// 而不是静默地把币打到一个没人持有私钥的地址。
// ---------------------------------------------------------------------------

/// bech32 字母表（BIP-173 规定，顺序不可改）。
///
/// 刻意**去掉**了容易混淆的 `1`、`b`、`i`、`o` 四个字符，便于人工抄写。
/// 注意 `1` 被保留为 hrp 与数据部分的分隔符，所以字母表里没有它。
const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// bech32 的两个校验和变体：BIP-173 的 `Bech32` 与 BIP-350 修订出的 `Bech32m`。
///
/// 领域说明：两者的**算法完全一致**，只在最后一步异或的常量上不同。
/// 这带来一个极其隐蔽的失败模式——用错常量编出来的地址，
/// **自己编码自己解码永远是通的**（两头用的是同一个常量），
/// 但对方钱包按它的常量一算 polymod 会得到另一个值，于是判定「校验和错误」。
/// 换言之：自往返测试**抓不到**这类 bug，必须有外部实现（官方 ckb-sdk）对拍。
///
/// 语法说明：`#[derive(Clone, Copy)]` 让这个枚举是**按位拷贝**的。
/// 传参时不会转移所有权，所以 `bech32_encode(.., variant)` 之后
/// 调用方还能继续使用原变量；若没有 `Copy`，每次传参都得写 `variant.clone()`。
/// `PartialEq` / `Eq` 则让下面 `variant != Bech32Variant::Bech32m` 的比较成为可能。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bech32Variant {
    /// BIP-173 原始 bech32（常量 `1`）。CKB 的 short / FullData / FullType 用。
    Bech32,
    /// BIP-350 修订版 bech32m（常量 `0x2bc830a3`）。CKB 的 ckb2021 full 用。
    Bech32m,
}

impl Bech32Variant {
    /// 取出该变体对应的校验和常量。
    ///
    /// 语法说明：参数写成 `self` 而不是 `&self`，配合 `Copy` 语义，
    /// 调用时是把整个枚举值拷进去。枚举只有一个 `u32` 的量级，
    /// 拷贝比传引用再解引用更直接，编译器也能更好地优化。
    fn constant(self) -> u32 {
        match self {
            Bech32Variant::Bech32 => 1,
            Bech32Variant::Bech32m => 0x2bc8_30a3,
        }
    }
}
/// BCH 校验码的 5 个生成多项式系数（BIP-173 给定，与字母表一样是标准常量）。
const GEN: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// BCH 校验和的核心：对一串 5-bit 值做多项式模运算。
///
/// 算法要点：维护一个 30 位的寄存器 `chk`，每来一个值就左移 5 位并异或新值；
/// 溢出的高位（`top`）用来决定要不要异或某个生成多项式。
/// 这是 GF(32) 上的长除法，也是整个 bech32 唯一有数学含量的部分。
fn polymod(values: &[u8]) -> u32 {
    let mut chk = 1u32;
    // `for &v in values`：迭代 `&[u8]` 得到 `&u8`，
    // 模式 `&v` 解构出 `u8`（因为 `u8` 是 `Copy` 的，这里可以直接拷出来）。
    for &v in values {
        // 取寄存器最高的 5 位（第 25-29 位），它们马上要被移出去。
        let top = chk >> 25;
        // 左移 5 位腾出空间，清掉溢出的高位，再并入新的 5-bit 值。
        // `0x01ff_ffff` 是低 25 位的掩码；中间的下划线只是可读性分隔，不影响数值。
        chk = (chk & 0x01ff_ffff) << 5 ^ u32::from(v);
        // `.iter().enumerate()` 同时给出下标 `i` 与元素引用 `g`。
        for (i, g) in GEN.iter().enumerate() {
            // `top` 的第 i 位为 1 时，异或第 i 个生成多项式。
            // `(top >> i) & 1 == 1` 就是「取第 i 位」。
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// 把 hrp 扩展成参与校验和运算的高位部分（BIP-173 规定：先放每个字符的高 3 位，
/// 再放一个 0，最后放每个字符的低 5 位）。
///
/// 这样做是为了让 hrp 的错字也能被校验和捕捉到。
fn hrp_expand(hrp: &str) -> Vec<u8> {
    // 输出长度 = 字符数 * 2 + 1（中间那个 0）。
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    // `hrp.bytes()` 迭代出 `u8`；hrp 恒为 ASCII（"ckb" / "ckt"），可以安全按字节处理。
    for b in hrp.bytes() {
        // `b >> 5`：取高 3 位。
        out.push(b >> 5);
    }
    out.push(0);
    for b in hrp.bytes() {
        // `b & 31`：取低 5 位（31 的二进制是 11111）。
        out.push(b & 31);
    }
    out
}

/// 计算 6 个校验字符。
fn create_checksum(hrp: &str, data: &[u8], variant: Bech32Variant) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    // 先追加 6 个 0 占位，算完 polymod 后填回真正的值——
    // 这是 BCH 码「系统码」形式的标准做法：校验位就写在数据后面。
    // `std::iter::repeat_n(0u8, 6)` 产生 6 个 0u8 的迭代器。
    values.extend(std::iter::repeat_n(0u8, 6));
    // 异或常量后即为校验值。具体用哪个常量由调用方按地址格式类型指定
    // （`0x00` 型是 bech32m，其余三种是 bech32）。
    let modulus = polymod(&values) ^ variant.constant();
    let mut checksum = [0u8; 6];
    // 把 30 位的 `modulus` 拆成 6 个 5-bit 值。
    //
    // `.iter_mut()` 给出 `&mut u8`，所以要 `*slot = ..` 写回。
    // `5 * (5 - i)`：第 0 个槽取最高 5 位（位移 25），最后一个槽取最低 5 位（位移 0）。
    // `& 31` 取出这 5 位。
    for (i, slot) in checksum.iter_mut().enumerate() {
        *slot = ((modulus >> (5 * (5 - i))) & 31) as u8;
    }
    checksum
}

/// 位宽转换：把 `data` 中每个 `from` 位的值，重新打包成每 `to` 位一个值。
///
/// 编码时是 8→5（字节流切成 5-bit 组），解码时是 5→8（5-bit 组拼回字节）。
/// 这是所有「base32 家族」编码共用的通用例程。
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, SdkError> {
    let mut acc = 0u32; // 累加器：暂存还没凑够一个输出单元的位
    let mut bits = 0u32; // 累加器里当前有多少有效位
    // `maxv` 是 `to` 位能表示的最大值（如 to=5 时是 31），用作掩码。
    let maxv = (1u32 << to) - 1;
    let mut out = Vec::new();
    for &value in data {
        let v = u32::from(value);
        // 输入值超出了 `from` 位能表示的范围 → 数据有问题，直接报错。
        // 例如 from=5 时，任何 > 31 的输入都是非法的。
        if v >> from != 0 {
            return Err(SdkError::invalid_argument("bech32 位转换时发现越界值"));
        }
        // 把新值接到累加器尾部。
        acc = (acc << from) | v;
        bits += from;
        // 攒够 `to` 位就吐出一个输出值。
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        // 编码方向：剩余的零头不足 `to` 位，左移补零后输出最后一个值。
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        // 解码方向：**严格模式**。两个条件任一成立都说明数据不合法：
        // - `bits >= from`：还剩了整整一个输入单元没吐出来，说明数据多了；
        // - 剩余的零头位不是全 0：说明编码时补的 padding 不是标准形式
        //   （这能挡住「同一串数据有多种编码表示」的延展性攻击）。
        return Err(SdkError::new(
            ErrorCode::ParseError,
            "bech32 padding 不完整",
        ));
    }
    Ok(out)
}

/// bech32 编码：payload 字节 → `hrp1<数据><校验和>`。
fn bech32_encode(hrp: &str, payload: &[u8], variant: Bech32Variant) -> String {
    // `.expect(..)`：8→5 位转换**不可能**失败（8 位输入永不超过 8 位表示范围，
    // pad=true 分支也不会报错），失败只可能是代码 bug，因此 panic 是合适的。
    let mut data = convert_bits(payload, 8, 5, true).expect("8→5 位转换不会失败");
    let checksum = create_checksum(hrp, &data, variant);
    data.extend_from_slice(&checksum);
    // hrp 与数据之间固定用 `1` 分隔。
    let mut out = format!("{hrp}1");
    for v in data {
        // `CHARSET[v as usize] as char`：5-bit 值 → 字母表字节 → char。
        // `v` 恒在 0..=31 内（由 convert_bits 保证），索引不会越界。
        out.push(CHARSET[v as usize] as char);
    }
    out
}

/// bech32 / bech32m 解码：校验并拆出 `(hrp, payload, variant)`。
///
/// 返回值里带上 **变体**，是因为光靠校验通过还不够：CKB 规定
/// `0x00` 型必须配 bech32m、其余三种必须配 bech32（见模块文档的格式表）。
/// 由 `decode_address` 拿着这个变体去核对「格式类型 ↔ 编码变体」是否匹配。
fn bech32_decode(raw: &str) -> Result<(String, Vec<u8>, Bech32Variant), SdkError> {
    // 最短形如 `ckb1` + 6 个校验字符 = 4+6 = 10，这里放宽到 8 做下限；
    // 255 是 BIP-173 规定的总长度上限（保证校验和的检错能力）。
    if raw.len() < 8 || raw.len() > 255 {
        return Err(SdkError::invalid_argument("地址长度不合法"));
    }
    // bech32 规定全小写或全大写，**不允许混用**。
    // 判断方法：原串既不等于自己的全小写形式、也不等于全大写形式，那就是混用了。
    if raw != raw.to_ascii_lowercase() && raw != raw.to_ascii_uppercase() {
        return Err(SdkError::invalid_argument("地址大小写混用"));
    }
    // 统一转小写处理；大写形式仅在展示时合法（BIP-173 允许全大写便于二维码）。
    let lower = raw.to_ascii_lowercase();
    // `rfind('1')` 从**右侧**找分隔符——因为 hrp 里不可能有 `1`，
    // 用 rfind 或 find 都一样，但 rfind 更能表达「取最后一个 1」的意图。
    let pos = lower
        .rfind('1')
        .ok_or_else(|| SdkError::invalid_argument("地址缺少分隔符 1"))?;
    // `lower[..pos]` 是字符串切片语法，取前 pos 个字节。
    let hrp = lower[..pos].to_string();
    let data_part = &lower[pos + 1..];
    let mut values = Vec::with_capacity(data_part.len());
    for c in data_part.bytes() {
        // 反查字母表：找不到就说明字符非法（比如用户把 `l` 抄成了 `1`）。
        //
        // `CHARSET.iter().position(|&x| x == c)`：
        // - `position` 返回**第一个**满足条件元素的下标（`Option<usize>`）；
        // - 闭包参数 `|&x|` 解构 `&u8` 得到 `u8`。
        // 这是 O(n) 线性查找，但字母表只有 32 项、地址也短，代价可忽略。
        let idx = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or_else(|| SdkError::invalid_argument("地址含非法字符"))?;
        values.push(idx as u8);
    }
    // 数据部分至少要有 6 个校验字符，否则无从校验。
    if values.len() < 6 {
        return Err(SdkError::invalid_argument("地址校验和缺失"));
    }
    // 重新走一遍 polymod，看算出的值能对上**哪个**常量：
    // - 等于 `1` → 这是 bech32；
    // - 等于 `0x2bc830a3` → 这是 bech32m；
    // - 都不等 → 校验和错误。
    // polymod 的结果只能是一个确定值，所以两个分支互斥，不存在歧义。
    let mut expanded = hrp_expand(&hrp);
    expanded.extend_from_slice(&values);
    let variant = match polymod(&expanded) {
        m if m == Bech32Variant::Bech32.constant() => Bech32Variant::Bech32,
        m if m == Bech32Variant::Bech32m.constant() => Bech32Variant::Bech32m,
        _ => return Err(SdkError::invalid_argument("地址校验和错误")),
    };
    // 剥掉末尾 6 个校验字符，剩下的 5-bit 值拼回字节。
    // `pad = false` 走严格模式，会检查 padding 是否规范。
    let payload = convert_bits(&values[..values.len() - 6], 5, 8, false)?;
    Ok((hrp, payload, variant))
}

// ---------------------------------------------------------------------------
// 对外地址编解码
// ---------------------------------------------------------------------------

/// 地址 payload 的首字节：ckb2021 full 格式（`0x00`）。这是当前的**标准格式**。
const ADDR_FULL: u8 = 0x00;
/// 地址 payload 的首字节：已废弃的 short 格式（`0x01`）。
const ADDR_SHORT: u8 = 0x01;
/// 地址 payload 的首字节：已废弃的 FullData 格式（`0x02`），隐含 hash_type = data。
const ADDR_FULL_DATA: u8 = 0x02;
/// 地址 payload 的首字节：已废弃的 FullType 格式（`0x04`），隐含 hash_type = type。
const ADDR_FULL_TYPE: u8 = 0x04;
/// short 地址里 `code_hash_index` 表示 secp256k1_blake160 单签的那个取值。
const CODE_HASH_INDEX_SIGHASH: u8 = 0x00;

/// 主网 / 其余网络（测试网、开发网）的 bech32 hrp。
///
/// 语法说明：`const fn` 表示这个函数**可以在编译期求值**。
/// 返回 `&'static str` 是写进二进制只读段的字面量，运行时零分配。
/// 因为只是选字面量、没有分配也没有循环，所以有资格当 `const fn`。
const fn hrp(is_mainnet: bool) -> &'static str {
    if is_mainnet {
        "ckb"
    } else {
        "ckt"
    }
}

/// `hash_type` 的合法取值只有 0/1/2/4，且**跳号**（没有 3）。
///
/// 为什么必须在解析时拦住：这个字节直接来自用户输入的地址，
/// 之后会被原样塞进 `get_cells` 的查询条件里。若放一个非法值进去，
/// 链上不会报错，只会静默「查不到任何 cell」，表现为**余额恒为 0**——
/// 一个不会报错、只会给出错误答案的 bug，比崩溃更危险。
///
/// 语法说明：`match` 的多个分支用 `|` 合并，等价于其它语言里的 `case 0: case 1: ...`。
/// 兜底分支把匹配到的值**绑定**到变量 `other` 上（这就是「绑定模式」），
/// 于是后面的格式串里可以直接用它。
fn valid_hash_type(value: u8) -> Result<u8, SdkError> {
    match value {
        0 | 1 | 2 | 4 => Ok(value),
        other => Err(SdkError::invalid_argument(format!(
            "非法 hash_type: {other}（合法取值为 0/1/2/4，注意没有 3）"
        ))),
    }
}

/// 把锁脚本编码为 **ckb2021 full 地址**；`is_mainnet` 决定 hrp 是 ckb 还是 ckt。
///
/// 主网地址以 `ckb1` 开头，测试网 / 开发网以 `ckt1` 开头——
/// 这是人工区分 CKB 网络最直接的方式。
///
/// 输出的是 `0x00` 型地址，payload 为**扁平拼接**：
/// `0x00 | code_hash(32) | hash_type(1) | args`，并用 **bech32m** 编码。
pub fn encode_address(script: &LockScript, is_mainnet: bool) -> String {
    // payload 结构没有任何长度前缀或偏移量——就是四个字段依次排开。
    // 这也是它与「交易内部的 molecule 序列化」最大的区别：
    // molecule 要存 total_size 与三个 field offset，地址则一律省略。
    //
    // `Vec::with_capacity(34 + args.len())` 一次预留够容量，
    // 避免后续三次 `extend_from_slice` 触发扩容重分配。
    let mut payload = Vec::with_capacity(34 + script.args.len());
    payload.push(ADDR_FULL);
    payload.extend_from_slice(&script.code_hash);
    payload.push(script.hash_type);
    payload.extend_from_slice(&script.args);
    // ⚠️ 必须是 **bech32m**。用 bech32 编出来的地址自己能解回来，
    // 但官方 ckb-sdk 会直接拒绝（"ckb2021 format full address must use
    // bech32m encoding"），其它钱包同理。
    bech32_encode(hrp(is_mainnet), &payload, Bech32Variant::Bech32m)
}

/// 旧 short 格式的 secp256k1_blake160 地址（payload = 0x01 0x00 + 20 字节 args）。
///
/// 该格式已被官方标记为 deprecated，但历史地址仍广泛存在，因此保留编码能力。
///
/// 为什么旧格式能短那么多：short 格式不存完整的 32 字节 code_hash，
/// 而是存一个 1 字节的 `code_hash_index`（0x00 = secp256k1_blake160），
/// hash_type 也隐含为 type。代价是**只能表达极少数预设脚本**，
/// 无法表达多签、自定义锁等，所以被 full 格式取代。
pub fn encode_short_sighash_address(args: &[u8], is_mainnet: bool) -> Result<String, SdkError> {
    if args.len() != 20 {
        return Err(SdkError::invalid_argument(format!(
            "short 单签地址的 args 必须是 20 字节 blake160，实际 {} 字节",
            args.len()
        )));
    }
    // 1（format）+ 1（code_hash_index）+ 20（args）= 22 字节。
    let mut payload = Vec::with_capacity(22);
    payload.push(ADDR_SHORT);
    payload.push(CODE_HASH_INDEX_SIGHASH);
    payload.extend_from_slice(args);
    // short 格式是 ckb2021 之前的产物，用 bech32（常量 1），不是 bech32m。
    Ok(bech32_encode(
        hrp(is_mainnet),
        &payload,
        Bech32Variant::Bech32,
    ))
}

/// 解析 CKB 地址，返回锁脚本与是否主网。
///
/// 支持全部四种格式（ckb2021 full / short / FullData / FullType）。
/// 后三种是历史格式，只解不编——新地址一律用 `encode_address` 产出 `0x00` 型。
///
/// 注意 `hrp` 与 `is_mainnet` 是**同一个信息**的两种表达：
/// 之所以把 `bool` 也一并返回，是因为调用方（如 `adapter.rs` 的 `balance`）
/// 需要拿它去决定「后续派生出来的地址用哪个 hrp」，
/// 而不必自己再维护一份 hrp → bool 的映射。
pub fn decode_address(raw: &str) -> Result<(LockScript, bool), SdkError> {
    // `raw.trim()`：先去掉首尾空白——用户从终端粘贴地址时很容易带空格或换行。
    let (hrp, payload, variant) = bech32_decode(raw.trim())?;
    // 校验和已经过了，但 hrp 还可能是任意字符串（比如另一个链的 bech32 地址），
    // 所以这里必须认准 `ckb` / `ckt`。
    let is_mainnet = match hrp.as_str() {
        "ckb" => true,
        "ckt" => false,
        other => {
            return Err(SdkError::invalid_argument(format!(
                "非法 CKB 地址前缀: {other}（应为 ckb / ckt）"
            )));
        }
    };
    // payload 的第一个字节是**格式类型**，决定后续怎么解释剩下的字节。
    //
    // `*payload.first().ok_or_else(..)?`：
    // - `first()` 返回 `Option<&u8>`（空 payload 时是 `None`，挡住空地址）；
    // - `?` 在 `None` 时提前返回错误；
    // - `*` 解引用拷出 `u8`（`u8` 是 `Copy` 的）。
    let format = *payload
        .first()
        .ok_or_else(|| SdkError::invalid_argument("空地址 payload"))?;
    // 定义一个**闭包**来构造错误，避免下面七八处重复写 `SdkError::new(..)`。
    //
    // 语法说明：这里必须是闭包，不能写成 `let bad = SdkError::new(..)`——
    // 后者只造出**一个**值，而 `SdkError` 不实现 `Copy`，
    // 第一次 `?` 传出去就被移走了，第二次用会编译报「use of moved value」。
    // 闭包则每次调用都新造一个值，可以用任意多次。
    let bad = || SdkError::new(ErrorCode::ParseError, "地址 payload 结构非法");
    // 去掉首字节格式标记后的剩余部分。因为上面 `first()` 已成功，
    // 这里 `payload[1..]` 一定不会越界。
    let body = &payload[1..];
    match format {
        // ---- ckb2021 full：`0x00 | code_hash(32) | hash_type(1) | args` + bech32m ----
        ADDR_FULL => {
            // 格式类型与 bech32 变体必须**成对**出现。
            // 这正是官方 ckb-sdk 的硬性要求；缺了这一条，
            // 「用错常量编出的地址」就能混进系统里，直到对方钱包拒收才暴露。
            if variant != Bech32Variant::Bech32m {
                return Err(SdkError::invalid_argument(
                    "ckb2021 full 地址（0x00）必须使用 bech32m 编码",
                ));
            }
            // 1（格式字节）+ 32（code_hash）+ 1（hash_type）= 34 是最小长度。
            if payload.len() < 34 {
                return Err(bad());
            }
            // `body.get(0..32).and_then(|s| s.try_into().ok()).ok_or_else(bad)?`
            // 是三步组合拳，每一步各有分工：
            // - `get(..)` 返回 `Option`，越界时是 `None` 而非 panic
            //   （处理外部数据**必须**用 `get` 而不是直接下标）；
            // - `try_into()` 尝试把 `&[u8]` 转成长度精确的 `&[u8; 32]`；
            // - `.ok()` 把 `Result` 降级成 `Option`，`and_then` 把两步串起来并扁平化，
            //   避免出现 `Option<Result<..>>` 这种嵌套类型；
            // - `ok_or_else(bad)?` 把 `Option` 转回 `Result`，失败时提前返回错误。
            let code_hash: [u8; 32] = body
                .get(0..32)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(bad)?;
            // 这里直接把闭包 `bad` 当函数传给 `ok_or_else`——
            // 因为它的签名恰好是 `FnOnce() -> SdkError`。
            let hash_type = valid_hash_type(*body.get(32).ok_or_else(bad)?)?;
            // `.to_vec()`：把 `&[u8]` 切片拷成 `Vec<u8>`，取得所有权放进 `LockScript`。
            let args = body.get(33..).ok_or_else(bad)?.to_vec();
            Ok((
                LockScript {
                    code_hash,
                    hash_type,
                    args,
                },
                is_mainnet,
            ))
        }
        // ---- 已废弃的 FullData / FullType：`0x02|0x04 | code_hash(32) | args` + bech32 ----
        //
        // 语法说明：`ADDR_FULL_DATA | ADDR_FULL_TYPE` 是**或模式**（or-pattern），
        // 一个分支匹配多个值，比写两个内容相同的分支清爽。
        ADDR_FULL_DATA | ADDR_FULL_TYPE => {
            if variant != Bech32Variant::Bech32 {
                return Err(SdkError::invalid_argument(
                    "旧式 full 地址（0x02/0x04）必须使用 bech32 编码",
                ));
            }
            // 1 + 32 = 33 是最小长度（args 允许为空）。
            if payload.len() < 33 {
                return Err(bad());
            }
            let code_hash: [u8; 32] = body
                .get(0..32)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(bad)?;
            // 这两种旧格式**没有** hash_type 字节，它由格式字节本身隐含：
            // `0x02` = FullData → data(0)，`0x04` = FullType → type(1)。
            // 注意别写成 `format - 0x02`：那会把 `0x04` 映射成 2（data1），是错的。
            let hash_type = if format == ADDR_FULL_DATA { 0 } else { 1 };
            let args = body.get(32..).ok_or_else(bad)?.to_vec();
            Ok((
                LockScript {
                    code_hash,
                    hash_type,
                    args,
                },
                is_mainnet,
            ))
        }
        // ---- 已废弃的 short：`0x01 | code_hash_index(1) | args` + bech32 ----
        ADDR_SHORT => {
            if variant != Bech32Variant::Bech32 {
                return Err(SdkError::invalid_argument(
                    "short 地址（0x01）必须使用 bech32 编码",
                ));
            }
            // short 的长度是**固定** 22 字节（1 + 1 + 20），所以判相等而不是判下界：
            // 多一个或少一个字节都说明这个地址不是合法的 short 格式。
            if payload.len() != 22 {
                return Err(bad());
            }
            let index = *body.first().ok_or_else(bad)?;
            // 除 0x00 以外的 index 对应的旧脚本类型（如 0x01 = secp256k1_blake160_multisig）
            // 官方早已废弃，这里不提供解码，直接引导用户改用 full 格式。
            //
            // 格式串 `{index:#04x}`：`#` 表示带 `0x` 前缀，`04` 表示最小宽度 4 且补零，
            // `x` 表示小写十六进制。于是 0x01 打印成 `0x01` 而不是 `1`。
            if index != CODE_HASH_INDEX_SIGHASH {
                return Err(SdkError::unsupported(format!(
                    "短地址 code_hash_index={index:#04x} 已废弃，请使用 full 格式地址"
                )));
            }
            let args = body.get(1..).ok_or_else(bad)?.to_vec();
            // 用常量 code_hash + 隐含的 hash_type=type 重建出完整的 lock script，
            // 于是「旧地址」与「新地址」在上层看起来是同一种东西。
            Ok((
                LockScript {
                    code_hash: SECP256K1_BLAKE160_CODE_HASH,
                    hash_type: 1,
                    args,
                },
                is_mainnet,
            ))
        }
        other => Err(SdkError::invalid_argument(format!(
            "未知 CKB 地址格式类型: {other:#04x}"
        ))),
    }
}

/// 压缩 secp256k1 公钥（33 字节）→ 标准单签地址。
///
/// 这是 `adapter.rs` 里 `address_from_pubkey` 的底层实现，单独暴露出来
/// 是为了让不想构造 `CkbClient` 的调用方也能直接算地址。
pub fn address_from_compressed_pubkey(
    pubkey_hex: &str,
    is_mainnet: bool,
) -> Result<String, SdkError> {
    // `hexutil::decode_hex` 允许 `0x` / `0X` 前缀、大小写不敏感。
    let bytes = hexutil::decode_hex(pubkey_hex)?;
    // 必须是**压缩**公钥：33 字节 = 1 字节前缀（02/03）+ 32 字节 x 坐标。
    // 未压缩格式是 65 字节（多一个 y 坐标），CKB 不用。
    if bytes.len() != 33 {
        return Err(SdkError::invalid_argument(format!(
            "CKB 单签公钥需为 33 字节压缩 secp256k1 公钥，实际 {} 字节",
            bytes.len()
        )));
    }
    let mut args = [0u8; 20];
    // `ckb_blake160` 返回的已经是 `[u8; 20]`，
    // 这里 copy 一份只是为了让 `args` 这个变量名更表意（它就是 lock 的 args）。
    args.copy_from_slice(&ckb_blake160(&bytes));
    Ok(encode_address(
        &LockScript::sighash_blake160(args),
        is_mainnet,
    ))
}

/// 编译期把 64 位十六进制常量转为 [u8;32]。
///
/// 语法说明：`const fn` 是**可在编译期求值**的函数，受严格限制：
/// 不能用 `for` 遍历迭代器（迭代器 trait 不是 const）、不能调用非 `const fn`、
/// 不能分配堆内存。所以下面只能写 `while` 循环 + 数组索引。
/// 好处是：常量初值在编译期就算好了，运行期零开销，且解析失败会**编译不过**。
const fn hex_literal_32(hex: &str) -> [u8; 32] {
    let bytes = hex.as_bytes();
    // `assert!` 在 `const fn` 里也是编译期检查：写错长度会直接编译失败，
    // 而不是等到运行时才发现 code_hash 不对。
    assert!(bytes.len() == 64, "code_hash 必须是 32 字节十六进制");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        // 每两个十六进制字符合成一个字节：高 4 位 + 低 4 位。
        let hi = hex_nibble(bytes[i * 2]);
        let lo = hex_nibble(bytes[i * 2 + 1]);
        // `<< 4` 把高位值挪到字节的高半部分，`|` 并入低位。
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    out
}

/// 单个十六进制字符 → 数值。`const fn` 里不能用 `to_digit`（非 const），
/// 因此手写 `match`。
const fn hex_nibble(b: u8) -> u8 {
    match b {
        // `b'0'..=b'9'` 是**字节字面量的闭区间模式**。
        // `b'0'` 的类型是 `u8`，值 48；减去 `b'0'` 就把 '0'-'9' 映射成 0-9。
        b'0'..=b'9' => b - b'0',
        // 字母 a-f 映射到 10-15。
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        // `panic!` 在 `const fn` 中同样是编译期触发的错误。
        _ => panic!("非法十六进制字符"),
    }
}

/// 单元测试模块：`#[cfg(test)]` 保证它只在 `cargo test` 时编译。
#[cfg(test)]
mod tests {
    use super::*;

    /// 测试专用：把地址拆回 `(hrp, 5-bit 值序列)`，以便**绕开** `bech32_decode`
    /// 直接用 `polymod` 复算校验和。
    ///
    /// 为什么需要它：验证「用的是哪个 bech32 变体」必须能自己指定常量去比对。
    /// 而 `bech32_decode` 内部已经替我们挑好了变体，从外面看不出它试过几次、
    /// 也不知道它对上了哪个常量，所以这里得回到更底层的材料上。
    fn split_data_part(addr: &str) -> (String, Vec<u8>) {
        let pos = addr.rfind('1').expect("地址缺少分隔符 1");
        let hrp = addr[..pos].to_string();
        let values = addr[pos + 1..]
            .bytes()
            .map(|c| {
                CHARSET
                    .iter()
                    .position(|&x| x == c)
                    .expect("地址含非法字符") as u8
            })
            .collect();
        (hrp, values)
    }

    #[test]
    fn encodes_known_short_address_vector() {
        // CKB 官方文档经典 short 地址向量。
        //
        // 用**官方公布的向量**而不是自己算的期望值，才能真正验证实现正确——
        // 自己算等于用同一套（可能也错的）逻辑验证自身。
        let args = hexutil::decode_hex("b39bbc0b3673c7d36450bc14cfcdad2d559c6c64").unwrap();
        assert_eq!(
            encode_short_sighash_address(&args, true).unwrap(),
            "ckb1qyqt8xaupvm8837nv3gtc9x0ekkj64vud3jqfwyw5v"
        );
        // 测试网的同一把钥匙应得到 `ckt1` 开头、数据部分相同的地址。
        assert!(
            encode_short_sighash_address(&args, false)
                .unwrap()
                .starts_with("ckt1")
        );
    }

    #[test]
    fn encodes_and_decodes_full_address_roundtrip() {
        let mut args = [0u8; 20];
        args.copy_from_slice(
            &hexutil::decode_hex("36c329ed630d6ce750712a477543672adab57f4c").unwrap(),
        );
        let script = LockScript::sighash_blake160(args);
        let addr = encode_address(&script, true);
        // full 地址的 payload 是 `0x00 | code_hash | hash_type | args`。
        // 所有标准单签地址的 code_hash 都是同一个系统常量，所以它们共享同一段前缀：
        //   `0x00 0x9b` → 二进制 `00000 00001 00110 11...` → 下标 0、2、13 → `q`、`z`、`d`
        // 于是恒以 `ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq` 开头。
        // 对比：short 地址 payload 是 `0x01 0x00` → `q`、`y`，以 `ckb1qy` 开头
        // ——这是肉眼区分两种地址格式最快的办法。
        //
        // 注意这个前缀**与具体 args 无关**（它只覆盖 code_hash 与 hash_type），
        // 所以它同时也是一个「格式没写错」的护栏：
        // 一旦有人把 payload 改回 molecule 布局（首字节后会多出 total_size），
        // 这里立刻就会红。
        assert!(
            addr.starts_with("ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq"),
            "full 地址前缀不符，实际 {addr}"
        );
        // 往返测试：编码再解码必须还原出**完全相同**的 script。
        // 这依赖 `LockScript` 派生了 `PartialEq`。
        let (decoded, mainnet) = decode_address(&addr).unwrap();
        assert!(mainnet);
        assert_eq!(decoded, script);
    }

    #[test]
    fn full_address_is_bech32m_not_bech32() {
        // 这是**最关键**的一条测试：验证 `0x00` 型地址确实用了 bech32m。
        //
        // 为什么单靠往返测试抓不到：bech32 与 bech32m 算法相同、只有常量不同，
        // 「自己编码、自己解码」永远自洽。唯一能发现的办法是换个常量再验一次——
        // 如果按 bech32 的常量也能验过，那就说明编出来的其实是 bech32。
        let args = [0x11u8; 20];
        let addr = encode_address(&LockScript::sighash_blake160(args), true);
        // 用 bech32 的常量重新算一遍校验和，结果必须**不等于** 1。
        // 若等于 1，说明这个地址其实是用 bech32 编的，属于格式错误。
        let (hrp, values) = split_data_part(&addr);
        let mut expanded = hrp_expand(&hrp);
        expanded.extend_from_slice(&values);
        assert_ne!(
            polymod(&expanded),
            Bech32Variant::Bech32.constant(),
            "full 地址不应能通过 bech32 常量校验"
        );
        assert_eq!(
            polymod(&expanded),
            Bech32Variant::Bech32m.constant(),
            "full 地址必须通过 bech32m 常量校验"
        );
    }

    #[test]
    fn rejects_full_address_encoded_with_wrong_variant() {
        // 反向用例：手动用 **bech32** 编一个 `0x00` 型 payload，解码必须拒绝。
        // 这正是「用错常量」会产出的那种地址——自洽，但任何钱包都不认。
        let mut payload = vec![ADDR_FULL];
        payload.extend_from_slice(&SECP256K1_BLAKE160_CODE_HASH);
        payload.push(1);
        payload.extend_from_slice(&[0x22u8; 20]);
        let wrong = bech32_encode("ckb", &payload, Bech32Variant::Bech32);
        assert!(
            decode_address(&wrong).is_err(),
            "用 bech32 编码的 0x00 型地址必须被拒绝"
        );
        // 换成 bech32m 就能通过，证明拒绝的原因确实是变体而非其它。
        let right = bech32_encode("ckb", &payload, Bech32Variant::Bech32m);
        assert!(decode_address(&right).is_ok());
    }

    #[test]
    fn rejects_invalid_hash_type() {
        // `hash_type` 只有 0/1/2/4 合法。放个 3 进去，解码必须拒绝——
        // 否则它会被原样送进 `get_cells` 查询条件，链上不报错、只返回空结果，
        // 表现为「余额恒为 0」这种不会崩但答案错的 bug。
        let mut payload = vec![ADDR_FULL];
        payload.extend_from_slice(&SECP256K1_BLAKE160_CODE_HASH);
        payload.push(3);
        payload.extend_from_slice(&[0x33u8; 20]);
        let addr = bech32_encode("ckb", &payload, Bech32Variant::Bech32m);
        assert!(decode_address(&addr).is_err());
    }

    #[test]
    fn decodes_deprecated_short_and_full_type_addresses() {
        // 历史格式只需能解、不需能编。这里同时验证：
        // 1. short（`0x01`）能还原出等价的 lock script；
        // 2. 旧式 FullType（`0x04`）能还原出 code_hash 与 args，且 hash_type 隐含为 type(1)。
        let args = hexutil::decode_hex("b39bbc0b3673c7d36450bc14cfcdad2d559c6c64").unwrap();
        let short = encode_short_sighash_address(&args, true).unwrap();
        let (script, mainnet) = decode_address(&short).unwrap();
        assert!(mainnet);
        assert_eq!(script, LockScript::sighash_blake160(<[u8; 20]>::try_from(args.as_slice()).unwrap()));

        // 旧式 FullType：`0x04 | code_hash | args`，用 bech32。
        let mut payload = vec![ADDR_FULL_TYPE];
        payload.extend_from_slice(&SECP256K1_BLAKE160_CODE_HASH);
        payload.extend_from_slice(&args);
        let old_full = bech32_encode("ckb", &payload, Bech32Variant::Bech32);
        let (script, _) = decode_address(&old_full).unwrap();
        assert_eq!(script.code_hash, SECP256K1_BLAKE160_CODE_HASH);
        assert_eq!(script.hash_type, 1, "0x04 型隐含 hash_type = type(1)");
        assert_eq!(script.args, args);
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut s = "ckb1qyqt8xaupvm8837nv3gtc9x0ekkj64vud3jqfwyw5v".to_string();
        s.replace_range(7..8, "q"); // 改动数据部分一个字符（t→q）
        // 改了任意一个字符，polymod 的结果就不可能再等于常量 1，
        // 这正是 bech32 校验和存在的意义：防手抄错误把币打丢。
        //
        // `replace_range` 按**字节**区间替换，这里替换的是单个 ASCII 字符，安全。
        assert!(decode_address(&s).is_err());
    }

    #[test]
    fn blake160_matches_official_ckb_hash_vector() {
        // 期望值取自 **CKB 官方 crate `ckb-hash` 的 `new_blake2b()`**，
        // 而不是用本文件的实现自算一遍——用自家实现验证自家实现等于没验证，
        // 历史上本函数正是因为缺少外部向量把关而算错了。
        //
        // 这两个向量一次性钉死三件事，任何一件写错都会红：
        //   1. personalization 确实是 `ckb-default-hash`；
        //   2. 走的是**无密钥**模式（误用 `Blake2bMac` 会吞掉一个全零密钥块，结果不同）；
        //   3. 先算满 32 字节再截断（直接输出 20 字节也会得到另一个值）。
        let pubkey = hexutil::decode_hex(
            "0263af818c963ec94d18912196ed6b20d992fb5e62ac890fd9b2f7123c86d01e46",
        )
        .unwrap();
        assert_eq!(
            hexutil::encode_hex(&ckb_blake160(&pubkey)),
            "cfe81e676437184be90962709dacfb264054d772"
        );
        assert_eq!(
            hexutil::encode_hex(&ckb_blake160(b"hello")),
            "2da1289373a9f6b7ed21db948f4dc5d942cf4023"
        );
    }

    #[test]
    fn blake160_is_stable() {
        // 同一输入两次结果必须一致（确定性），不同输入结果必须不同（抗碰撞）。
        let a = ckb_blake160(b"hello");
        let b = ckb_blake160(b"hello");
        assert_eq!(a, b);
        assert_ne!(a, ckb_blake160(b"world"));
    }
}
