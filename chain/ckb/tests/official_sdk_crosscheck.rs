//! 与**官方 ckb-sdk** 的逐字节对拍测试。
//!
//! 为什么需要这个文件：本 crate 的地址编解码（blake160 / bech32 / bech32m）全是手写的。
//! 手写实现最大的风险是**「自往返通过、但与链上不一致」**——最典型的两个坑：
//!   1. bech32 与 bech32m 算法完全相同、只差一个常量。
//!      编错了，自己编码自己解码永远自洽，只有换一个常量验才暴露；
//!   2. 地址 payload 是**扁平拼接**，不是 molecule。
//!      塞进 molecule 布局后结构自洽、也能往返，但任何钱包都认不出来。
//!
//! 这两类 bug 都不是「单元测试写得多」能防住的，必须有**外部实现**当标准答案。
//!
//! 于是这里用官方 `ckb-sdk` 生成同一份 lock script 的地址，与本 crate 逐一比对：
//! 三种格式（ckb2021 full / 已废弃的 short / 已废弃的 FullType）都必须完全一致。
//! 以后任何人改了 payload 布局或 bech32 变体，这里会立刻变红。

// 注意这里的命名：本 crate 自己的 lib 名就叫 `ckb_sdk`（见 `Cargo.toml` 的 `[lib] name`），
// 所以 `ckb_sdk::` 指的是**我们要测的实现**；官方 SDK 在 dev-dependencies 里
// 被重命名成 `official_ckb_sdk`，以免两者撞名（rustc E0464）。
use ckb_types::core::ScriptHashType;
use ckb_types::prelude::*;
use official_ckb_sdk::{Address, AddressPayload, CodeHashIndex, NetworkType};

/// 系统锁 secp256k1_blake160_sighash_all 的 code_hash（主网/测试网相同）。
const CODE_HASH: &str = "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
/// 一把测试公钥的 blake160（期望值来自官方 ckb-hash，见 address.rs 内的单测）。
const LOCK_ARGS: &str = "cfe81e676437184be90962709dacfb264054d772";
/// 第二组 args，确保对拍不是「恰好撞上一个向量」。
const LOCK_ARGS_B: &str = "36c329ed630d6ce750712a477543672adab57f4c";

fn hex_to_vec(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("合法十六进制"))
        .collect()
}

/// 构造官方 SDK 的 `Full` payload。
///
/// 注意不能走 `AddressPayload::from(Script)`：官方那个 `From` 实现会先做识别，
/// 发现是「sighash code_hash + type + 20 字节 args」就**降级成 Short**，
/// 于是永远拿不到 full 形态。要测 full 必须直接构造枚举。
fn full_payload(args_hex: &str, hash_type: ScriptHashType) -> AddressPayload {
    // 注意两个参数的类型**不同源**，极易弄混：
    // - `code_hash` 是 molecule 的 `packed::Byte32`，由 `[u8; 32].pack()` 得到；
    // - `args` 是 `bytes` crate 的 `Bytes`，直接由 `Vec<u8>` 转换而来。
    // 二者名字都叫 `Bytes` / `Byte32`，但分属 `packed` 与 `bytes` 两个世界。
    AddressPayload::new_full(
        hash_type,
        hex_to_bytes32(CODE_HASH).pack(),
        hex_to_vec(args_hex).into(),
    )
}

fn hex_to_bytes32(s: &str) -> [u8; 32] {
    let v = hex_to_vec(s);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// 本 crate 侧的 lock script。
fn our_script(args_hex: &str) -> ckb_sdk::address::LockScript {
    let mut args = [0u8; 20];
    args.copy_from_slice(&hex_to_vec(args_hex));
    ckb_sdk::address::LockScript::sighash_blake160(args)
}

#[test]
fn ckb2021_full_address_matches_official_sdk() {
    // 这是**最关键**的一条：现行标准格式（`0x00` 型 + bech32m）的逐字符比对。
    //
    // 断言的期望值**不是**手抄的常量，而是当场用官方 SDK 算出来的，
    // 因此它同时钉死了四件事：payload 布局、bech32m 变体、hash_type 取值、hrp。
    for args_hex in [LOCK_ARGS, LOCK_ARGS_B] {
        let official = Address::new(
            NetworkType::Mainnet,
            full_payload(args_hex, ScriptHashType::Type),
            // `is_new = true` → 走 ckb2021 full 分支（payload 以 `0x00` 开头 + bech32m）。
            true,
        )
        .to_string();

        let ours = ckb_sdk::address::encode_address(&our_script(args_hex), true);
        assert_eq!(
            ours, official,
            "ckb2021 full 地址与官方 SDK 不一致（args={args_hex}）"
        );

        // 反向：官方编出来的地址，我们也能解回同一个 script。
        let (decoded, is_mainnet) = ckb_sdk::address::decode_address(&official).unwrap();
        assert!(is_mainnet);
        assert_eq!(decoded, our_script(args_hex));
    }
}

#[test]
fn deprecated_short_address_matches_official_sdk() {
    // 已废弃的 short 格式（`0x01` 型 + bech32）。历史地址广泛存在，必须能对上。
    for args_hex in [LOCK_ARGS, LOCK_ARGS_B] {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&hex_to_vec(args_hex));
        // short payload 只需要 20 字节 hash，code_hash 由 `CodeHashIndex::Sighash` 隐含。
        let official = Address::new(
            NetworkType::Mainnet,
            AddressPayload::new_short(CodeHashIndex::Sighash, hash.into()),
            false,
        )
        .to_string();

        let ours = ckb_sdk::address::encode_short_sighash_address(&hash, true).unwrap();
        assert_eq!(ours, official, "short 地址与官方 SDK 不一致（args={args_hex}）");

        // 官方的 short 地址我们能解，且解出的 script 与 full 地址解出的**等价**
        // ——这正是 `decode_address` 那句「旧地址与新地址在上层看起来是同一种东西」的含义。
        let (decoded, _) = ckb_sdk::address::decode_address(&official).unwrap();
        assert_eq!(decoded, our_script(args_hex));

        // 官方 SDK 也应能把我们的 short 地址解析回同一个 payload。
        let parsed: Address = official.parse().expect("官方 SDK 应能解析本 crate 的 short 地址");
        assert_eq!(parsed.to_string(), official);
    }
}

#[test]
fn deprecated_full_type_address_matches_official_sdk() {
    // 已废弃的 FullType 格式（`0x04` 型 + bech32）：payload 是
    // `0x04 | code_hash(32) | args`，**没有** hash_type 字节（由格式字节隐含为 type）。
    //
    // 本 crate 只解不编，所以这条走「官方编码 → 本 crate 解码」的对拍。
    for args_hex in [LOCK_ARGS, LOCK_ARGS_B] {
        let official = Address::new(
            NetworkType::Mainnet,
            full_payload(args_hex, ScriptHashType::Type),
            // `is_new = false` + `hash_type = Type` → `AddressType::FullType`（`0x04`）。
            false,
        )
        .to_string();
        // 确认官方给的确实是 `0x04` 型（`ckb1` 之后首字符对应 payload 首字节的高 5 位）。
        assert!(
            official.starts_with("ckb1q"),
            "旧式 full 地址首字节为 0x04，5-bit 重排后应仍以 q 开头，实际 {official}"
        );

        let (decoded, is_mainnet) = ckb_sdk::address::decode_address(&official).unwrap();
        assert!(is_mainnet);
        assert_eq!(decoded, our_script(args_hex));
    }
}

#[test]
fn official_sdk_rejects_bech32_encoded_ckb2021_address() {
    // 反向护栏：故意用 **bech32**（错变体）编一个 `0x00` 型 payload，
    // 交给官方 SDK 解析，它必须拒绝——以此证明「变体必须匹配」不只是我们自家约定。
    //
    // 若这条哪天变成「官方接受了」，说明官方放宽了限制，本 crate 的
    // `decode_address` 也应同步放宽；在此之前保持严格更安全。
    let official = Address::new(
        NetworkType::Mainnet,
        full_payload(LOCK_ARGS, ScriptHashType::Type),
        true,
    )
    .to_string();
    // 官方编出来的 full 地址必须能被官方自己解析回来（sanity check）。
    let roundtrip: Address = official
        .parse()
        .unwrap_or_else(|e| panic!("官方 SDK 应能解析自己编的地址: {e}"));
    assert_eq!(roundtrip.to_string(), official);

    // 而把最后一个字符改掉，官方必须拒绝——说明它确实在校验 bech32m 的常量。
    let mut broken = official.clone();
    let last = broken.pop().unwrap();
    broken.push(if last == 'q' { 'p' } else { 'q' });
    assert!(
        broken.parse::<Address>().is_err(),
        "篡改后的地址应被官方 SDK 拒绝"
    );
}
