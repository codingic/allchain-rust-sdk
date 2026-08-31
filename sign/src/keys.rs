//! 离线密钥生成与地址派生。
//!
//! `generate(chaintype)` 为指定链随机生成密钥对，派生该链原生地址，
//! 返回可供 `getprikey` 端点输出的 [`KeyInfo`]，并把 `{scheme, seed}` 交给调用方存入 [`KeyStore`]。
//!
//! 支持的链（与 `signtx` 一致）：eth / sol / near / apt / sui / ton。
//! - eth：secp256k1（k256）
//! - 其余五链：ed25519（ed25519-dalek）
//!
//! 地址派生规则：
//! - eth ：keccak256(非压缩公钥[1:])[12:]  →  `0x…`
//! - sol ：ed25519 公钥 → base58（即 Solana 地址）
//! - near：ed25519 公钥 → `ed25519:<base58>`（NEAR 隐式账户地址表示）
//! - apt ：sha3-256(公钥 ‖ 0x00)[0:32]      →  `0x…`
//! - sui ：blake2b-256(公钥)[0:32]          →  `0x…`
//! - ton ：原始 ed25519 公钥十六进制。TON 真实地址由钱包合约 code+state-init 决定，
//!          通用离线签名器无法仅凭公钥算出，故返回公钥本身供上层对照。

use crate::store::{Scheme, StoredKey};
use rand::rngs::OsRng;

/// 一次密钥生成的完整结果（不含敏感种子的「公开视图」其实也含私钥——本端点就是发私钥的）。
///
/// 注意：`private_key` 始终是 32 字节种子的 `0x` 十六进制，统一格式；
/// `public_key` 对各链给出最自然的展示（hex / base58），`address` 是该链原生地址字符串。
pub struct KeyInfo {
    pub chain: String,
    pub scheme: Scheme,
    /// 原生地址（getprikey 之后作为 signtx 的 fromaddress 使用）。
    pub address: String,
    /// `0x` + 32 字节种子十六进制。
    pub private_key: String,
    /// 公钥（hex 或 base58，随链）。
    pub public_key: String,
    /// 32 字节种子，交给密钥库存放。
    pub seed: [u8; 32],
}

/// 该链是否被本签名器支持（用于尽早返回 Unsupported，而非在签名时才报错）。
pub fn is_supported(chain: &str) -> bool {
    matches!(chain, "eth" | "sol" | "near" | "apt" | "sui" | "ton")
}

/// 为指定链生成密钥对并派生地址。
pub fn generate(chain: &str) -> anyhow::Result<KeyInfo> {
    match chain {
        "eth" => gen_secp256k1(chain),
        "sol" | "near" | "apt" | "sui" | "ton" => gen_ed25519(chain),
        other => Err(anyhow::anyhow!("不支持的链: {other}（可选 eth / sol / near / apt / sui / ton）")),
    }
}

/// ETH：secp256k1 密钥对 + keccak256 地址派生。
fn gen_secp256k1(chain: &str) -> anyhow::Result<KeyInfo> {
    use k256::ecdsa::{SigningKey, VerifyingKey};

    let sk = SigningKey::random(&mut OsRng);
    let vk = VerifyingKey::from(&sk);
    // 非压缩公钥：0x04 ‖ X(32) ‖ Y(32)，共 65 字节。
    let pub_bytes = vk.to_encoded_point(false).as_bytes().to_vec();

    // ETH 地址 = keccak256(公钥[1:])[12:]，合金库直接提供 keccak256。
    let hash = alloy::primitives::keccak256(&pub_bytes[1..]);
    let address = format!("0x{}", hex::encode(&hash[12..]));

    let seed: [u8; 32] = sk.to_bytes().into();
    Ok(KeyInfo {
        chain: chain.to_string(),
        scheme: Scheme::Secp256k1,
        address,
        private_key: format!("0x{}", hex::encode(seed)),
        public_key: format!("0x{}", hex::encode(pub_bytes)),
        seed,
    })
}

/// SOL / NEAR / APT / SUI / TON：ed25519 密钥对 + 各自地址派生。
fn gen_ed25519(chain: &str) -> anyhow::Result<KeyInfo> {
    use ed25519_dalek::{SigningKey, VerifyingKey};

    let sk = SigningKey::generate(&mut OsRng);
    let vk = VerifyingKey::from(&sk);
    let pub_bytes = vk.to_bytes(); // 32 字节 ed25519 公钥

    let address = match chain {
        "sol" => {
            // Solana 地址即 ed25519 公钥的 base58。
            solana_pubkey::Pubkey::from(pub_bytes).to_string()
        }
        "near" => {
            // NEAR 隐式账户地址 = `ed25519:<base58(公钥)>`。
            let pk = near_crypto::PublicKey::ED25519(
                near_crypto::ED25519PublicKey::try_from(pub_bytes.as_slice())
                    .map_err(|e| anyhow::anyhow!("NEAR 公钥构造失败: {e}"))?,
            );
            pk.to_string()
        }
        "apt" => {
            // Aptos 地址 = sha3-256(公钥 ‖ 0x00)[0:32]。
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(pub_bytes);
            h.update([0x00u8]);
            let out = h.finalize();
            format!("0x{}", hex::encode(&out[..32]))
        }
        "sui" => {
            // Sui 地址 = blake2b-256(方案标志 0x00 ‖ 公钥)[0:32]。
            use blake2::digest::{Update, VariableOutput};
            use blake2::Blake2bVar;
            let mut h = Blake2bVar::new(32)
                .map_err(|e| anyhow::anyhow!("SUI 哈希初始化失败: {e}"))?;
            h.update(&[0x00u8]);
            h.update(&pub_bytes);
            let mut out = [0u8; 32];
            h.finalize_variable(&mut out)
                .map_err(|e| anyhow::anyhow!("SUI 地址派生失败: {e}"))?;
            format!("0x{}", hex::encode(out))
        }
        "ton" => {
            // TON 真实地址需钱包合约；此处返回原始公钥十六进制供上层对照。
            format!("0x{}", hex::encode(pub_bytes))
        }
        _ => unreachable!(),
    };

    // 公钥展示：SOL 用 base58，其余用 hex。
    let public_key = match chain {
        "sol" => solana_pubkey::Pubkey::from(pub_bytes).to_string(),
        _ => format!("0x{}", hex::encode(pub_bytes)),
    };

    let seed: [u8; 32] = sk.to_bytes();
    Ok(KeyInfo {
        chain: chain.to_string(),
        scheme: Scheme::Ed25519,
        address,
        private_key: format!("0x{}", hex::encode(seed)),
        public_key,
        seed,
    })
}

/// 把 [`KeyInfo`] 转成可存入 [`KeyStore`] 的记录。
pub fn to_stored(key: &KeyInfo) -> StoredKey {
    StoredKey {
        scheme: key.scheme,
        seed: key.seed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::KeyStore;
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

    /// 受支持的 6 条链。
    const CHAINS: &[&str] = &["eth", "sol", "near", "apt", "sui", "ton"];
    /// getprikey 明确延后的链（应返回 false）。
    const DEFERRED: &[&str] = &["btc", "ckb", "fil", "ar", "xxx"];

    #[test]
    fn is_supported_matrix() {
        for c in CHAINS {
            assert!(is_supported(c), "期望支持 {c}");
        }
        for c in DEFERRED {
            assert!(!is_supported(c), "期望延后 {c}");
        }
    }

    #[test]
    fn generate_rejects_unsupported() {
        let r = generate("btc");
        assert!(r.is_err(), "btc 应被拒");
        assert!(generate("not-a-chain").is_err());
    }

    #[test]
    fn generate_store_roundtrip_all_chains() {
        let store = KeyStore::new();
        for chain in CHAINS {
            let ki = generate(chain).expect("generate 应成功");
            // 种子必须是 32 字节。
            assert_eq!(ki.seed.len(), 32, "{chain}: 种子长度应为 32");
            // private_key 必须是 0x+64hex。
            assert!(ki.private_key.starts_with("0x"));
            assert_eq!(ki.private_key.len(), 66, "{chain}: private_key 长度应为 0x+64hex");
            // 地址不得为空。
            assert!(!ki.address.is_empty(), "{chain}: 地址不得为空");

            // 存入 → 取出，种子与算法族必须完全一致。
            let stored = to_stored(&ki);
            store.insert(&ki.address, stored);
            let got = store.get(&ki.address).expect("应能从密钥库取回");
            assert_eq!(got.seed, ki.seed, "{chain}: 取回的种子不一致");
            assert_eq!(got.scheme, ki.scheme, "{chain}: 取回的算法族不一致");
        }
        assert_eq!(store.len(), CHAINS.len());
    }

    #[test]
    fn two_generations_differ() {
        // 极高概率：两次随机生成的种子不同（验证熵来源正常）。
        let a = generate("eth").unwrap();
        let b = generate("eth").unwrap();
        assert_ne!(a.seed, b.seed, "两次 eth 生成不应完全相同");
        assert_ne!(a.address, b.address);
    }

    #[test]
    fn eth_address_format() {
        let ki = generate("eth").unwrap();
        // ETH 地址 = 0x + 40 hex；全小写（keccak256 派生）。
        assert!(ki.address.starts_with("0x"));
        assert_eq!(ki.address.len(), 42);
        assert!(ki.address[2..].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(ki.address[2..].chars().all(|c| !c.is_ascii_uppercase()));
        assert_eq!(ki.scheme, Scheme::Secp256k1);
    }

    #[test]
    fn ed25519_seed_keypair_is_real_and_verifiable() {
        // 对每条 ed25519 链，用种子重建 dalek 密钥对，独立做一次 sign/verify，
        // 证明 generate() 产出的种子是可用 ed25519 种子（而非随机噪声 / 字节错位）。
        for chain in ["sol", "near", "apt", "sui", "ton"] {
            let ki = generate(chain).unwrap();
            assert_eq!(ki.scheme, Scheme::Ed25519);

            let sk = SigningKey::from_bytes(&ki.seed);
            let vk = VerifyingKey::from(&sk);
            let msg = b"allchain-offline-signer-self-check";
            let sig = sk.sign(msg);
            assert!(vk.verify(msg, &sig).is_ok(), "{chain}: 种子重建的密钥对签名验签失败");

            // 公钥展示应与种子重建的公钥一致（hex 形式的链直接比对字节）。
            if chain != "sol" {
                let pk_hex = ki.public_key.trim_start_matches("0x");
                let pk_bytes = hex::decode(pk_hex).expect("public_key 应为 hex");
                assert_eq!(pk_bytes, vk.to_bytes().to_vec(), "{chain}: public_key 与种子公钥不一致");
            }
        }
    }

    #[test]
    fn scheme_assignment() {
        assert_eq!(generate("eth").unwrap().scheme, Scheme::Secp256k1);
        for chain in ["sol", "near", "apt", "sui", "ton"] {
            assert_eq!(generate(chain).unwrap().scheme, Scheme::Ed25519);
        }
    }
}

