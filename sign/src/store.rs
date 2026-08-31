//! 进程内密钥库：仅持有「地址 -> 种子」的映射，绝不落盘。
//!
//! 设计要点：
//! - 私钥原材料只存 32 字节种子（secp256k1 标量 / ed25519 种子），签名时再按链重建具体签名器；
//!   这样存储层与任何链的具体密钥类型解耦，也不需要把各链的 SecretKey 类型塞进同一个 HashMap。
//! - 用 `Arc<Mutex<..>>` 包一层，便于通过 axum 的 `State` 在 handler 间共享，且 `KeyStore` 本身可 Clone。
//! - 进程退出即清空，符合「离线签名、不持久化」的安全预期。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// 签名算法族。决定种子如何被解释、如何派生地址、如何签名。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// ETH：secp256k1 可恢复签名。
    Secp256k1,
    /// SOL / NEAR / APT / SUI / TON：ed25519。
    Ed25519,
}

/// 密钥库中的一条记录：算法族 + 32 字节种子。
///
/// 种子本身是敏感数据；本结构只在进程内传递，不会被序列化进任何响应。
#[derive(Clone, Copy, Debug)]
pub struct StoredKey {
    pub scheme: Scheme,
    pub seed: [u8; 32],
}

/// 进程内密钥库。
#[derive(Clone)]
pub struct KeyStore {
    map: Arc<Mutex<HashMap<String, StoredKey>>>,
}

#[allow(dead_code)]
impl KeyStore {
    /// 新建空库。
    pub fn new() -> Self {
        KeyStore {
            map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 以地址为键存入一条密钥。覆盖同地址旧值（同一地址重新生成即替换）。
    pub fn insert(&self, address: &str, key: StoredKey) {
        self.map.lock().unwrap().insert(address.to_string(), key);
    }

    /// 按地址取出密钥；不在内存中返回 `None`（调用方需先 `getprikey` 生成，或传入已知地址）。
    pub fn get(&self, address: &str) -> Option<StoredKey> {
        self.map.lock().unwrap().get(address).copied()
    }

    /// 当前内存中密钥条数（用于状态/调试端点）。
    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.map.lock().unwrap().is_empty()
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}
