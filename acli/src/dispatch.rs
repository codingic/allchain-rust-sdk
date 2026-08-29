//! 统一调度：把「链 + 动作」翻译成某条链适配器上的一次调用，并包装成统一信封。
//!
//! CLI / HTTP / MCP 三种接入形态共用这一层，保证返回结构与错误码完全一致。

use std::time::Instant;

use allchain_core::{ChainClient, ChainKind, Envelope, ErrorCode, SdkError, TransferRequest};
use serde_json::Value;

/// 统一动作集合（只读 + 转账）。
#[derive(Debug, Clone)]
pub enum Action {
    Status,
    Balance {
        address: String,
    },
    Block {
        reference: Option<String>,
    },
    Tx {
        hash: String,
    },
    /// 由公钥派生地址；纯本地计算，不访问 RPC。
    AddressFromPubkey {
        pubkey: String,
    },
    /// 转账；私钥缺省时按链从环境变量读取。
    Transfer {
        to: String,
        amount: String,
        private_key: Option<String>,
        dry_run: bool,
        from: Option<String>,
    },
}

/// 按链标识构造对应适配器。
pub fn build_client(
    chain: ChainKind,
    network: Option<&str>,
    rpc_url: Option<&str>,
) -> Result<Box<dyn ChainClient>, SdkError> {
    Ok(match chain {
        ChainKind::Eth => Box::new(eth_sdk::adapter::EthClient::new(network, rpc_url)?),
        ChainKind::Btc => Box::new(btc_sdk::adapter::BtcClient::new(network, rpc_url)?),
        ChainKind::Sol => Box::new(sol_sdk::adapter::SolClient::new(network, rpc_url)?),
        ChainKind::Near => Box::new(near_sdk::adapter::NearClient::new(network, rpc_url)?),
        ChainKind::Apt => Box::new(apt_sdk::adapter::AptClient::new(network, rpc_url)?),
        ChainKind::Ar => Box::new(ar_sdk::adapter::ArClient::new(network, rpc_url)?),
        ChainKind::Ckb => Box::new(ckb_sdk::adapter::CkbClient::new(network, rpc_url)?),
        ChainKind::Fil => Box::new(fil_sdk::adapter::FilClient::new(network, rpc_url)?),
        ChainKind::Sui => Box::new(sui_sdk::adapter::SuiClient::new(network, rpc_url)?),
        ChainKind::Ton => Box::new(ton_sdk::adapter::TonClient::new(network, rpc_url)?),
    })
}

/// 执行一次统一动作，永远返回信封（不向上抛错）。
pub async fn run_action(
    chain: ChainKind,
    network: Option<&str>,
    rpc_url: Option<&str>,
    action: Action,
) -> Envelope<Value> {
    let started = Instant::now();
    let chain_name = chain.as_str().to_string();
    let fallback_network = network.unwrap_or("default").to_string();

    let client = match build_client(chain, network, rpc_url) {
        Ok(client) => client,
        Err(err) => {
            return Envelope::err(
                chain_name,
                fallback_network,
                started.elapsed().as_millis() as u64,
                err,
            );
        }
    };
    let network_name = client.network().to_string();
    let rpc_url = client.rpc_url().to_string();

    let outcome: Result<Value, SdkError> = match action {
        Action::Status => client
            .status()
            .await
            .and_then(to_value)
            .map(|v| with_rpc(v, &rpc_url)),
        Action::Balance { address } => client
            .balance(&address)
            .await
            .and_then(to_value)
            .map(|v| with_rpc(v, &rpc_url)),
        Action::Block { reference } => client
            .block(reference.as_deref())
            .await
            .and_then(to_value)
            .map(|v| with_rpc(v, &rpc_url)),
        Action::Tx { hash } => client
            .tx(&hash)
            .await
            .and_then(to_value)
            .map(|v| with_rpc(v, &rpc_url)),
        Action::AddressFromPubkey { pubkey } => client
            .address_from_pubkey(&pubkey)
            .await
            .and_then(to_value)
            .map(|v| with_rpc(v, &rpc_url)),
        Action::Transfer {
            to,
            amount,
            private_key,
            dry_run,
            from,
        } => {
            // 写操作只对已实现本地签名的链开放，其余链在协议层明确返回 UNSUPPORTED。
            if !chain.supports_transfer() {
                Err(SdkError::unsupported(format!(
                    "{} 暂未实现本地签名转账（只读查询与地址派生可用）",
                    chain
                )))
            } else {
                match resolve_private_key(chain, private_key.as_deref()) {
                    Ok(key) => client
                        .transfer(TransferRequest {
                            to,
                            amount,
                            private_key: key,
                            dry_run,
                            from,
                        })
                        .await
                        .and_then(to_value)
                        .map(|v| with_rpc(v, &rpc_url)),
                    Err(err) => Err(err),
                }
            }
        }
    };

    let took_ms = started.elapsed().as_millis() as u64;
    match outcome {
        Ok(data) => Envelope::ok(chain_name, network_name, took_ms, data),
        Err(err) => Envelope::err(chain_name, network_name, took_ms, err),
    }
}

fn to_value<T: serde::Serialize>(value: T) -> Result<Value, SdkError> {
    serde_json::to_value(value)
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("结果序列化失败: {e}")))
}

/// 把实际使用的端点补进响应的 `extra`（VPN/代理场景下便于核对打到哪个节点）。
fn with_rpc(mut value: Value, rpc_url: &str) -> Value {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("rpc_url".to_string(), Value::from(rpc_url));
    }
    value
}

/// 解析链标识，统一错误信息。
pub fn parse_chain(raw: &str) -> Result<ChainKind, SdkError> {
    ChainKind::parse(raw).ok_or_else(|| {
        SdkError::invalid_argument(format!(
            "不支持的链: {raw}（可选 eth / btc / sol / near / apt / ar / ckb / fil / sui / ton）"
        ))
    })
}

/// 各链签名私钥的环境变量名（与单链 CLI 一致）。
fn private_key_env(chain: ChainKind) -> &'static str {
    match chain {
        ChainKind::Eth => "ETH_SECRET_KEY",
        ChainKind::Btc => "BTC_WIF",
        ChainKind::Sol => "SOL_KEYPAIR",
        ChainKind::Near => "NEAR_SECRET_KEY",
        // 六条新链暂不支持本地签名转账，不会走到环境变量解析。
        ChainKind::Apt
        | ChainKind::Ar
        | ChainKind::Ckb
        | ChainKind::Fil
        | ChainKind::Sui
        | ChainKind::Ton => "",
    }
}

/// 私钥解析：显式参数优先，否则读对应链的环境变量。
fn resolve_private_key(chain: ChainKind, explicit: Option<&str>) -> Result<String, SdkError> {
    match explicit {
        Some(key) if !key.trim().is_empty() => Ok(key.trim().to_string()),
        _ => {
            let env = private_key_env(chain);
            std::env::var(env).map_err(|_| {
                SdkError::invalid_argument(format!(
                    "缺少私钥：请用 --private-key 传入，或设置环境变量 {env}（{}）",
                    chain
                ))
            })
        }
    }
}

/// 能力清单，供 `/v1/chains` 与 MCP 使用；能力按链真实声明。
pub fn chain_catalog() -> Value {
    let chains: Vec<Value> = ChainKind::ALL
        .iter()
        .map(|c| {
            serde_json::json!({
                "chain": c.as_str(),
                "symbol": c.symbol(),
                "unit": c.unit_name(),
                "decimals": c.decimals(),
                "default_network": c.default_network(),
                "capabilities": c.capabilities(),
                "supports_transfer": c.supports_transfer(),
            })
        })
        .collect();
    serde_json::json!({ "chains": chains, "count": chains.len() })
}
