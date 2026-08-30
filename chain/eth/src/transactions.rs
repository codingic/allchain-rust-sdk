//! 交易构造、本地签名与广播（私钥不出本机）。
//!
//! 两条路径并存，服务于不同场景：
//! 1. `transfer` / `call_contract` / `transfer_silent` —— 用 alloy 的**带钱包 Provider**
//!    自动填充 nonce、gas、chain id 后签名广播，代码短但依赖节点返回的元数据；
//! 2. `build_signed_transfer` / `sign_only` —— **手工组装 `TxEip1559`** 再本地签名，
//!    产出可离线保存的 raw 交易，用于 dry-run、硬件钱包之外的冷签名与人工广播。
//!
//! 无论哪条路径，私钥都只在本地参与 ECDSA 签名运算，从不进入任何请求体。

// `FromStr` 只是为了让 `PrivateKeySigner::from_str` 可用——trait 必须先引入作用域。
use std::str::FromStr;

// `SignableTransaction` 提供 `into_signed(签名)`，把「未签名交易 + 签名」合成信封。
use alloy::consensus::SignableTransaction;
// `Encodable2718` 是 EIP-2718 的编码 trait：它定义了「如何把任意类型的交易
// 序列化成可广播的字节流」，不同类型化交易（Legacy / EIP-2930 / EIP-1559）统一走它。
use alloy::eips::eip2718::Encodable2718;
// `TxSignerSync` 是**同步**签名 trait（与之相对的是异步的 `TxSigner`）。
// 本地私钥签名是纯 CPU 运算，没有 IO，用同步版本即可。
use alloy::network::{ReceiptResponse, TxSignerSync};
use alloy::primitives::{Address, B256, TxKind, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{TransactionInput, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};

use crate::units::{format_wei, parse_gas_limit};

/// 原生转账的默认 gas limit（普通转账固定 21000）。
///
/// 领域说明：21000 是 EVM 协议写死的常量——**任何**不涉及合约执行的转账
/// 都恰好消耗这么多 gas，多一点少一点都不行（少则 OOG，多则白填，虽然会退还）。
pub const TRANSFER_GAS: u64 = 21_000;
/// 合约调用的默认 gas limit。
///
/// 合约执行的 gas 取决于走了哪些分支，静态估不准，所以给一个宽松缺省值，
/// 并允许调用方用 `--gas` 覆盖。未用完的 gas 会自动退还。
pub const CALL_GAS: u64 = 200_000;

/// 解析 `0x...` 或裸十六进制私钥为本地签名器。
///
/// 领域说明：`PrivateKeySigner` 持有 secp256k1 私钥，能派生出地址与签名。
/// 它实现了 `Debug` 但**刻意不打印私钥内容**，避免日志泄漏。
pub fn parse_signer(raw: &str) -> Result<PrivateKeySigner> {
    PrivateKeySigner::from_str(raw.trim())
        .context("解析私钥失败（期望 32 字节十六进制，可带 0x 前缀）")
}

/// 构造带钱包的 Provider：自动填充 nonce / gas / chain id，并用钱包本地签名。
///
/// 语法说明：返回类型 `impl Provider` 是 **`impl Trait` 返回位置**（existential type）：
/// 调用方只知道「它是个实现了 `Provider` 的东西」，不知道也不该知道具体类型——
/// 因为 `ProviderBuilder` 叠出来的真实类型是一长串嵌套泛型，写出来既冗长又易变。
/// 代价是该函数只能返回**同一种**具体类型，不能在不同分支返回不同实现。
fn wallet_provider(rpc_url: &str, signer: PrivateKeySigner) -> Result<impl Provider> {
    let url = crate::network::parse_url(rpc_url)?;
    // 注意：alloy 2.x 的 `ProviderBuilder::new()` 内部已是
    // `default().with_recommended_fillers()`，再次调用反而会因类型不匹配而报错。
    //
    // `.wallet(signer)` 之后，Provider 发出的 `eth_sendTransaction` 会先由
    // filler 层向节点问出 nonce、chain id、gas 价格并填进请求，
    // 再用钱包本地签名——这就是「自动填充」的来源。
    Ok(alloy::providers::ProviderBuilder::new()
        .wallet(signer)
        .connect_http(url))
}

/// 发送交易并等待回执（入块），返回交易哈希。
///
/// 领域说明：广播与入块是**两件事**。`send_transaction` 只把交易推进内存池，
/// 拿到的是「预期哈希」；`get_receipt()` 才会轮询直到交易被打包。
/// 只有回执里的 `status` 才能说明交易是否真的执行成功。
async fn send_and_wait(provider: impl Provider, request: TransactionRequest) -> Result<B256> {
    let pending = provider
        .send_transaction(request)
        .await
        .context("广播交易失败")?;
    // `pending.tx_hash()` 返回 `&B256`（引用），`*` 解引用拿到值本身。
    // `B256` 实现了 `Copy`，所以这步是复制而非移动。
    let tx_hash = *pending.tx_hash();
    println!("tx_hash      : {tx_hash}");
    let receipt = pending
        .get_receipt()
        .await
        .with_context(|| format!("等待交易 {tx_hash} 回执失败（超时或节点异常）"))?;
    println!(
        "status       : {}",
        if receipt.status() {
            "success"
        } else {
            "reverted"
        }
    );
    // `{:?}` 是 `Debug` 格式化。`block_number` 是 `Option<u64>`，
    // 用 Debug 能直接印出 `Some(123)` 而非只印数字，避免与 0 混淆。
    println!("block_number : {:?}", receipt.block_number());
    println!("gas_used     : {}", receipt.gas_used());
    println!(
        "gas_price    : {} gwei",
        format_wei(U256::from(receipt.effective_gas_price()), 9)
    );
    Ok(tx_hash)
}

/// 原生 ETH 转账，返回交易哈希。
pub async fn transfer(
    rpc_url: &str,
    // `signer` 按值接收：它会被 `wallet_provider` 交进 Provider 里长期持有，
    // 因此必须取得所有权，不能只是借用。
    signer: PrivateKeySigner,
    to: Address,
    value: U256,
) -> Result<B256> {
    // `signer.address()` 由私钥本地推导，不发网络请求。
    let from = signer.address();
    println!("from         : {from}");
    println!("to           : {to}");
    println!("value        : {} ETH", format_wei(value, 18));

    let request = TransactionRequest {
        from: Some(from),
        to: Some(TxKind::Call(to)),
        value: Some(value),
        gas: Some(TRANSFER_GAS),
        // 其余字段（nonce / chain_id / 费用）留空，交给 Provider 的 filler 自动填。
        ..Default::default()
    };

    send_and_wait(wallet_provider(rpc_url, signer)?, request).await
}

/// 调用合约（可选附带 value，data 为 ABI 编码后的调用数据），返回交易哈希。
pub async fn call_contract(
    rpc_url: &str,
    signer: PrivateKeySigner,
    to: Address,
    data: Vec<u8>,
    value: U256,
    gas: Option<&str>,
) -> Result<B256> {
    let from = signer.address();
    let gas_limit = parse_gas_limit(gas, CALL_GAS)?;
    println!("from         : {from}");
    println!("to           : {to}");
    println!("value        : {} ETH", format_wei(value, 18));
    println!("input        : 0x{}", alloy::hex::encode(&data));
    println!("gas_limit    : {gas_limit}");

    let request = TransactionRequest {
        from: Some(from),
        to: Some(TxKind::Call(to)),
        input: TransactionInput::from(data.clone()),
        value: Some(value),
        gas: Some(gas_limit),
        ..Default::default()
    };

    send_and_wait(wallet_provider(rpc_url, signer)?, request).await
}

/// 广播一笔原生转账并等待回执（不打印），供统一接口复用。
///
/// 返回 `(交易哈希, 是否成功, 区块号, gas_used)`。
///
/// 语法说明：返回**元组**而非结构体，是因为这四项只在本 crate 内部
/// 短距离传递一次（adapter 立刻拆包塞进 `TransferView` 的 extra），
/// 为此单建一个结构体属于过度设计。
pub async fn transfer_silent(
    rpc_url: &str,
    signer: PrivateKeySigner,
    to: Address,
    value: U256,
) -> Result<(B256, bool, Option<u64>, u64)> {
    let request = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(to)),
        value: Some(value),
        gas: Some(TRANSFER_GAS),
        ..Default::default()
    };

    let pending = wallet_provider(rpc_url, signer)?
        .send_transaction(request)
        .await
        .context("广播交易失败")?;
    let tx_hash = *pending.tx_hash();
    let receipt = pending
        .get_receipt()
        .await
        .with_context(|| format!("等待交易 {tx_hash} 回执失败"))?;
    Ok((
        tx_hash,
        receipt.status(),
        receipt.block_number(),
        receipt.gas_used(),
    ))
}

/// 离线构造并签名一笔 EIP-1559 原生转账（不广播），返回哈希与已签名 raw 编码。
///
/// 领域说明：各字段含义
/// - `max_fee_per_gas`          ：**单价上限**（含 base fee），超出就宁愿不打包；
/// - `max_priority_fee_per_gas` ：给矿工/验证者的小费，决定打包优先级；
/// - `tx_hash`                  ：已签名交易的 Keccak 哈希，广播成功后的 txid 与它一致。
pub struct SignedTransfer {
    /// 交易哈希。因为签名是确定性的，本地签完就能算出上链后的 txid。
    pub tx_hash: B256,
    /// 可直接 `eth_sendRawTransaction` 的十六进制编码（带 0x 前缀）。
    pub signed_raw: String,
    /// 链 ID，用于 EIP-155 重放保护（主网 1、Sepolia 11155111）。
    pub chain_id: u64,
    /// 发送方交易序号，同一 nonce 只能成功一笔。
    pub nonce: u64,
    /// 费用上限（wei）。
    pub max_fee_per_gas: u128,
    /// 优先费（wei）。
    pub max_priority_fee_per_gas: u128,
}

/// 本地签名（私钥不经过网络）并序列化为 raw 编码，供 dry-run 与人工广播使用。
///
/// 与 `transfer` 的关键差别：这里**手工**取齐 chain id、nonce、费率三项，
/// 再组装 `TxEip1559`。之所以不复用 Provider 的自动填充，是因为 dry-run
/// 要求"结果可被完整审计且可离线重放"，每一步的中间值都得显式拿到手。
pub async fn build_signed_transfer(
    rpc_url: &str,
    // `&PrivateKeySigner` 借用：本函数不长期持有签名器，签完就归还，
    // 于是调用方（`sign_only`）之后还能继续用同一个 signer 打印地址。
    signer: &PrivateKeySigner,
    to: Address,
    value: U256,
) -> Result<SignedTransfer> {
    // 只用一个**只读** Provider 取这三项链上/节点元数据，私钥压根不在其中。
    let client = crate::network::connect(rpc_url)?;
    let chain_id = client.get_chain_id().await.context("查询链 ID 失败")?;
    // `get_transaction_count` 默认取「已确认的下一 nonce」，
    // 即 pending 池里的交易不计入——连续快速发两笔会撞 nonce。
    let nonce = client
        .get_transaction_count(signer.address())
        .await
        .context("查询 nonce 失败")?;
    // `estimate_eip1559_fees` 由节点按最近的 base fee 历史给出建议值。
    let fees = client
        .estimate_eip1559_fees()
        .await
        .context("估算 gas 费用失败")?;

    // `mut` 是必需的：`sign_transaction_sync` 需要 `&mut`，因为它要在
    // 签名过程中读取并就地处理交易结构。
    let mut tx = alloy::consensus::TxEip1559 {
        chain_id,
        nonce,
        gas_limit: TRANSFER_GAS,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        to: TxKind::Call(to),
        value,
        // 普通转账没有调用数据，用 `Default` 得到空 input。
        input: Default::default(),
        // EIP-2930 的访问列表，普通转账用不到，留空。
        access_list: Default::default(),
    };

    let signature = signer
        .sign_transaction_sync(&mut tx)
        .context("本地签名失败")?;
    // `into_signed` 把「交易体 + 签名」合成为 `Signed<Tx>`，此后它的哈希才是 txid。
    let envelope = tx.into_signed(signature);
    let tx_hash = *envelope.hash();
    // `encoded_2718()` 产出 EIP-2718 编码字节：`0x02 || RLP(交易字段与签名)`。
    let signed_raw = format!("0x{}", alloy::hex::encode(envelope.encoded_2718()));

    Ok(SignedTransfer {
        tx_hash,
        signed_raw,
        chain_id,
        nonce,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
    })
}

/// 离线导出已签名交易（不广播）：用于硬件钱包之外的人工广播场景。
///
/// 典型用法：在离线机器上跑出 `signed_raw`，拿到联网机器上用
/// `eth_sendRawTransaction` 广播，私钥全程不接触网络。
pub async fn sign_only(
    rpc_url: &str,
    signer: PrivateKeySigner,
    to: Address,
    value: U256,
) -> Result<()> {
    // 传 `&signer` 借用，所以下面还能继续用 `signer.address()`。
    let signed = build_signed_transfer(rpc_url, &signer, to, value).await?;

    println!("from             : {}", signer.address());
    println!("to               : {to}");
    println!("chain_id         : {}", signed.chain_id);
    println!("nonce            : {}", signed.nonce);
    println!(
        "max_fee          : {} gwei",
        format_wei(U256::from(signed.max_fee_per_gas), 9)
    );
    println!(
        "priority_fee     : {} gwei",
        format_wei(U256::from(signed.max_priority_fee_per_gas), 9)
    );
    // 格式串里直接内联常量 `TRANSFER_GAS`：这是 Rust 的**隐式命名参数捕获**，
    // 花括号里写变量名即可，等价于 `format!(".. {}", TRANSFER_GAS)`。
    println!("gas_limit        : {TRANSFER_GAS}");
    println!("tx_hash          : {}", signed.tx_hash);
    println!("signed_raw       : {}", signed.signed_raw);
    Ok(())
}
