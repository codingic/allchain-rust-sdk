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

// `SignableTransaction` 提供 `into_signed(签名)`（把「未签名交易 + 签名」合成信封）
// 以及 `encode_for_signing` / `signature_hash` 两项——**待签原像**与**待签摘要**都由它给出，
// 无私钥构造路径正是靠这两个方法精确复刻签名器的输入。
use alloy::consensus::{SignableTransaction, TxEip1559};
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

/// 组装一笔 EIP-1559 转账所需的**链上元数据**。
///
/// 领域说明：nonce 与费率必须由节点提供，不能本地猜——
/// nonce 猜错会让交易永久卡在池里（或被引擎直接拒），
/// 费率猜低了则永远等不到打包。chain id 参与 EIP-155 重放保护，
/// 写错会把主网交易签名成测试网交易（反之亦然）。
///
/// 之所以把它单独立成一个结构体，是因为**两条路径都要它**：
/// `build_signed_transfer`（本地签名）与 `build_unsigned_transfer`（无私钥构造）
/// 取的是同一组值，抽出来才能避免两处逻辑漂移。
struct TransferMeta {
    /// 链 ID，用于 EIP-155 重放保护。
    chain_id: u64,
    /// 发送方的下一可用交易序号。
    nonce: u64,
    /// 费用上限（wei）。
    max_fee_per_gas: u128,
    /// 优先费（wei）。
    max_priority_fee_per_gas: u128,
}

/// 向节点取齐构造转账所需的三项元数据。
///
/// 只用一个**只读** Provider：这一步完全不涉及私钥，
/// 因此无私钥构造路径可以安全复用它。
async fn fetch_transfer_meta(rpc_url: &str, from: Address) -> Result<TransferMeta> {
    let client = crate::network::connect(rpc_url)?;
    let chain_id = client.get_chain_id().await.context("查询链 ID 失败")?;
    // `get_transaction_count` 默认取「已确认的下一 nonce」，
    // 即 pending 池里的交易不计入——连续快速发两笔会撞 nonce。
    let nonce = client
        .get_transaction_count(from)
        .await
        .context("查询 nonce 失败")?;
    // `estimate_eip1559_fees` 由节点按最近的 base fee 历史给出建议值。
    let fees = client
        .estimate_eip1559_fees()
        .await
        .context("估算 gas 费用失败")?;

    Ok(TransferMeta {
        chain_id,
        nonce,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
    })
}

/// 用元数据 + 收款方 + 金额组装出**未签名**的 `TxEip1559`。
///
/// 领域说明：原生固定 21000 gas（见 [`TRANSFER_GAS`]），没有调用数据、
/// 没有访问列表——这三项都写死，构造结果与链上惯例一致，也便于审计。
fn unsigned_eip1559(meta: &TransferMeta, to: Address, value: U256) -> TxEip1559 {
    TxEip1559 {
        chain_id: meta.chain_id,
        nonce: meta.nonce,
        gas_limit: TRANSFER_GAS,
        max_fee_per_gas: meta.max_fee_per_gas,
        max_priority_fee_per_gas: meta.max_priority_fee_per_gas,
        to: TxKind::Call(to),
        value,
        // 普通转账没有调用数据，用 `Default` 得到空 input。
        input: Default::default(),
        // EIP-2930 的访问列表，普通转账用不到，留空。
        access_list: Default::default(),
    }
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
    let meta = fetch_transfer_meta(rpc_url, signer.address()).await?;
    // `mut` 是必需的：`sign_transaction_sync` 需要 `&mut`，因为它要在
    // 签名过程中读取并就地处理交易结构。
    let mut tx = unsigned_eip1559(&meta, to, value);

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
        chain_id: meta.chain_id,
        nonce: meta.nonce,
        max_fee_per_gas: meta.max_fee_per_gas,
        max_priority_fee_per_gas: meta.max_priority_fee_per_gas,
    })
}

/// 无私钥构造出的一笔 EIP-1559 转账：**待签原像 + 待签摘要 + 全部字段**。
///
/// 领域说明（为什么必须同时给出两个字节串）：
/// 以太坊要签的不是最终交易字节，而是 `keccak256(0x02 || RLP(9 个未签名字段))`。
/// 于是「签什么」与「最终广播什么」是两回事：
/// - `unsigned_tx_hex`     ：`0x02 || RLP(未签名字段)`，是摘要的**原像**，
///   也是签名方重组最终交易时需要的基底（签名后要把它与 r/s/y_parity 一起
///   重新 RLP 编码成 12 个字段的信封）；
/// - `signing_hash`        ：上面那串字节的 keccak256，**ECDSA 真正作用其上的 32 字节**。
///
/// 若只给其中一个，调用方要么得自己再算一次 keccak（有算错的风险），
/// 要么拿不到重组成广播格式所需的字段列表。两个都给，才能既审计又闭环。
pub struct UnsignedTransfer {
    /// 可直接喂给离线签名器的未签名编码（`0x02 || RLP(...)`，带 0x 前缀）。
    ///
    /// 与 `../sign` 程序的 `signtx(chaintype="eth", txdatahex=..)` 输入格式**完全一致**：
    /// 那边用 `TypedTransaction::decode_unsigned` 解它，两者互为逆运算。
    pub unsigned_tx_hex: String,
    /// 待签摘要：`keccak256(unsigned_tx_hex 的字节)`。ECDSA 签的是它。
    pub signing_hash: B256,
    /// 链 ID，用于 EIP-155 重放保护（主网 1、Sepolia 11155111）。
    pub chain_id: u64,
    /// 发送方交易序号，同一 nonce 只能成功一笔。
    pub nonce: u64,
    /// 费用上限（wei）。
    pub max_fee_per_gas: u128,
    /// 优先费（wei）。
    pub max_priority_fee_per_gas: u128,
}

/// 由元数据组装出待签交易。**纯函数，不访问网络**。
///
/// 之所以要把「取元数据」与「组装」拆成两半：后者是唯一真正有业务风险的一步
/// （字段顺序、类型标志、摘要口径全在这里），拆出来后单测就能**直接打在它身上**，
/// 不必为了测它去连公共 RPC——那样只会把网络抖动变成假失败。
/// 这里的划分不是为了好看，而是为了让「最关键的代码」同时是「可测的代码」。
fn assemble_unsigned(meta: TransferMeta, to: Address, value: U256) -> UnsignedTransfer {
    let tx = unsigned_eip1559(&meta, to, value);

    // `Vec::with_capacity` 预分配到精确长度，避免 RLP 写入过程中的多次扩容。
    // `payload_len_for_signature()` 由 `SignableTransaction` 提供，
    // 正是 `encode_for_signing` 将要写出的字节数（字段 RLP 长度 + 1 字节类型前缀）。
    let mut buf = Vec::with_capacity(tx.payload_len_for_signature());
    // `encode_for_signing` 写入 `0x02 || RLP(chain_id, nonce, max_priority_fee,
    // max_fee, gas_limit, to, value, input, access_list)`——注意**优先费排在费用上限之前**，
    // 这个顺序是 EIP-1559 规定的，手写 RLP 时极易弄反。
    tx.encode_for_signing(&mut buf);

    // `signature_hash()` 的默认实现就是 `keccak256(encode_for_signing(...))`，
    // 直接调用它而不是自己再算一遍，是为了与 alloy 签名器内部**逐字节对齐**——
    // 这一层若出现任何偏差，签名会被网络拒绝，且本地自往返永远测不出来。
    let signing_hash = tx.signature_hash();

    UnsignedTransfer {
        unsigned_tx_hex: format!("0x{}", alloy::hex::encode(&buf)),
        signing_hash,
        chain_id: meta.chain_id,
        nonce: meta.nonce,
        max_fee_per_gas: meta.max_fee_per_gas,
        max_priority_fee_per_gas: meta.max_priority_fee_per_gas,
    }
}

/// **无私钥**构造一笔 EIP-1559 转账：只取链上元数据并组装，不签名、不广播。
///
/// 与 `build_signed_transfer` 的分工：后者在组装完后立刻本地签名，
/// 本函数则在组装完就**停在这里**，把待签原像与待签摘要交出去，
/// 由调用方（agent）拿着自己的私钥去签——私钥全程不进入本进程。
///
/// 领域说明：`from` 地址在这里只用于**查 nonce**，不做任何权限校验。
/// 无私钥就无法证明调用方拥有该地址，这是「无私钥构造」这一形态的固有性质：
/// 谁都能为任意地址构造一笔待签交易，但**没有对应私钥就签不出能被网络接受的签名**。
/// 因此安全性由签名环节保障，而非构造环节。
pub async fn build_unsigned_transfer(
    rpc_url: &str,
    from: Address,
    to: Address,
    value: U256,
) -> Result<UnsignedTransfer> {
    let meta = fetch_transfer_meta(rpc_url, from).await?;
    Ok(assemble_unsigned(meta, to, value))
}

/// 广播**已签名**的交易字节，返回交易哈希。
///
/// 与 `transfer` / `transfer_silent` 的区别：本函数只做 `eth_sendRawTransaction`，
/// 不构造、不签名、也不等回执——它假定输入已经是完整可广播的编码。
///
/// 领域说明：广播成功**不等于**执行成功。交易可能入块后 revert，
/// 也可能因费率过低长期滞留内存池。要确认结果请用 `tx()` 查回执。
/// 这里刻意不等待：等待时长与链出块节奏强相关（ETH 约 12 秒，
/// 而其它链从 0.4 秒到数分钟不等），统一等待会让跨链语义难以对齐。
pub async fn broadcast_raw(rpc_url: &str, raw: &[u8]) -> Result<B256> {
    let client = crate::network::connect(rpc_url)?;
    // `send_raw_transaction` 只把交易推进内存池，返回值里的哈希是
    // **节点算出的** txid——与本地 `keccak256(签名后字节)` 应完全一致，
    // 但以节点返回为准，能顺带验证签名结构合法（畸形交易会在这一步被拒）。
    let pending = client
        .send_raw_transaction(raw)
        .await
        .context("广播已签名交易失败")?;
    // `tx_hash()` 返回 `&B256`，`*` 解引用取值（`B256` 实现 `Copy`）。
    Ok(*pending.tx_hash())
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

/// 单元测试：只覆盖**纯本地、无网络**的部分。
///
/// 需要联网的元数据获取（nonce / 费率）不在此测试范围内，
/// 因为公共端点不稳定，写进单测会把网络抖动变成假失败。
/// 为此 `assemble_unsigned` 才被拆成一个独立纯函数——它承载了全部业务逻辑，
/// 于是「最需要测的那部分」恰好「不需要网络就能测」。
///
/// 一条贯穿全部用例的纪律：**断言只基于函数真正交出去的字符串**
/// （`unsigned_tx_hex` / `signing_hash`），不在测试里重算 RLP。
/// 若测试自己再算一遍同样的公式，实现改坏时它会跟着一起坏，
/// 于是「红不红」取决于测试写没写对，而不是实现写没写对——那样的测试是恒真的。
#[cfg(test)]
mod tests {
    use super::*;
    use alloy::consensus::TypedTransaction;
    use alloy::primitives::{address, keccak256};

    /// 一个固定的收款地址（任意有效地址即可，测试不广播）。
    const TO: Address = address!("0x0000000000000000000000000000000000000001");

    /// 走一遍**生产路径** `assemble_unsigned`，用固定元数据绕开网络。
    fn fixed_unsigned() -> UnsignedTransfer {
        assemble_unsigned(
            TransferMeta {
                chain_id: 1,
                nonce: 7,
                max_fee_per_gas: 30_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
            },
            TO,
            U256::from(1_000_000_000_000_000u128),
        )
    }

    /// 把 `unsigned_tx_hex` 解回字节（剥掉 `0x` 前缀）。
    fn unsigned_bytes(u: &UnsignedTransfer) -> Vec<u8> {
        alloy::hex::decode(u.unsigned_tx_hex.trim_start_matches("0x"))
            .expect("unsigned_tx_hex 必须是合法十六进制")
    }

    /// **对拍**：与一份完全独立的 Python 实现逐字节比对。
    ///
    /// 期望值的来源（刻意不取自被测代码，否则测试是恒真的）：
    /// 用「手写的 RLP 编码器 + pycryptodome 的 Keccak」在 Python 里独立算了一遍，
    /// 输入与 `fixed_unsigned()` 完全一致。
    ///
    /// 为什么必须跨实现比对：其余几条测试验证的都是「输出与我们的公式自洽」，
    /// 而公式本身写错时它们会一起错——字段顺序写反、漏掉类型标志字节，
    /// 都仍然满足「摘要 == keccak(原像)」。只有外部真值能钉住这一类错误。
    ///
    /// 这条测试一旦变红，含义是**我们的序列化与以太坊规范不一致**，
    /// 交易会被网络以 invalid signature 拒绝，应当作 P0 处理。
    #[test]
    fn matches_independently_computed_signing_hash() {
        // 48 字节 = 1 字节类型标志 + 1 字节列表头（0xef = 0xc0 + 47）+ 47 字节字段。
        const EXPECT_UNSIGNED: &str =
            "0x02ef0107843b9aca008506fc23ac0082520894000000000000000000000000000000000000000187038d7ea4c6800080c0";
        const EXPECT_SIGHASH: &str =
            "0x23d5b8277a00704a1bd4a953e3a1f984754e0c6a02338dd7c339bbc41e844bed";

        let u = fixed_unsigned();
        assert_eq!(u.unsigned_tx_hex, EXPECT_UNSIGNED);
        assert_eq!(
            format!("0x{}", alloy::hex::encode(u.signing_hash.as_slice())),
            EXPECT_SIGHASH
        );
    }

    /// 待签摘要必须等于待签原像的 keccak256。
    ///
    /// 这条测试锁死的是 `BuildTransferView` 里两个字段的**语义契约**：
    /// 调用方可以完全不信任我们的说明，自己拿 `unsigned_tx_hex` 算一遍哈希，
    /// 结果必须与 `signing_payload_hex` 一致。这正是「可审计」的含义。
    #[test]
    fn signing_hash_is_keccak_of_encoded_for_signing() {
        let u = fixed_unsigned();
        let bytes = unsigned_bytes(&u);

        assert_eq!(u.signing_hash, keccak256(&bytes));
        // 类型化交易的第一个字节必须是 EIP-2718 的类型标志，EIP-1559 为 0x02。
        assert_eq!(bytes[0], 0x02);
    }

    /// 待签原像必须能被 `TypedTransaction::decode_unsigned` **原样**解回。
    ///
    /// 这是**跨进程契约**的核心：`../sign` 程序的 `signtx(chaintype="eth")`
    /// 正是用 `decode_unsigned` 解析我们交出去的字节串。若任一侧的字段顺序
    /// 或类型标志有出入，这里会立刻变红——而这类错误在链上的表现是
    /// 「签名无效 / 交易被拒」，排查成本极高。
    #[test]
    fn encoded_for_signing_round_trips_through_typed_transaction() {
        let u = fixed_unsigned();
        let bytes = unsigned_bytes(&u);

        let mut slice: &[u8] = &bytes;
        let decoded = TypedTransaction::decode_unsigned(&mut slice)
            .expect("未签名编码必须能被 TypedTransaction 解析");
        // 输入必须被**完整**消费，否则说明还有尾巴没解析（长度字段写错）。
        assert!(slice.is_empty(), "解码后仍有 {slice:?} 剩余字节未被消费");

        // 解出来的交易重新编码，必须与原始字节逐字节相同。
        let mut re_encoded = Vec::new();
        decoded.encode_for_signing(&mut re_encoded);
        assert_eq!(re_encoded, bytes);
    }

    /// 端到端闭环：交出去的字节 → 外部解码与签名 → 重组 → 官方解码器解析通过。
    ///
    /// 这条测试走的是**离线签名程序的视角**，复刻 `../sign` 里 `signtx` 的动作：
    /// 只拿到 `unsigned_tx_hex` 与 `signing_payload_hex`，解码、签名、重组，
    /// 最后产出的字节必须能被 `TxEnvelope` 完整解析。
    ///
    /// 它验证的是**格式闭环**，不是摘要正确性——诚实地说，
    /// 「对某个哈希签名、再从同一个哈希恢复」对任意 32 字节都成立，
    /// 因此抓不到摘要算错。摘要的正确性由上面那条**跨实现对拍**负责。
    /// 这里之所以仍然保留恢复断言，是为了确认签名三元组能被正确装配：
    /// 若类型标志或字段列表与签名结构不匹配，解码会在最后一步失败。
    ///
    /// 领域说明：这类「看着像验证、其实恒真」的测试最危险，
    /// 它给人虚假的安全感。写测试时必须问一句：
    /// 「我把实现改坏，这条会红吗？」——答不上来就该换判据。
    #[test]
    fn signed_payload_recovers_to_the_payer() {
        use alloy::consensus::TxEnvelope;
        use alloy::rlp::Decodable;
        use alloy::signers::local::PrivateKeySigner;
        // `SignerSync` 提供 `sign_hash_sync`：对**裸 32 字节摘要**做可恢复签名。
        // 与 `TxSignerSync::sign_transaction_sync` 的区别是后者内部会自己去算
        // `signature_hash()`；而这里我们要模拟「外部签名方只拿到摘要」的情形，
        // 因此必须走前者——否则摘要算错了也会被同一份逻辑掩盖过去。
        use alloy::signers::SignerSync;

        // Anvil / Hardhat 的 0 号测试账户，公开且无资金，可安全写进测试。
        const DEV_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

        let signer = PrivateKeySigner::from_str(DEV_KEY).expect("测试私钥应合法");
        let expected_from = signer.address();

        let u = fixed_unsigned();
        let bytes = unsigned_bytes(&u);

        // 外部签名方视角：只拿到 32 字节摘要，用它签出可恢复签名。
        let signature = signer
            .sign_hash_sync(&u.signing_hash)
            .expect("对摘要签名应成功");

        // 反推：用**与签名侧完全无关**的恢复路径，从「摘要 + 签名」推出地址。
        // `recover_address_from_prehash` 走的是标准 ECDSA 公钥恢复
        // （由 r 反解 R 点、再由 s 与消息哈希求公钥），与签名过程互为实现，
        // 因此它能在摘要被算错时立刻给出**另一个**地址——这正是我们要的判据。
        let recovered = signature
            .recover_address_from_prehash(&u.signing_hash)
            .expect("应能从摘要与签名恢复出地址");
        assert_eq!(recovered, expected_from);

        // 重组：像离线签名程序那样——先解码交出去的字节，再把签名装回信封，
        // 产出可广播字节（即 `broadcast_raw` 的输入形态），
        // 最后确认它是**结构合法**的交易，能被官方解码器完整解析。
        //
        // `&mut &[u8]` 是 `Decodable` 的惯用写法：外层 `&mut` 让解码器能推进游标，
        // 里层的切片本身不必可变。
        let typed = TypedTransaction::decode_unsigned(&mut &bytes[..]).expect("未签名解码应成功");
        let signed_bytes = typed.into_envelope(signature).encoded_2718();
        let mut slice: &[u8] = &signed_bytes;
        TxEnvelope::decode(&mut slice).expect("已签名交易应能被官方解码器解析");
        assert!(slice.is_empty(), "已签名交易解码后有剩余字节");
        // 类型标志仍在首位，且长度必然大于未签名原像（多出签名三元组）。
        assert_eq!(signed_bytes[0], 0x02);
        assert!(signed_bytes.len() > bytes.len());
    }

    /// 原像里**优先费排在费用上限之前**——EIP-1559 的字段顺序。
    ///
    /// 手写 RLP 时这是最常弄反的一处，且弄反后签名依然「能算出来」，
    /// 只是网络会拒绝，属于典型的「本地自测全绿、上链必挂」缺陷。
    /// 这里直接对字节串做子串定位，把顺序钉死。
    #[test]
    fn max_priority_fee_is_encoded_before_max_fee() {
        // 去掉 `0x` 前缀后就是纯十六进制串，可直接做子串查找。
        let hex = fixed_unsigned().unsigned_tx_hex.trim_start_matches("0x").to_string();

        // 1 gwei = 0x3B9ACA00，30 gwei = 0x6FC23AC00。
        // 用 `find` 取首次出现位置：优先费应更早出现。
        let priority = hex.find("3b9aca00").expect("找不到优先费字段");
        let max_fee = hex.find("6fc23ac00").expect("找不到费用上限字段");
        assert!(
            priority < max_fee,
            "字段顺序错误：优先费在 {priority}、费用上限在 {max_fee}，\n\
             EIP-1559 要求优先费在前（完整编码: {hex}）"
        );
    }
}
