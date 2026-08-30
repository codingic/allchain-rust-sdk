//! 从 WIF 私钥派生地址、选择 UTXO、构造交易并离线签名。
//!
//! 完整流程（对应 `build_transfer` 里的 1~4 步注释）：
//!   1. 由 WIF 私钥派生出各类地址 → 向索引器询问这些地址下的 UTXO；
//!   2. 选币（大额优先）并按估算体积算手续费；
//!   3. 处理找零（低于 dust 就并入手续费）；
//!   4. 按每个输入各自的脚本类型分别计算 sighash 并本地签名。
//!
//! 私钥全程只在本进程内参与 ECDSA 运算，不进入任何网络请求。

use std::str::FromStr;

use anyhow::{Context, Result, bail};
// `encode` 是比特币的字节级序列化（非 JSON）。
use bitcoin::consensus::encode;
// `Hash` trait 提供 `to_byte_array()` / `from_byte_array()` 这类定长哈希操作。
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
// `PushBytesBuf` 是「可直接压入脚本的字节缓冲区」，带长度上限检查。
use bitcoin::script::PushBytesBuf;
// `Message` 是 secp256k1 签名时所需的 32 字节摘要类型。
use bitcoin::secp256k1::Message;
// `SighashCache` 会缓存中间计算结果，逐输入签名时避免重复哈希。
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Address, Amount, CompressedPublicKey, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute::LockTime, transaction::Version,
};

use crate::backend::{Chain, UtxoView};
use crate::units::{
    DEFAULT_FEE_RATE, DUST_LIMIT, ScriptKind, estimate_vsize, fee_for_vsize, format_btc,
    parse_fee_rate,
};

/// 由 WIF 私钥派生的本地钱包（不含链上状态）。
///
/// 领域说明：**WIF（Wallet Import Format）** 是 base58check 编码的私钥，
/// 主网以 `L` / `K` / `5` 开头，测试网以 `c` / `9` 开头。
/// 它自带一个网络标识字节，所以能校验「这把私钥属于哪个网络」。
///
/// 注意这里派生的是**四类地址**，同一个私钥在不同脚本类型下地址完全不同：
/// `p2wpkh`（bc1q…）/ `p2pkh`（1…）/ `p2sh-p2wpkh`（3…）/ `p2tr`（bc1p…）。
/// 它们花的都是同一份币，但手续费与兼容性各异。
pub struct Wallet {
    /// 所属网络，决定地址编码。
    pub network: Network,
    /// 私钥本体。
    pub private_key: PrivateKey,
    /// **未压缩**公钥（65 字节），P2PKH 的 scriptSig 需要它。
    pub public_key: PublicKey,
    /// **压缩**公钥（33 字节），所有隔离见证地址都基于它。
    pub compressed: CompressedPublicKey,
    /// 原生隔离见证地址（bc1q...），默认收款与找零地址。
    pub p2wpkh: Address,
    /// 传统地址（1...）。
    pub p2pkh: Address,
}

impl Wallet {
    /// 由 WIF 私钥构造钱包，并校验私钥的网络与 `network` 一致。
    pub fn from_wif(wif: &str, network: Network) -> Result<Self> {
        // `from_wif` 会同时校验 base58check 校验和与长度。
        let private_key = PrivateKey::from_wif(wif.trim()).with_context(|| "解析 WIF 私钥失败")?;

        // `NetworkKind::from(network)`：把「网络」抽象成「网络种类」
        // （main / test / regtest / signet 归成几类），用于比较而不必逐一列变体。
        let expected = bitcoin::network::NetworkKind::from(network);
        if private_key.network != expected {
            // 这条校验是**安全相关**的：把主网私钥用到测试网（或反之）
            // 会让人以为「币丢了」，实际上币还在另一个网络的同名地址上。
            bail!(
                "私钥网络不匹配：WIF 属于 {:?}，当前选择 {:?}",
                private_key.network,
                expected
            );
        }

        // `Secp256k1::new()` 创建一个带完整预计算表的上下文。
        // 它是 CPU 密集型对象，理想上应复用而非每次新建。
        let secp = Secp256k1::new();
        // 由私钥做椭圆曲线点乘得到公钥：先出未压缩形式。
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        // 再出压缩形式。这里用 `context` 而非直接 panic：
        // 压缩本身几乎不会失败，失败说明输入异常，要有可读的错误。
        let compressed = CompressedPublicKey::from_private_key(&secp, &private_key)
            .context("私钥必须使用压缩公钥格式")?;

        Ok(Self {
            network,
            private_key,
            public_key,
            compressed,
            // P2WPKH 地址 = bech32(hash160(压缩公钥))。
            p2wpkh: Address::p2wpkh(&compressed, network),
            // P2PKH 地址 = base58check(版本字节 || hash160(公钥))。
            // 注意它用的是**未压缩**公钥的哈希——这是历史惯例，
            // 也是为什么 P2PKH 的 scriptSig 里要放 65 字节的未压缩公钥。
            p2pkh: Address::p2pkh(public_key.pubkey_hash(), network),
        })
    }

    /// 按脚本类型返回本钱包的对应地址。
    ///
    /// 语法说明：`match kind` 对 `Copy` 枚举按值匹配，不需要引用。
    pub fn address(&self, kind: ScriptKind) -> Address {
        match kind {
            // `.clone()`：字段是 `Address`，返回自有副本而非引用，
            // 调用方拿到后可长期持有，不受 `&self` 生命周期限制。
            ScriptKind::P2wpkh => self.p2wpkh.clone(),
            ScriptKind::P2pkh => self.p2pkh.clone(),
        }
    }

    /// 密钥路径花费的 Taproot 地址（bc1p...）。
    ///
    /// 领域说明：**Taproot（P2TR，BIP341）** 的输出脚本是一个调整后的公钥。
    /// 这里的 `None` 表示没有脚本树（merkle root 为空），
    /// 即只能用「密钥路径」花费，行为上等价于单签但更省体积、隐私更好。
    /// 注意 bech32m 编码（不是 bech32），故前缀是 `bc1p` 而非 `bc1q`。
    pub fn taproot_address(&self) -> Address {
        let secp = Secp256k1::new();
        // `self.compressed.0`：`CompressedPublicKey` 是元组结构体，
        // `.0` 取出内部的 `secp256k1::PublicKey`；`.into()` 转成 Taproot 需要的类型。
        Address::p2tr(&secp, self.compressed.0.into(), None, self.network)
    }
}

/// 选中的 UTXO 及其脚本信息。
///
/// 语法说明：只派生 `Clone`（没有 `Debug`）——它只在选币与签名阶段短距离传递，
/// 不需要打印，少派生一个 trait 就少一份生成代码。
#[derive(Clone)]
struct Selected {
    /// 来自索引器的 UTXO 信息（txid / vout / 金额 / 确认状态）。
    utxo: UtxoView,
    /// 该 UTXO 锁在哪种脚本里——决定了签名方式。
    kind: ScriptKind,
    /// 对应的锁定脚本（`scriptPubKey`），计算 sighash 时需要。
    script: ScriptBuf,
}

/// 一笔已在本地构造并签名、但尚未广播的转账。
#[derive(Clone)]
pub struct BuiltTransfer {
    /// 序列化后的完整交易（十六进制），可直接广播。
    pub raw_hex: String,
    /// 交易 ID。
    pub txid: String,
    /// 付款地址（本钱包默认地址）。
    pub from: String,
    /// 收款地址。
    pub to: String,
    /// 转账金额（satoshi）。
    pub amount_sat: u64,
    /// 实际支付的手续费（satoshi）。
    pub fee: u64,
    /// 使用的费率（sat/vB）。
    pub fee_rate: f64,
    /// 签名后**实测**的虚拟字节数。
    pub vsize: u64,
    /// 选币阶段按签名前脚本种类估算的 vsize（与实测 vsize 有少量出入）。
    ///
    /// 领域说明：二者会差几个字节，因为 DER 签名的长度不固定
    /// （ECDSA 签名是 DER 编码，前导零会导致长度在 71~73 字节间浮动）。
    /// 实测值偏大时实际费率略低于目标，因此估算时通常宁可略微高估。
    pub vsize_estimate: u64,
    /// 找零金额；0 表示找零并入了手续费。
    pub change: u64,
    /// 本次花掉的输入明细，供调用方展示与审计。
    pub inputs: Vec<InputInfo>,
}

/// 交易输入概览，供调用方展示与审计。
#[derive(Clone)]
pub struct InputInfo {
    pub txid: String,
    pub vout: u32,
    /// 该输入的金额（satoshi）。
    pub value: u64,
    /// 是否来自已确认区块。花未确认的 UTXO 会被下游延迟确认。
    pub confirmed: bool,
}

/// 构造并签名一笔转账（不打印不广播）：`选币 -> 估算手续费 -> 本地签名`。
///
/// 私钥只参与本地签名，不会离开本进程。返回的 raw 交易既可广播，也可 dry-run 审计。
///
/// 语法说明：`#[allow(clippy::too_many_arguments)]` 关掉 clippy 的「参数过多」警告。
/// 这里七个参数各自代表一个正交的业务维度（目标、金额、费率、脚本类型、RBF），
/// 拆成配置结构体会让调用方更啰嗦，权衡后保留扁平签名。
#[allow(clippy::too_many_arguments)]
pub async fn build_transfer(
    chain: &Chain,
    wif: &str,
    to: &Address,
    amount_sat: u64,
    fee_rate: Option<&str>,
    legacy: bool,
    rbf: bool,
) -> Result<BuiltTransfer> {
    // `chain.network()` 是 `NetworkArg`（CLI 层枚举），
    // 再 `.network()` 得到 rust-bitcoin 的 `Network`。
    let network = chain.network().network();
    let wallet = Wallet::from_wif(wif, network)?;
    // 费率：显式给了就解析，否则向数据源问推荐值。
    let rate = match fee_rate {
        Some(raw) => parse_fee_rate(Some(raw))?,
        None => recommended_fee_rate(chain).await,
    };

    // 1) 拉取可用 UTXO：默认只花 P2WPKH 地址上的币，`--legacy` 时额外扫描传统地址。
    //
    // 之所以默认只扫 P2WPKH：绝大多数现代钱包只往隔离见证地址收币，
    // 少扫一个地址就少一次网络请求。
    let mut kinds = vec![ScriptKind::P2wpkh];
    if legacy {
        kinds.push(ScriptKind::P2pkh);
    }
    let mut candidates: Vec<Selected> = Vec::new();
    for kind in kinds {
        // `kind` 是 `Copy` 的，循环里可反复使用。
        let address = wallet.address(kind);
        // `script_pubkey()` 由地址反推出锁定脚本，签名算 sighash 时需要。
        let script = address.script_pubkey();
        for utxo in chain.utxos(&address.to_string()).await? {
            candidates.push(Selected {
                utxo,
                kind,
                // 同一地址下所有 UTXO 共用同一个脚本，这里克隆一份。
                script: script.clone(),
            });
        }
    }
    if candidates.is_empty() {
        // 报错里给出具体地址，用户可直接拿去区块浏览器核对。
        bail!("地址 {} 上没有可用 UTXO", wallet.p2wpkh);
    }
    // 大额优先，尽量减少输入数量与交易体积。
    //
    // `sort_by` 接受一个返回 `Ordering` 的比较闭包。
    // `b.utxo.value.cmp(&a.utxo.value)`：用 **b 比 a** 得到**降序**——
    // 这是 Rust 里写降序排序的标准技巧（把比较的两边对调）。
    candidates.sort_by(|a, b| b.utxo.value.cmp(&a.utxo.value));

    // 2) 选币并估算手续费（先按「带找零输出」计算，不够再加输入）。
    //
    // 这里存在一个**鸡生蛋问题**：手续费取决于交易体积，
    // 而体积又取决于选了几个输入。做法是逐个加输入、每次重算，够用即停。
    let mut selected: Vec<Selected> = Vec::new();
    let mut total: u64 = 0;
    let mut fee: u64 = 0;
    // `for candidate in candidates`：**按值**消耗候选列表，直接移进 `selected`。
    for candidate in candidates {
        selected.push(candidate);
        // `selected.last().unwrap()` 取出刚 push 进去的那一项。
        // `unwrap` 在这里是安全的——上一行刚 push 过，必然有值。
        total += selected.last().unwrap().utxo.value;
        fee = fee_for_vsize(
            // 先按「有找零输出」估算（output_count = 2），
            // 若最终无找零，实际手续费会略高于目标，方向是安全的。
            estimate_vsize(&kinds_of(&selected), ScriptKind::P2wpkh, 2),
            rate,
        );
        // 够了就停；否则继续加下一个候选。
        if total >= amount_sat + fee {
            break;
        }
    }
    // 全部 UTXO 加起来还是不够。
    if total < amount_sat + fee {
        bail!(
            "余额不足：可用 {} BTC，需要 {} BTC（金额 {} + 手续费 {} sat）",
            format_btc(total),
            format_btc(amount_sat + fee),
            format_btc(amount_sat),
            fee
        );
    }

    // 3) 找零：低于 dust 阈值就直接并入手续费，避免产生无法花费的粉尘输出。
    let mut change = total - amount_sat - fee;
    let mut output_count = 2usize;
    if change < DUST_LIMIT {
        change = 0;
        // 剩余的全给矿工：不产生粉尘输出，也变相提高了费率，更容易被打包。
        fee = total - amount_sat;
        output_count = 1;
    }
    // 重新按最终的输出数量估算一次，得到对外报告的 vsize 预测值。
    let vsize_estimate = estimate_vsize(&kinds_of(&selected), ScriptKind::P2wpkh, output_count);

    // **RBF（Replace-By-Fee，BIP125）**：让这笔交易在卡住时可用更高费率替换。
    //
    // 实现方式是设置 nSequence < 0xFFFFFFFE：
    // `ENABLE_RBF_NO_LOCKTIME` = 0xFFFFFFFD（信号可替换、不启用相对时间锁）；
    // `Sequence::MAX` = 0xFFFFFFFF 表示**不可**替换（最终版）。
    let sequence = if rbf {
        Sequence::ENABLE_RBF_NO_LOCKTIME
    } else {
        Sequence::MAX
    };
    let mut inputs = Vec::with_capacity(selected.len());
    for s in &selected {
        let txid =
            Txid::from_str(&s.utxo.txid).with_context(|| format!("非法 txid: {}", s.utxo.txid))?;
        inputs.push(TxIn {
            // `OutPoint` = txid + vout，即「引用哪一个 UTXO」。
            previous_output: OutPoint {
                txid,
                vout: s.utxo.vout,
            },
            // scriptSig 先留空，签名阶段再填（P2WPKH 恒为空）。
            script_sig: ScriptBuf::new(),
            sequence,
            // 见证字段先留空，签名阶段再填。
            witness: Witness::new(),
        });
    }

    let mut tx = Transaction {
        // 版本 2：支持相对时间锁（BIP68），现代钱包的标准选择。
        version: Version::TWO,
        // `LockTime::ZERO`：不设置绝对时间锁，交易立即可入块。
        lock_time: LockTime::ZERO,
        input: inputs,
        // 第一个输出：给收款方。有找零时下面再 push 第二个。
        output: vec![TxOut {
            // `Amount::from_sat`：把 u64 包成 `Amount` 新类型，
            // 防止与「字节数」「权重」等其它数值混用。
            value: Amount::from_sat(amount_sat),
            // `to.script_pubkey()`：由收款地址推出锁定脚本。
            script_pubkey: to.script_pubkey(),
        }],
    };
    if change > 0 {
        tx.output.push(TxOut {
            value: Amount::from_sat(change),
            // 找零回到**自己的** P2WPKH 地址。
            script_pubkey: wallet.p2wpkh.script_pubkey(),
        });
    }

    // 4) 离线签名：每个输入按自己的脚本类型分别计算 sighash。
    //
    // 为什么必须逐个签：两种脚本的 sighash 算法不同（BIP143 vs 传统），
    // 且每个输入的 sighash 都覆盖「全部输入 + 全部输出」的组合摘要，
    // 改动任何一个输入都会让其它输入的签名失效。
    let secp = Secp256k1::new();
    // `selected.iter().enumerate()` 同时拿到下标（写回 `tx.input[index]`）与元素。
    for (index, input) in selected.iter().enumerate() {
        match input.kind {
            ScriptKind::P2wpkh => sign_p2wpkh(
                // `&mut tx`：签名要就地写入见证字段。
                &mut tx,
                index,
                &input.script,
                // P2WPKH 的 sighash 需要知道**这个输入值多少钱**（BIP143 的防篡改设计）。
                input.utxo.value,
                &wallet,
                &secp,
            )?,
            // P2PKH 的传统 sighash 不需要金额——这正是它后来被发现可被
            // 硬件钱包「少找零攻击」的原因，SegWit 的 BIP143 补上了这个洞。
            ScriptKind::P2pkh => sign_p2pkh(&mut tx, index, &input.script, &wallet, &secp)?,
        }
    }

    let info: Vec<InputInfo> = selected
        .iter()
        .map(|s| InputInfo {
            txid: s.utxo.txid.clone(),
            vout: s.utxo.vout,
            value: s.utxo.value,
            confirmed: s.utxo.confirmed,
        })
        .collect();

    Ok(BuiltTransfer {
        // `serialize_hex`：按比特币的字节格式序列化并转成十六进制。
        raw_hex: encode::serialize_hex(&tx),
        // `compute_txid()`：对**非见证**部分做双 SHA256，这才是链上 txid。
        txid: tx.compute_txid().to_string(),
        from: wallet.p2wpkh.to_string(),
        to: to.to_string(),
        amount_sat,
        fee,
        fee_rate: rate,
        // 签名后实测的 vsize：此时见证已填好，`tx.vsize()` 是准确值。
        vsize: tx.vsize() as u64,
        vsize_estimate,
        change,
        inputs: info,
    })
}

/// 构造并广播一笔转账：`选币 -> 估算手续费 -> 本地签名 -> 广播`。
///
/// 私钥只参与本地签名，不会离开本进程。
///
/// 返回值语义：`Ok(Some(txid))` 表示已广播；`Ok(None)` 表示 dry-run（只构造未广播）。
/// 用 `Option` 而不是额外的 bool 输出参数，可让「忘记处理 dry-run」变成编译期不可能。
#[allow(clippy::too_many_arguments)]
pub async fn transfer(
    chain: &Chain,
    wif: &str,
    to: &Address,
    amount_sat: u64,
    fee_rate: Option<&str>,
    legacy: bool,
    rbf: bool,
    dry_run: bool,
) -> Result<Option<String>> {
    // 签名、估算、选币全部在 `build_transfer` 里完成，这里只负责展示与广播。
    // 拆开的好处：调用方（如 acli 的 HTTP 接口）可只调 build 而不打印。
    let built = build_transfer(chain, wif, to, amount_sat, fee_rate, legacy, rbf).await?;

    // 以下是一段纯展示代码：把构造结果对齐打印，方便人工核对后再广播。
    println!("from             : {}", built.from);
    println!("to               : {}", built.to);
    println!(
        "amount           : {} BTC ({} sat)",
        format_btc(built.amount_sat),
        built.amount_sat
    );
    // `{:.2}`：保留两位小数，费率通常不是整数。
    println!("fee_rate         : {:.2} sat/vB", built.fee_rate);
    println!(
        "fee              : {} BTC ({} sat)",
        format_btc(built.fee),
        built.fee
    );
    // 同时给出实测与估算体积，便于观察两者偏差（DER 签名长度浮动导致）。
    println!(
        "vsize            : {} vB (估算 {} vB)",
        built.vsize, built.vsize_estimate
    );
    if built.change > 0 {
        println!(
            "change           : {} BTC -> {}",
            format_btc(built.change),
            built.from
        );
    }
    println!("inputs           : {} 个", built.inputs.len());
    // `&built.inputs`：`&Vec<InputInfo>` 会解引用强制转换成 `&[InputInfo]` 切片，
    // 只读遍历时用切片即可，不必移动所有权（`built` 后面还要用）。
    for input in &built.inputs {
        println!(
            "  {}:{}  {} BTC{}",
            input.txid,
            input.vout,
            format_btc(input.value),
            // 用 `if` 表达式直接产出 `&str`：确认了就不加后缀，未确认加提示。
            // 注意两个分支类型必须一致，都是 `&'static str`。
            if input.confirmed {
                ""
            } else {
                "  (unconfirmed)"
            }
        );
    }
    println!("txid             : {}", built.txid);
    println!("raw_tx           : {}", built.raw_hex);

    if dry_run {
        println!("dry-run          : 仅本地构造，未广播");
        // `Ok(None)`：与「已广播」区分开，调用方可据此决定是否继续。
        return Ok(None);
    }

    // 5) 广播：配置了 bitcoind 时走自己的节点，否则走 Esplora。
    //
    // 注意广播是**不可逆**操作：一旦被网络接受就无法撤回，
    // 因此上面的打印 + dry-run 分支是给用户最后的人工确认机会。
    let txid = chain
        .broadcast(&built.raw_hex)
        .await
        .context("广播交易失败")?;
    println!("broadcast        : ok (via {})", chain.source());
    Ok(Some(txid))
}

/// 把选中的 UTXO 列表映射成脚本类型列表，供体积估算使用。
///
/// 语法说明：`s.kind` 能直接拷贝是因为 `ScriptKind` 派生了 `Copy`，
/// 所以不需要写 `s.kind.clone()`——这也是小枚举应当派生 `Copy` 的理由。
fn kinds_of(selected: &[Selected]) -> Vec<ScriptKind> {
    selected.iter().map(|s| s.kind).collect()
}

/// 取「约 3 个区块确认」档位的推荐费率，取不到就用缺省值。
///
/// 领域说明：索引器返回的是「目标区块数 -> 费率」的阶梯表，
/// 目标是 3 个块 ≈ 半小时左右，是性价比与确认速度的常用折中点。
async fn recommended_fee_rate(chain: &Chain) -> f64 {
    match chain.fee_estimates().await {
        // 链式组合：先找第一个目标 >= 3 的档位；找不到就退而取最贵的第一档；
        // 再没有就用常量缺省值。三层兜底保证「一定有费率可用」。
        Ok(estimates) => estimates
            .iter()
            // 闭包参数是 `&(u32, f64)` 的引用，故要 `*target` 解引用后再比较。
            .find(|(target, _)| *target >= 3)
            // `or_else` 接闭包且**惰性**求值：只有 `find` 失败才会执行。
            .or_else(|| estimates.first())
            // 此时是 `Option<&(u32, f64)>`，`*rate` 把 f64 拷出来。
            .map(|(_, rate)| *rate)
            // `unwrap_or` 的参数是**立即求值**的常量，这里代价可忽略。
            .unwrap_or(DEFAULT_FEE_RATE),
        // 问费率失败不应阻断交易构造：静默退回缺省值，让流程继续。
        // `Err(_)` 用通配符丢弃错误详情——这里不打算向用户报告。
        Err(_) => DEFAULT_FEE_RATE,
    }
}

/// P2WPKH 输入的 BIP143 签名（见证字段）。
///
/// 领域说明：**BIP143** 规定了隔离见证输入的 sighash 算法。
/// 与旧算法最大的区别是它把**当前输入的金额**也纳入哈希，
/// 从而堵住了硬件钱包「被隐瞒真实输入金额 → 少找零」的攻击面。
fn sign_p2wpkh(
    // 待签名的交易，签名结果就地写回 `tx.input[index].witness`。
    tx: &mut Transaction,
    // 要签第几个输入。
    index: usize,
    // 该输入的锁定脚本（P2WPKH 形如 `OP_0 <20 字节哈希>`）。
    script_pubkey: &ScriptBuf,
    // **这个输入值多少 satoshi**——BIP143 要求把它混进哈希。
    value: u64,
    wallet: &Wallet,
    // `Secp256k1<All>` 表示启用全部能力（签名 + 验签）的上下文，
    // 泛型参数写在类型里，编译期就能确保能力齐备。
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<()> {
    // 用花括号包一层**块作用域**，是为了让 `cache` 的可变借用提前结束。
    // `SighashCache::new(&*tx)` 会持有 `tx` 的借用，若不及时释放，
    // 下面 `tx.input[index].witness = ...` 的写操作会被借用检查器拒绝。
    // 这是 Rust 里「先算完哈希、再改结构体」的典型写法。
    let sighash = {
        // `&*tx`：`tx` 是 `&mut Transaction`，`*tx` 先解引用得到 `Transaction`，
        // 再 `&` 借一次，把「可变借用重借用为不可变借用」。
        let mut cache = SighashCache::new(&*tx);
        cache
            .p2wpkh_signature_hash(
                index,
                script_pubkey,
                Amount::from_sat(value),
                // `SIGHASH_ALL`：签名覆盖全部输入与全部输出，
                // 即「我认可这笔交易的每一个细节」。
                EcdsaSighashType::All,
            )
            .context("计算 P2WPKH sighash 失败")?
    };
    // `to_byte_array()` 由 `Hash` trait 提供，取出定长 32 字节数组；
    // secp256k1 签的是**摘要**而不是原文。
    let message = Message::from_digest(sighash.to_byte_array());
    // `sighash_all` 在 DER 签名的末尾追加 0x01 标志字节（SIGHASH_ALL）。
    let signature = bitcoin::ecdsa::Signature::sighash_all(
        // `wallet.private_key.inner`：取出 `PrivateKey` 内部的 secp256k1 私钥。
        secp.sign_ecdsa(&message, &wallet.private_key.inner),
    );
    // 见证由两项组成：`[DER 签名 + 标志字节, 压缩公钥]`。
    // 见证字段**不计入 txid**，所以补签名不会改变交易 ID（这是 SegWit 修复的延展性漏洞）。
    tx.input[index].witness = Witness::p2wpkh(&signature, &wallet.compressed.0);
    Ok(())
}

/// P2PKH 输入的传统签名（scriptSig = <DER 签名> <公钥>）。
///
/// 领域说明：传统 P2PKH 把解锁数据放在 scriptSig 里，
/// 而 scriptSig **参与 txid 计算**，因此签名前后 txid 会变（交易延展性问题）。
/// 这也是为什么测试里要用签名前的 `unsigned` 副本重新算 sighash。
fn sign_p2pkh(
    tx: &mut Transaction,
    index: usize,
    script_pubkey: &ScriptBuf,
    wallet: &Wallet,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<()> {
    // 传统 sighash **不需要**输入金额——这正是 BIP143 补上的安全缺口。
    // `to_u32()` 把 sighash 类型转成一个字节标志（All = 0x01）。
    // 这里没有用块作用域：临时值在语句结束后即释放，下一句就能改 `tx`。
    let sighash = SighashCache::new(&*tx)
        .legacy_signature_hash(index, script_pubkey, EcdsaSighashType::All.to_u32())
        .context("计算 P2PKH sighash 失败")?;
    let message = Message::from_digest(sighash.to_byte_array());
    let signature = bitcoin::ecdsa::Signature::sighash_all(
        secp.sign_ecdsa(&message, &wallet.private_key.inner),
    );

    // `PushBytesBuf` 是带长度上限的字节缓冲：脚本单次最多推送 520 字节，
    // 超限会被拒绝。DER 签名最长 73 字节，公钥 65 字节，都远在上限内。
    let mut sig_bytes = PushBytesBuf::new();
    sig_bytes
        // `extend_from_slice` 返回 `Result`：超限时报错而非静默截断。
        .extend_from_slice(&signature.serialize())
        .context("签名长度超出脚本推送上限")?;
    let mut pubkey_bytes = PushBytesBuf::new();
    pubkey_bytes
        // 注意这里取的是**未压缩**公钥（65 字节，`0x04 || X || Y`）。
        // 历史惯例：P2PKH 地址哈希的是未压缩公钥，所以 scriptSig 必须提交同一个。
        .extend_from_slice(&wallet.public_key.inner.serialize())
        .context("公钥长度超出脚本推送上限")?;

    // 比特币脚本是**栈式**执行的：先压入的先出栈，
    // 而 P2PKH 的 `OP_CHECKSIG` 期望栈顶是公钥、其下是签名。
    // 因此这里必须**先 push 签名、再 push 公钥**。
    tx.input[index].script_sig = ScriptBuf::builder()
        .push_slice(sig_bytes)
        .push_slice(pubkey_bytes)
        // `into_script()` 把建造者转成不可变的 `ScriptBuf`。
        .into_script();
    Ok(())
}

// `#[cfg(test)]`：整个模块只在 `cargo test` 时参与编译，正式构建会被剔除。
// 这是 Rust 把单元测试与源码同文件放置的标准做法（`use super::*` 引入被测项）。
#[cfg(test)]
mod tests {
    use super::*;

    /// 一个公开可查的测试向量（主网 WIF，余额早已归零，不含真实资产）。
    ///
    /// 语法说明：`const` 是编译期常量，类型为 `&str`
    /// （`&'static str` 的生命周期被省略了——字符串字面量存活于整个程序）。
    const TEST_WIF: &str = "L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy";

    /// 构造测试钱包。测试里用 `unwrap()` 是惯例：
    /// 断言失败即 panic，正好符合「出错就该失败」的测试语义。
    fn test_wallet() -> Wallet {
        Wallet::from_wif(TEST_WIF, Network::Bitcoin).unwrap()
    }

    /// 构造一个只有一个输入的测试交易，输出脚本沿用输入的脚本。
    ///
    /// 这样同一个模板可以给 P2WPKH 和 P2PKH 两种测试复用。
    fn test_tx(input_script: &ScriptBuf) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    // 这是比特币**创世区块 coinbase** 的 txid，仅作占位引用。
                    // 测试只做本地签名，不需要这笔输入真实存在。
                    txid: Txid::from_str(
                        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                // 不可替换（最终版），无需 RBF。
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: input_script.clone(),
            }],
        }
    }

    /// 地址派生必须与脚本类型严格对应，且跨网络要被拒绝。
    #[test]
    fn derives_expected_addresses() {
        let wallet = test_wallet();
        // P2WPKH / P2TR 在**主网**的前缀分别是 bech32 的 `bc1q` 与 bech32m 的 `bc1p`；
        // P2PKH 是 base58check 的 `1`。用前缀断言比写死完整地址更抗重构。
        assert!(wallet.p2wpkh.to_string().starts_with("bc1q"));
        // `'1'` 是 `char`，`starts_with` 对 `char` 与 `&str` 都有重载实现。
        assert!(wallet.p2pkh.to_string().starts_with('1'));
        assert!(wallet.taproot_address().to_string().starts_with("bc1p"));
        // 换网络应被拒绝，避免把主网私钥用到测试网上（反之亦然）。
        assert!(Wallet::from_wif(TEST_WIF, Network::Testnet).is_err());
    }

    /// P2WPKH 签名必须能通过 secp256k1 验签，见证里带的公钥要与地址一致。
    #[test]
    fn signs_p2wpkh_input() {
        let wallet = test_wallet();
        let secp = Secp256k1::new();
        let script = wallet.p2wpkh.script_pubkey();
        let value = 10_000;

        let mut tx = test_tx(&script);
        // 先克隆一份**未签名**的交易：签名会改变 tx，
        // 而验签时必须用签名前的状态重算 sighash。
        let unsigned = tx.clone();
        sign_p2wpkh(&mut tx, 0, &script, value, &wallet, &secp).unwrap();

        // 见证恰好两项：[签名, 压缩公钥]。
        let witness = tx.input[0].witness.to_vec();
        assert_eq!(witness.len(), 2);
        assert_eq!(witness[1], wallet.compressed.0.serialize());

        let sig = bitcoin::ecdsa::Signature::from_slice(&witness[0]).unwrap();
        assert_eq!(sig.sighash_type, EcdsaSighashType::All);

        // 用 `unsigned` 复现 sighash，再对签名做一次**验签**——
        // 只比对字节无法证明签名真的有效，验签才是端到端的正确性证明。
        let sighash = SighashCache::new(&unsigned)
            .p2wpkh_signature_hash(0, &script, Amount::from_sat(value), EcdsaSighashType::All)
            .unwrap();
        let message = Message::from_digest(sighash.to_byte_array());
        assert!(
            secp.verify_ecdsa(&message, &sig.signature, &wallet.compressed.0)
                .is_ok()
        );
    }

    /// P2PKH 签名写入 scriptSig，同样要通过验签。
    #[test]
    fn signs_p2pkh_input() {
        let wallet = test_wallet();
        let secp = Secp256k1::new();
        let script = wallet.p2pkh.script_pubkey();

        let mut tx = test_tx(&script);
        let unsigned = tx.clone();
        sign_p2pkh(&mut tx, 0, &script, &wallet, &secp).unwrap();

        let script_sig = tx.input[0].script_sig.as_bytes();
        // 公钥是最后压入的，所以位于字节串末尾。
        assert!(script_sig.ends_with(&wallet.public_key.inner.serialize()));

        // 反向解析脚本：`instructions()` 返回逐条指令的迭代器，
        // 用来取出第一项（DER 签名）而不必手工解析长度前缀。
        let pushed = bitcoin::Script::from_bytes(script_sig);
        let mut instructions = pushed.instructions();
        // 双层 `unwrap()`：外层是 `Option`（迭代器可能已结束），
        // 内层是 `Result`（脚本可能非法）。测试里直接 panic 即可。
        let sig = match instructions.next().unwrap().unwrap() {
            bitcoin::script::Instruction::PushBytes(bytes) => {
                bitcoin::ecdsa::Signature::from_slice(bytes.as_bytes()).unwrap()
            }
            // `{other:?}` 是**内联命名捕获**：把 `other` 用 Debug 格式打印进 panic 信息。
            other => panic!("scriptSig 首项不是签名: {other:?}"),
        };

        let sighash = SighashCache::new(&unsigned)
            .legacy_signature_hash(0, &script, EcdsaSighashType::All.to_u32())
            .unwrap();
        let message = Message::from_digest(sighash.to_byte_array());
        // 注意这里用**未压缩**公钥验签，与 scriptSig 里提交的一致。
        assert!(
            secp.verify_ecdsa(&message, &sig.signature, &wallet.public_key.inner)
                .is_ok()
        );
    }
}
