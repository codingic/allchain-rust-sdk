//! 选币与未签名交易构造——**本模块不接触私钥**。
//!
//! 私钥只应停留在签名器（见 `sign` crate）里，不在 SDK 侧出现。
//! 本模块负责无私钥的那半边：
//!   1. 由**压缩公钥**派生出可花费地址 → 向索引器询问这些地址下的 UTXO；
//!   2. 选币（大额优先）并按估算体积算手续费；
//!   3. 处理找零（低于 dust 就并入手续费）；
//!   4. 搭出**未签名**的交易骨架，交给 `tx` 模块算 sighash、再交给签名器签。
//!
//! 为什么把私钥路径整个删掉：两条路径（一体式与两段式）在选币、搭模板上
//! 共用这里的纯函数，但**签名**是两套独立代码。同时维护两套的代价是
//! 「两处对 sighash 的理解可能漂移」，而漂移只会在广播时才暴露。
//! 只留一条，就让这种漂移在编译期就不可能发生。

use std::str::FromStr;

use anyhow::{Context, Result, bail};
use bitcoin::{
    Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime, transaction::Version,
};

use crate::backend::{Chain, UtxoView};
use crate::units::{
    DEFAULT_FEE_RATE, DUST_LIMIT, ScriptKind, estimate_vsize, fee_for_vsize, format_btc,
};

/// 选中的 UTXO 及其脚本信息。
///
/// 语法说明：只派生 `Clone`（没有 `Debug`）——它只在选币与构造阶段短距离传递，
/// 不需要打印，少派生一个 trait 就少一份生成代码。
///
/// 声明为 `pub` 是为了让 `tx.rs`（两段式构造）与本文件**共用同一套选币逻辑**：
/// 手续费估算、找零阈值、输入排序只要有一处不同，两条路径就会算出不同的 sighash，
/// 而这类不一致**不会报错**，只会表现为广播被拒。
#[derive(Clone)]
pub struct Selected {
    /// 来自索引器的 UTXO 信息（txid / vout / 金额 / 确认状态）。
    pub utxo: UtxoView,
    /// 该 UTXO 锁在哪种脚本里——决定了签名方式。
    pub kind: ScriptKind,
    /// 对应的锁定脚本（`scriptPubKey`），计算 sighash 时需要。
    pub script: ScriptBuf,
}

/// 选币结果：选了哪些 UTXO、手续费多少、找零多少。
///
/// 领域说明：这是「选币 + 估算 + 找零」三步的**纯计算结果**，不含任何私钥，
/// 因此可以直接交给 `tx.rs` 去算 sighash——私钥只出现在签名器那一侧。
#[derive(Clone)]
pub struct CoinSelection {
    /// 选中的输入（已按金额降序，即大额优先）。
    pub selected: Vec<Selected>,
    /// 选中输入的总额（satoshi）。
    pub total: u64,
    /// 本次应当支付的手续费（satoshi）。
    pub fee: u64,
    /// 找零金额；0 表示找零低于 dust 阈值、已并入手续费。
    pub change: u64,
    /// 最终的输出个数（1 = 无找零，2 = 带找零）。
    pub output_count: usize,
    /// 按最终输出数重算的 vsize 预测值。
    pub vsize_estimate: u64,
}

/// 纯选币：逐个累加 UTXO 直到覆盖「金额 + 手续费」，再决定找零去留。
///
/// 领域说明：这里存在一个**鸡生蛋问题**——手续费取决于交易体积，
/// 而体积又取决于选了几个输入。做法是逐个加输入、每次重算，够用即停。
///
/// 为什么必须是纯函数（不碰网络、不碰私钥）：两条签名路径要共用它。
/// 只要有一条走自己的实现，两条路径算出的 sighash 就会分叉，
/// 而分叉**不会报任何错**，只会在广播时被节点拒绝。
pub fn select_coins(
    // 候选 UTXO，**按值**接收：内部会直接把它们移进结果里，避免克隆。
    mut candidates: Vec<Selected>,
    amount_sat: u64,
    rate: f64,
) -> Result<CoinSelection> {
    // 大额优先，尽量减少输入数量与交易体积。
    //
    // `sort_by` 接受一个返回 `Ordering` 的比较闭包。
    // `b.utxo.value.cmp(&a.utxo.value)`：用 **b 比 a** 得到**降序**——
    // 这是 Rust 里写降序排序的标准技巧（把比较的两边对调）。
    candidates.sort_by(|a, b| b.utxo.value.cmp(&a.utxo.value));

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

    // 找零：低于 dust 阈值就直接并入手续费，避免产生无法花费的粉尘输出。
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

    Ok(CoinSelection {
        selected,
        total,
        fee,
        change,
        output_count,
        vsize_estimate,
    })
}

/// 由选币结果搭出**未签名**的交易骨架（scriptSig / witness 均为空）。
///
/// 领域说明：这一步的输出就是「待签模板」。它的字节内容**直接决定 sighash**，
/// 所以两条签名路径必须调用同一个函数——各自搭一遍的话，
/// 哪怕只是 sequence 字节差一位，签出来的东西也废了。
pub fn build_unsigned_transaction(
    selection: &CoinSelection,
    // 收款方的锁定脚本。
    to_script: &ScriptBuf,
    // 找零地址对应的锁定脚本（无找零时不会用到）。
    change_script: &ScriptBuf,
    amount_sat: u64,
    // 是否启用 RBF（见下方 `Sequence` 的说明）。
    rbf: bool,
) -> Result<Transaction> {
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
    let mut inputs = Vec::with_capacity(selection.selected.len());
    for s in &selection.selected {
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
            script_pubkey: to_script.clone(),
        }],
    };
    if selection.change > 0 {
        tx.output.push(TxOut {
            value: Amount::from_sat(selection.change),
            // 找零回到**调用方指定**的地址（一体式路径是钱包自己的 P2WPKH）。
            script_pubkey: change_script.clone(),
        });
    }
    Ok(tx)
}

/// 交易输入概览，供调用方展示与审计。
#[derive(Debug, Clone)]
pub struct InputInfo {
    pub txid: String,
    pub vout: u32,
    /// 该输入的金额（satoshi）。
    pub value: u64,
    /// 是否来自已确认区块。花未确认的 UTXO 会被下游延迟确认。
    pub confirmed: bool,
}

/// 把选中的 UTXO 列表映射成脚本类型列表，供体积估算使用。
///
/// 语法说明：`s.kind` 能直接拷贝是因为 `ScriptKind` 派生了 `Copy`，
/// 所以不需要写 `s.kind.clone()`——这也是小枚举应当派生 `Copy` 的理由。
fn kinds_of(selected: &[Selected]) -> Vec<ScriptKind> {
    selected.iter().map(|s| s.kind).collect()
}

/// 向索引器拉取若干地址下的 UTXO，打包成选币候选。
///
/// 抽成独立函数的原因同 [`select_coins`]：候选集合的**顺序与脚本归类**
/// 也会影响选币结果，进而影响 sighash。两条签名路径共用它才能不漂移。
///
/// 语法说明：`addresses: &[(Address, ScriptKind)]` 是**元组切片**，
/// 把「地址」与「该地址对应的脚本类型」绑在一起传给本函数——
/// 调用方决定要扫哪些地址（一体式路径受 `--legacy` 开关控制，
/// 两段式路径固定扫两个），本函数只管拉数据。
pub async fn collect_candidates(
    chain: &Chain,
    addresses: &[(Address, ScriptKind)],
) -> Result<Vec<Selected>> {
    let mut candidates: Vec<Selected> = Vec::new();
    // `for (address, kind) in addresses`：迭代 `&[(Address, ScriptKind)]`
    // 得到 `&(Address, ScriptKind)`，解构后 `address: &Address`、`kind: &ScriptKind`。
    for (address, kind) in addresses {
        // `script_pubkey()` 由地址反推出锁定脚本，签名算 sighash 时需要。
        let script = address.script_pubkey();
        for utxo in chain.utxos(&address.to_string()).await? {
            candidates.push(Selected {
                utxo,
                // `*kind`：`ScriptKind` 派生了 `Copy`，从引用里拷出值即可。
                kind: *kind,
                // 同一地址下所有 UTXO 共用同一个脚本，这里克隆一份。
                script: script.clone(),
            });
        }
    }
    Ok(candidates)
}

/// 取「约 3 个区块确认」档位的推荐费率，取不到就用缺省值。
///
/// 领域说明：索引器返回的是「目标区块数 -> 费率」的阶梯表，
/// 目标是 3 个块 ≈ 半小时左右，是性价比与确认速度的常用折中点。
pub(crate) async fn recommended_fee_rate(chain: &Chain) -> f64 {
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

