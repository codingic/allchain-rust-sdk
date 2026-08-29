//! 从 WIF 私钥派生地址、选择 UTXO、构造交易并离线签名。

use std::str::FromStr;

use anyhow::{Context, Result, bail};
use bitcoin::consensus::encode;
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::Message;
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
pub struct Wallet {
    pub network: Network,
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub compressed: CompressedPublicKey,
    /// 原生隔离见证地址（bc1q...），默认收款与找零地址。
    pub p2wpkh: Address,
    /// 传统地址（1...）。
    pub p2pkh: Address,
}

impl Wallet {
    pub fn from_wif(wif: &str, network: Network) -> Result<Self> {
        let private_key = PrivateKey::from_wif(wif.trim()).with_context(|| "解析 WIF 私钥失败")?;

        let expected = bitcoin::network::NetworkKind::from(network);
        if private_key.network != expected {
            bail!(
                "私钥网络不匹配：WIF 属于 {:?}，当前选择 {:?}",
                private_key.network,
                expected
            );
        }

        let secp = Secp256k1::new();
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        let compressed = CompressedPublicKey::from_private_key(&secp, &private_key)
            .context("私钥必须使用压缩公钥格式")?;

        Ok(Self {
            network,
            private_key,
            public_key,
            compressed,
            p2wpkh: Address::p2wpkh(&compressed, network),
            p2pkh: Address::p2pkh(public_key.pubkey_hash(), network),
        })
    }

    /// 按脚本类型返回本钱包的对应地址。
    pub fn address(&self, kind: ScriptKind) -> Address {
        match kind {
            ScriptKind::P2wpkh => self.p2wpkh.clone(),
            ScriptKind::P2pkh => self.p2pkh.clone(),
        }
    }

    /// 密钥路径花费的 Taproot 地址（bc1p...）。
    pub fn taproot_address(&self) -> Address {
        let secp = Secp256k1::new();
        Address::p2tr(&secp, self.compressed.0.into(), None, self.network)
    }
}

/// 选中的 UTXO 及其脚本信息。
#[derive(Clone)]
struct Selected {
    utxo: UtxoView,
    kind: ScriptKind,
    script: ScriptBuf,
}

/// 一笔已在本地构造并签名、但尚未广播的转账。
#[derive(Clone)]
pub struct BuiltTransfer {
    pub raw_hex: String,
    pub txid: String,
    pub from: String,
    pub to: String,
    pub amount_sat: u64,
    pub fee: u64,
    pub fee_rate: f64,
    pub vsize: u64,
    /// 选币阶段按签名前脚本种类估算的 vsize（与实测 vsize 有少量出入）。
    pub vsize_estimate: u64,
    /// 找零金额；0 表示找零并入了手续费。
    pub change: u64,
    pub inputs: Vec<InputInfo>,
}

/// 交易输入概览，供调用方展示与审计。
#[derive(Clone)]
pub struct InputInfo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub confirmed: bool,
}

/// 构造并签名一笔转账（不打印不广播）：`选币 -> 估算手续费 -> 本地签名`。
///
/// 私钥只参与本地签名，不会离开本进程。返回的 raw 交易既可广播，也可 dry-run 审计。
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
    let network = chain.network().network();
    let wallet = Wallet::from_wif(wif, network)?;
    let rate = match fee_rate {
        Some(raw) => parse_fee_rate(Some(raw))?,
        None => recommended_fee_rate(chain).await,
    };

    // 1) 拉取可用 UTXO：默认只花 P2WPKH 地址上的币，`--legacy` 时额外扫描传统地址。
    let mut kinds = vec![ScriptKind::P2wpkh];
    if legacy {
        kinds.push(ScriptKind::P2pkh);
    }
    let mut candidates: Vec<Selected> = Vec::new();
    for kind in kinds {
        let address = wallet.address(kind);
        let script = address.script_pubkey();
        for utxo in chain.utxos(&address.to_string()).await? {
            candidates.push(Selected {
                utxo,
                kind,
                script: script.clone(),
            });
        }
    }
    if candidates.is_empty() {
        bail!("地址 {} 上没有可用 UTXO", wallet.p2wpkh);
    }
    // 大额优先，尽量减少输入数量与交易体积。
    candidates.sort_by(|a, b| b.utxo.value.cmp(&a.utxo.value));

    // 2) 选币并估算手续费（先按「带找零输出」计算，不够再加输入）。
    let mut selected: Vec<Selected> = Vec::new();
    let mut total: u64 = 0;
    let mut fee: u64 = 0;
    for candidate in candidates {
        selected.push(candidate);
        total += selected.last().unwrap().utxo.value;
        fee = fee_for_vsize(
            estimate_vsize(&kinds_of(&selected), ScriptKind::P2wpkh, 2),
            rate,
        );
        if total >= amount_sat + fee {
            break;
        }
    }
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
        fee = total - amount_sat;
        output_count = 1;
    }
    let vsize_estimate = estimate_vsize(&kinds_of(&selected), ScriptKind::P2wpkh, output_count);

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
            previous_output: OutPoint {
                txid,
                vout: s.utxo.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        });
    }

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: vec![TxOut {
            value: Amount::from_sat(amount_sat),
            script_pubkey: to.script_pubkey(),
        }],
    };
    if change > 0 {
        tx.output.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: wallet.p2wpkh.script_pubkey(),
        });
    }

    // 4) 离线签名：每个输入按自己的脚本类型分别计算 sighash。
    let secp = Secp256k1::new();
    for (index, input) in selected.iter().enumerate() {
        match input.kind {
            ScriptKind::P2wpkh => sign_p2wpkh(
                &mut tx,
                index,
                &input.script,
                input.utxo.value,
                &wallet,
                &secp,
            )?,
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
        raw_hex: encode::serialize_hex(&tx),
        txid: tx.compute_txid().to_string(),
        from: wallet.p2wpkh.to_string(),
        to: to.to_string(),
        amount_sat,
        fee,
        fee_rate: rate,
        vsize: tx.vsize() as u64,
        vsize_estimate,
        change,
        inputs: info,
    })
}

/// 构造并广播一笔转账：`选币 -> 估算手续费 -> 本地签名 -> 广播`。
///
/// 私钥只参与本地签名，不会离开本进程。
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
    let built = build_transfer(chain, wif, to, amount_sat, fee_rate, legacy, rbf).await?;

    println!("from             : {}", built.from);
    println!("to               : {}", built.to);
    println!(
        "amount           : {} BTC ({} sat)",
        format_btc(built.amount_sat),
        built.amount_sat
    );
    println!("fee_rate         : {:.2} sat/vB", built.fee_rate);
    println!(
        "fee              : {} BTC ({} sat)",
        format_btc(built.fee),
        built.fee
    );
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
    for input in &built.inputs {
        println!(
            "  {}:{}  {} BTC{}",
            input.txid,
            input.vout,
            format_btc(input.value),
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
        return Ok(None);
    }

    // 5) 广播：配置了 bitcoind 时走自己的节点，否则走 Esplora。
    let txid = chain
        .broadcast(&built.raw_hex)
        .await
        .context("广播交易失败")?;
    println!("broadcast        : ok (via {})", chain.source());
    Ok(Some(txid))
}

fn kinds_of(selected: &[Selected]) -> Vec<ScriptKind> {
    selected.iter().map(|s| s.kind).collect()
}

/// 取「约 3 个区块确认」档位的推荐费率，取不到就用缺省值。
async fn recommended_fee_rate(chain: &Chain) -> f64 {
    match chain.fee_estimates().await {
        Ok(estimates) => estimates
            .iter()
            .find(|(target, _)| *target >= 3)
            .or_else(|| estimates.first())
            .map(|(_, rate)| *rate)
            .unwrap_or(DEFAULT_FEE_RATE),
        Err(_) => DEFAULT_FEE_RATE,
    }
}

/// P2WPKH 输入的 BIP143 签名（见证字段）。
fn sign_p2wpkh(
    tx: &mut Transaction,
    index: usize,
    script_pubkey: &ScriptBuf,
    value: u64,
    wallet: &Wallet,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<()> {
    let sighash = {
        let mut cache = SighashCache::new(&*tx);
        cache
            .p2wpkh_signature_hash(
                index,
                script_pubkey,
                Amount::from_sat(value),
                EcdsaSighashType::All,
            )
            .context("计算 P2WPKH sighash 失败")?
    };
    let message = Message::from_digest(sighash.to_byte_array());
    let signature = bitcoin::ecdsa::Signature::sighash_all(
        secp.sign_ecdsa(&message, &wallet.private_key.inner),
    );
    tx.input[index].witness = Witness::p2wpkh(&signature, &wallet.compressed.0);
    Ok(())
}

/// P2PKH 输入的传统签名（scriptSig = <DER 签名> <公钥>）。
fn sign_p2pkh(
    tx: &mut Transaction,
    index: usize,
    script_pubkey: &ScriptBuf,
    wallet: &Wallet,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<()> {
    let sighash = SighashCache::new(&*tx)
        .legacy_signature_hash(index, script_pubkey, EcdsaSighashType::All.to_u32())
        .context("计算 P2PKH sighash 失败")?;
    let message = Message::from_digest(sighash.to_byte_array());
    let signature = bitcoin::ecdsa::Signature::sighash_all(
        secp.sign_ecdsa(&message, &wallet.private_key.inner),
    );

    let mut sig_bytes = PushBytesBuf::new();
    sig_bytes
        .extend_from_slice(&signature.serialize())
        .context("签名长度超出脚本推送上限")?;
    let mut pubkey_bytes = PushBytesBuf::new();
    pubkey_bytes
        .extend_from_slice(&wallet.public_key.inner.serialize())
        .context("公钥长度超出脚本推送上限")?;

    tx.input[index].script_sig = ScriptBuf::builder()
        .push_slice(sig_bytes)
        .push_slice(pubkey_bytes)
        .into_script();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_WIF: &str = "L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy";

    fn test_wallet() -> Wallet {
        Wallet::from_wif(TEST_WIF, Network::Bitcoin).unwrap()
    }

    fn test_tx(input_script: &ScriptBuf) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(
                        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: input_script.clone(),
            }],
        }
    }

    #[test]
    fn derives_expected_addresses() {
        let wallet = test_wallet();
        assert!(wallet.p2wpkh.to_string().starts_with("bc1q"));
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
        let unsigned = tx.clone();
        sign_p2wpkh(&mut tx, 0, &script, value, &wallet, &secp).unwrap();

        let witness = tx.input[0].witness.to_vec();
        assert_eq!(witness.len(), 2);
        assert_eq!(witness[1], wallet.compressed.0.serialize());

        let sig = bitcoin::ecdsa::Signature::from_slice(&witness[0]).unwrap();
        assert_eq!(sig.sighash_type, EcdsaSighashType::All);

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
        assert!(script_sig.ends_with(&wallet.public_key.inner.serialize()));

        let pushed = bitcoin::Script::from_bytes(script_sig);
        let mut instructions = pushed.instructions();
        let sig = match instructions.next().unwrap().unwrap() {
            bitcoin::script::Instruction::PushBytes(bytes) => {
                bitcoin::ecdsa::Signature::from_slice(bytes.as_bytes()).unwrap()
            }
            other => panic!("scriptSig 首项不是签名: {other:?}"),
        };

        let sighash = SighashCache::new(&unsigned)
            .legacy_signature_hash(0, &script, EcdsaSighashType::All.to_u32())
            .unwrap();
        let message = Message::from_digest(sighash.to_byte_array());
        assert!(
            secp.verify_ecdsa(&message, &sig.signature, &wallet.public_key.inner)
                .is_ok()
        );
    }
}
