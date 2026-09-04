//! 密钥管理与转账交易构造、签名、广播。
//!
//! ## Solana 密钥模型
//! Solana 的账户身份就是一条 **ed25519 密钥对**的公钥，「地址」= 公钥的 base58 编码，
//! 二者是同一个字符串（这一点与 ETH 那种「公钥再哈希取后 20 字节」的模型完全不同）。
//! 官方 CLI 的 keypair 文件存的是 **64 字节**：前 32 字节是种子（seed），
//! 后 32 字节是对应的公钥，所以私钥文件本身就自带地址，无需再推导。
//!
//! ## 签名流程
//! 一笔转账需要三样东西：SystemProgram.transfer 指令、付款方密钥对、
//! 以及一个**近期 blockhash**（Solana 用它替代 nonce 做防重放，
//! 交易锚定的 blockhash 若早于最近 150 个块，节点会直接拒绝）。
//! 因此构造交易前必须先向节点要一次 `get_latest_blockhash`——
//! 这也是本模块里唯一需要联网的一步，其余（指令构造、签名）都是纯本地计算。

// `Path` 是**路径切片类型**（类似 `str` 之于 `String`）：它本身不拥有数据，
// 只借用一段路径字符串。用它做参数类型意味着「我只需要读一下这个路径，
// 不需要把它存下来」，于是调用方既能传 `&str` 也能传 `&PathBuf`（后者会自动解引用成 `&Path`）。
use std::path::Path;
// `FromStr` 是标准库的 trait，提供 `.parse()` 的能力。
// 注意：它必须被 `use` 进来（在作用域内）才能对某类型调用 `.parse()`——
// 这是 Rust「trait 方法必须先引入 trait」规则的一个典型例子。
use std::str::FromStr;

// anyhow 三件套：
// - `Result`   → `Result<T, anyhow::Error>` 的别名；
// - `Context`  → trait，给错误**附加上下文**，提供 `.context(..)` 与 `.with_context(..)` 两个方法；
// - `bail!`    → 宏，等价于 `return Err(anyhow!(..))`。
//
// `.context("静态文案")` 直接吃一个 `Display` 值；
// `.with_context(|| format!(..))` 吃一个**闭包**，需要拼接字符串时才用它——
// 因为闭包只在真的出错时才会被调用，成功路径上不付 format! 的开销。
use anyhow::{Context, Result, bail};
// 密钥对类型：内部持有 32 字节种子，公钥由种子推导而来。
use solana_keypair::Keypair;
// `Message` 是「账户表 + 指令列表」的编译结果，`serialize()` 产出的线格式字节
// 就是 ed25519 真正签名作用其上的内容。
use solana_message::Message;
// `Hash` 即 32 字节 blockhash，Solana 用它替代 nonce 做防重放。
use solana_hash::Hash;
// `Pubkey`：32 字节公钥的**可复制**包装类型（实现了 `Copy`），`Display` 即 base58 地址。
use solana_pubkey::Pubkey;
// 同步阻塞的 JSON-RPC 客户端（阻塞语义见 cluster.rs 的说明）。
use solana_rpc_client::rpc_client::RpcClient;
// `Signer` trait：提供 `pubkey()` 与 `sign()`。必须 `use` 进来才能对 `Keypair` 调用这些方法。
use solana_signer::Signer;
// SystemProgram 的 transfer 指令构造器，本模块转账的核心。
use solana_system_interface::instruction::transfer;
// 已签名/未签名交易的容器类型。
use solana_transaction::Transaction;

/// 生成新的 ed25519 密钥对。
///
/// 内部使用操作系统的密码学随机数发生器，**纯本地、不联网**。
/// 返回的密钥对只存在于内存，需要持久化请配合 [`keypair_to_json`]。
pub fn keygen() -> Keypair {
    Keypair::new()
}

/// 以 Solana CLI 兼容格式导出：JSON 数组形式的 64 字节。
///
/// 产出形如 `[12,34,...]`（共 64 个 0-255 的整数），与
/// `solana-keygen new` 生成的 `~/.config/solana/id.json` 完全一致，
/// 因此本 SDK 生成的密钥可以直接被官方 CLI 使用。
pub fn keypair_to_json(keypair: &Keypair) -> String {
    // `to_bytes()` 返回 `[u8; 64]`（定长数组），`.to_vec()` 转成 `Vec<u8>`，
    // 因为 serde 只为 `Vec<u8>` 生成「JSON 数组」的序列化实现，
    // 定长数组在旧版 serde 里会被序列化成元组形式。
    //
    // 为什么这里敢用 `.expect(..)`：`Vec<u8>` 序列化成 JSON **不可能失败**
    // （没有 NaN、没有 map 的非字符串键、没有递归深度问题）。
    // 用 `expect` 而不是 `?` 是为了让函数签名保持返回 `String` 而非 `Result<String>`，
    // 不把「不可能发生的失败」抛给调用方——代价是万一判断错了会 panic。
    serde_json::to_string(&keypair.to_bytes().to_vec()).expect("序列化密钥字节数组")
}

/// 密钥字节长度（种子 32 + 公钥 32），与 `Keypair::to_bytes` 一致。
pub const KEYPAIR_LENGTH: usize = 64;

/// 从多种输入解析私钥：
/// - JSON 数组（`[12,34,...]`，Solana CLI 的 keypair 文件格式）
/// - base58 编码的 64 字节
pub fn parse_keypair(input: &str) -> Result<Keypair> {
    // `trim()` 去首尾空白。必须做：私钥常从文件里读出来，末尾会带换行符 `\n`，
    // 不 trim 的话下面的 `starts_with('[')` / base58 解码都会失败。
    let raw = input.trim();
    // 用首字符判断格式。JSON 数组一定以 `[` 开头，base58 字母表里不含 `[`，
    // 因此这个判断是无歧义的——比「先试 JSON、失败再试 base58」更明确，
    // 也避免了把一段合法的（虽然不可能是密钥的）输入误判。
    if raw.starts_with('[') {
        // 变量标注 `let bytes: Vec<u8>` 告诉 `from_str` 要反序列化成什么类型；
        // `.context(..)` 在解析失败时把 serde 的报错包上一层中文说明。
        let bytes: Vec<u8> = serde_json::from_str(raw).context("解析 JSON 数组形式的私钥失败")?;
        // `return` 提前返回，避开下面 base58 那条路径（两个分支是互斥的）。
        return keypair_from_bytes(&bytes);
    }
    // 非 JSON 则按 base58 处理（这是 solana 官方 `Keypair::from_base58_string` 接受的格式）。
    let bytes = bs58_decode(raw).context("解析 base58 私钥失败")?;
    // 末行无分号 = 返回值，这里返回 `keypair_from_bytes(..)` 的结果。
    keypair_from_bytes(&bytes)
}

/// 从文件读取私钥（Solana CLI 的 `~/.config/solana/id.json` 格式）。
pub fn load_keypair_file(path: &Path) -> Result<Keypair> {
    // `read_to_string` 一次性把整个文件读成 `String`（不适合超大文件，密钥文件只有几百字节）。
    // `with_context` 的闭包形式：只在出错时才执行 `format!` 与 `path.display()`。
    // `path.display()` 把 `&Path` 转成可 `Display` 的值——`Path` 本身不实现 `Display`
    // （因为路径可能是非 UTF-8 字节序列，直接打印不安全），`display()` 会做有损但安全的替换。
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("读取密钥文件失败: {}", path.display()))?;
    parse_keypair(&content)
}

/// 由 64 字节还原密钥。solana-keypair 3.1 只暴露 base58 构造，因此先编码再转换。
///
/// 语法说明：参数 `bytes: &[u8]` 是**字节切片**（`&[u8]` 读作 "ref to u8 slice"）。
/// 它比 `&Vec<u8>` 更通用：`Vec<u8>`、数组 `[u8; N]`、以及它们的任意子区间
/// 都能**自动强制转换**（deref coercion）成 `&[u8]`，所以这里用切片是最宽松的选择。
fn keypair_from_bytes(bytes: &[u8]) -> Result<Keypair> {
    if bytes.len() != KEYPAIR_LENGTH {
        // `bail!` = `return Err(anyhow!(..))`。
        // 长度必须先校验：越界字节传进底层会 panic 或产生不可预期的密钥，
        // 在这里拦下来才能给出可读的中文错误。
        bail!(
            "私钥长度应为 {} 字节，实际 {} 字节",
            KEYPAIR_LENGTH,
            bytes.len()
        );
    }
    // 官方 API 只接受 base58 字符串，于是先把字节编码回 base58 再交给它
    // （一次绕路，换来不必依赖 `Keypair::try_from` 这类不稳定接口）。
    Ok(Keypair::from_base58_string(&bs58_encode(bytes)))
}

/// 一笔本地构造并签名、尚未广播的转账。
///
/// 把「构造结果」整体返回而不是直接广播，是为了支持 **dry-run**：
/// 调用方可以先拿到 `signature`（这笔交易应有的签名）与 `recent_blockhash` 做校验/展示，
/// 再自行决定是否调用 `send_and_confirm_transaction`。adapter 层正是这么用的。
pub struct BuiltTx {
    /// 已签名的交易体，可直接交给 `send_and_confirm_transaction` 广播。
    pub tx: Transaction,
    /// 交易签名（Solana 里它同时就是「交易哈希 / txid」，与 ETH 的哈希不是一回事但地位相同）。
    pub signature: solana_signature::Signature,
    /// 付款方公钥（由密钥对推导）。
    pub from: Pubkey,
    /// 收款方公钥。
    pub to: Pubkey,
    /// 转账金额，单位 lamport。
    pub lamports: u64,
    /// 交易锚定的近期 blockhash（字符串形式，便于直接展示）。
    pub recent_blockhash: String,
}

/// 构造并签名 SystemProgram.transfer（不打印不广播）。
///
/// 私钥只参与本地签名；返回的交易可交给调用方决定广播或丢弃（dry-run）。
pub fn build_signed_transfer(
    client: &RpcClient,
    keypair: &Keypair,
    to: &Pubkey,
    lamports: u64,
) -> Result<BuiltTx> {
    // `pubkey()` 是 `Signer` trait 的方法（已在文件头 `use` 进来）。
    // 返回值是 `Pubkey`，它是 `Copy` 的，所以这里拿到的是一份副本，不涉及所有权转移。
    let from = keypair.pubkey();
    // SystemProgram.transfer 是 Solana 原生转账的唯一指令：
    // 它直接改两个账户的 lamport 余额，**不涉及任何合约代码**。
    // 参数顺序是 (from, to, lamports)，注意与直觉相反——不是 (to, amount)。
    let instruction = transfer(&from, to, lamports);
    // 联网第一步（也是唯一一步）：取最新 blockhash。
    //
    // Solana 用 blockhash 做防重放：交易必须锚定最近 150 个块内的 blockhash，
    // 超出则节点直接拒绝（报 `BlockhashNotFound`）。
    // 这与 ETH 的 nonce 机制不同——**同一账户并发发交易不会互相顶掉**，
    // 但代价是必须先联网拿这个哈希，无法完全离线构造。
    let blockhash = client
        .get_latest_blockhash()
        .context("获取最新 blockhash 失败")?;

    // 一次性完成「打包指令 + 指定 fee payer + 用密钥对签名 + 写入 blockhash」。
    // - 第二个参数 `Some(&from)` 指定 **fee payer**（手续费支付者），这里即付款方；
    //   传 `None` 表示由签名者中的第一个充当，显式写出可读性更好。
    // - 第四个参数 `&[keypair]` 是签名者列表：Solana 的交易要求**指令里涉及的所有
    //   需要签名的账户**都提供签名者，多签场景这里会有多个。
    let tx = Transaction::new_signed_with_payer(&[instruction], Some(&from), &[keypair], blockhash);

    // 取第一个签名（单签名交易只有一个）。
    // - `.first()` 返回 `Option<&Signature>`；
    // - `.copied()` 是 `Option<&T>` 的便捷方法，等价于 `.map(|x| *x)`，
    //   把 `Option<&Signature>` 变成 `Option<Signature>`（依赖 `Signature: Copy`）。
    //   对比 `.cloned()`：那是给 `T: Clone` 用的，这里 `Copy` 更轻。
    // - `.unwrap_or_default()`：为空时取 `Signature` 的 `Default` 值（全零签名）。
    //   理论上不会发生——单签名交易必有且仅有一个签名槽位。
    let signature = tx.signatures.first().copied().unwrap_or_default();
    Ok(BuiltTx {
        tx,
        signature,
        from,
        // `*to`：**解引用**。`to` 是 `&Pubkey`，而字段要求 `Pubkey` 值；
        // 因为 `Pubkey: Copy`，解引用是一次按位复制，不会把 `to` 借走（不构成 move）。
        to: *to,
        lamports,
        recent_blockhash: blockhash.to_string(),
    })
}

/// **无私钥**构造出的一笔转账：待签消息 + 待组装的未签名交易。
///
/// 领域说明（Solana 的两个「不同字节串」，务必分清）：
/// - `signing_payload` = `Message::serialize()`，即线格式消息。
///   它是 **ed25519 真正作用其上的字节**——Solana 不做二次哈希，
///   直接对这串字节签名（ed25519 内部自带 SHA-512 摘要）。
/// - `unsigned_tx`     = bincode 序列化的 `Transaction`，其 `signatures[0]`
///   是一段**全零占位**。它比消息多一层外壳（签名槽位），
///   是签名方「把签名填回去」所需的基底。
///
/// 两者是**包含关系**而非相等关系：签名方拿到 `unsigned_tx` 后，
/// 从中取出 message 序列化得 `signing_payload`，签名，再把签名写回 `signatures[0]`。
/// 因此我们必须两个都交出去，否则签名方无法闭环。
pub struct UnsignedTransfer {
    /// bincode 序列化的未签名 `Transaction`（带全零占位签名），十六进制。
    ///
    /// 与 `../sign` 程序 `signtx(chaintype="sol")` 的输入格式一致：
    /// 那边用 `bincode::deserialize::<Transaction>` 解它，两者互为逆运算。
    pub unsigned_tx_hex: String,
    /// 真正要签的字节：`Message::serialize()`，十六进制。
    pub signing_payload_hex: String,
    /// 交易锚定的近期 blockhash（防重放，有效期约 150 个块）。
    pub recent_blockhash: String,
    /// 付款方公钥（base58）。
    pub from: Pubkey,
    /// 收款方公钥（base58）。
    pub to: Pubkey,
    /// 转账金额，单位 lamport。
    pub lamports: u64,
}

/// 由 blockhash 组装出待签交易。**纯函数，不访问网络**。
///
/// 与「联网取 blockhash」拆开，是为了让最有业务风险的一步（消息编译、
/// 待签字节口径、交易外壳序列化）变成**可离线测试**的——
/// 否则要测它就得连公共 RPC，网络抖动会变成假失败。
fn assemble_unsigned(
    blockhash: Hash,
    from: &Pubkey,
    to: &Pubkey,
    lamports: u64,
) -> Result<UnsignedTransfer> {
    let instruction = transfer(from, to, lamports);

    // 必须用 `new_with_blockhash` 而不是 `new`——这是一个**真实踩过的坑**：
    // `Message::new` 产出的 message 里 `recent_blockhash` 是**全零占位**，
    // blockhash 直到 `Transaction::sign` 时才被写进去。
    // 于是若这里用 `new`，我们交出去的待签字节锚定的是零 blockhash，
    // 而 `recent_blockhash` 字段却报着真实值——两者不一致。
    // 其后果是：调用方签出来的交易对一个「零 blockhash」的消息签名，
    // 节点会以 BlockhashNotFound 拒绝，而本地怎么自测都发现不了
    // （签名对任何字节都成立）。这正是测试
    // `signing_payload_matches_official_signing_path` 要防的事。
    let message = Message::new_with_blockhash(&[instruction], Some(from), &blockhash);
    // 真正要签的字节。**不要**换成 serde/bincode 编码——
    // 虽然 `ShortVec` 的 serde 实现恰好与线格式一致（见 ../sign 的测试），
    // 但 `serialize()` 才是官方 `Transaction::try_partial_sign` 内部用的那一个，
    // 语义明确且不依赖 serde feature。
    let signing_payload = message.serialize();

    // `new_unsigned` 会按 `num_required_signatures` 生成对应个数的**全零占位签名**。
    // 这正是各钱包适配器之间交换「待签交易」的通用形态。
    let tx = Transaction::new_unsigned(message);
    let unsigned_tx =
        bincode::serialize(&tx).context("序列化未签名交易失败（需 solana-transaction 的 serde feature）")?;

    Ok(UnsignedTransfer {
        unsigned_tx_hex: format!("0x{}", hex::encode(&unsigned_tx)),
        signing_payload_hex: format!("0x{}", hex::encode(&signing_payload)),
        recent_blockhash: blockhash.to_string(),
        from: *from,
        to: *to,
        lamports,
    })
}

/// **无私钥**构造一笔转账：取最新 blockhash、组装指令，产出待签消息与未签名交易。
///
/// 与 [`build_signed_transfer`] 的关系：后者多走一步本地签名，
/// 本函数则停在「待签」处，把字节交给调用方——私钥不进入本进程。
///
/// 领域说明：`from` 在这里只用于**构造指令**（SystemProgram.transfer 需要付款方账户）
/// 与充当 fee payer，**不做任何权限校验**。无私钥就无法证明调用方拥有该地址；
/// 安全性由签名环节保障：没有私钥就签不出节点能接受的签名。
pub fn build_unsigned_transfer(
    client: &RpcClient,
    from: &Pubkey,
    to: &Pubkey,
    lamports: u64,
) -> Result<UnsignedTransfer> {
    // 联网取 blockhash：Solana 用它替代 nonce 做防重放，
    // 锚定的 blockhash 若早于最近 150 个块，节点会直接拒绝。
    // 这是本函数唯一需要联网的一步，也是「无法完全离线构造」的原因。
    let blockhash = client
        .get_latest_blockhash()
        .context("获取最新 blockhash 失败")?;
    assemble_unsigned(blockhash, from, to, lamports)
}

/// 广播**已签名**的交易字节，返回签名（Solana 里签名即 txid）。
///
/// 领域说明：与 ETH 不同，Solana 的交易标识不是哈希而是**签名本身**——
/// 因为签名是确定性的，同一笔交易签名唯一，天然可作标识。
///
/// 本函数只做 `send_transaction`，**不等待确认**。
/// 广播成功 ≠ 落块：交易可能因 blockhash 过期或余额不足而被丢弃，
/// 要确认结果请用 `tx()` 查签名状态。
pub fn broadcast_raw(client: &RpcClient, raw: &[u8]) -> Result<solana_signature::Signature> {
    // 先反序列化成 `Transaction`：这一步顺带校验字节结构是否合法，
    // 畸形输入会在本地报错，而不是发出一个注定被拒的请求。
    let tx: Transaction = bincode::deserialize(raw).context("解析已签名交易失败")?;
    client
        .send_transaction(&tx)
        .context("广播交易失败（blockhash 可能已过期，或账户余额不足）")
}

/// 转账：构造 SystemProgram.transfer 指令 -> 用最新 blockhash 签名 -> 广播并等待确认。
///
/// `dry_run` 为 true 时只签名并打印，不广播。
pub fn send_tx(
    client: &RpcClient,
    keypair: &Keypair,
    to: &Pubkey,
    lamports: u64,
    dry_run: bool,
) -> Result<solana_signature::Signature> {
    // 复用构造逻辑：先本地构造并签名，再决定是否广播。
    // 这样 dry-run 与真发走的是**同一条构造路径**，不会出现「试跑正常、真发出问题」的偏差。
    let built = build_signed_transfer(client, keypair, to, lamports)?;

    println!("from             : {}", built.from);
    println!("to               : {}", built.to);
    println!("lamports         : {}", built.lamports);
    println!("recent_blockhash : {}", built.recent_blockhash);
    println!("signature        : {}", built.signature);

    if dry_run {
        println!("# dry-run 模式：未广播");
        // 提前返回：**不**广播，只把本地签名结果交回调用方。
        // 注意返回的签名是真实有效的——同一笔交易稍后再广播依然能被接受
        // （只要 blockhash 还没过期）。
        return Ok(built.signature);
    }

    // `send_and_confirm_transaction` 是**阻塞**调用：它先广播，再轮询
    // `getSignatureStatuses` 直到交易达到客户端默认的 commitment（或超时）。
    // 耗时通常在几百毫秒到几十秒，绝不能在 async 运行时的工作线程里直接调用。
    let confirmed = client
        .send_and_confirm_transaction(&built.tx)
        .context("广播交易失败（账户可能不存在或余额不足）")?;
    println!("confirmed        : {confirmed}");
    Ok(confirmed)
}

/// 解析地址字符串。
///
/// `Pubkey::from_str` 接受 base58 形式（32 字节解码后），
/// 会自动校验长度并拒绝含 base58 字母表外字符（如 `0` / `O` / `I` / `l`）的输入。
pub fn parse_pubkey(raw: &str) -> Result<Pubkey> {
    // `with_context` 的闭包里同时用到了 `raw`（未 trim 的原串），
    // 便于用户对照自己到底输入了什么——错误回显「原始输入」比回显处理结果更有用。
    Pubkey::from_str(raw.trim()).with_context(|| format!("非法地址: {raw}"))
}

/// 极简 base58 解码（仅用于解析 base58 私钥，避免额外依赖）。
///
/// ## 为什么不直接引 `bs58` crate
/// NEAR 那边已经引了 `bs58`，但 SOL 这一侧只需要「解码私钥 / 编码还原 Keypair」
/// 两个方向，一共几十行。为了这两处再拉一个外部依赖（连带它的传递依赖）
/// 不划算，因此手写一份**够用即可**的实现。
/// 注意它的定位是「解析用户输入的密钥」，**没有校验和**（Bitcoin 的 Base58Check
/// 带 4 字节校验和，Solana 的地址/密钥不带），所以无法检测「输错一个字符」这类错误。
///
/// ## 算法
/// base58 本质是一个 **58 进制的大整数**，把 256 进制的字节流当成一个大数反复
/// 「乘 58 加当前位」即可（即课本上的 Horner 法则）。
/// 由于大数可能上千位，这里用 `Vec<u8>` 手工维护这个大数的字节表示，
/// 从**低位到高位**存放（小端），每轮做一次「乘 58 + 加数位」的多精度运算。
///
/// 字母表刻意去掉了 4 个容易混淆的字符：`0`（零）、`O`（大写 o）、`I`（大写 i）、`l`（小写 L）。
pub fn bs58_decode(input: &str) -> Result<Vec<u8>> {
    // `b"..."` 是**字节串字面量**，类型是 `&[u8; 58]`；
    // 标注成 `&[u8]` 后定长数组被**强制转换**成切片，长度信息被擦除。
    // `const` 定义在函数体内是合法的，作用域仅限本函数，不会污染模块命名空间。
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // `out` 保存当前累积的大数（小端字节序：`out[0]` 是最低有效字节）。
    let mut out: Vec<u8> = Vec::new();
    // `.chars()` 迭代 Unicode 字符（base58 输入应当全是 ASCII，但用 chars 更安全）。
    for ch in input.chars() {
        // base58 里 `'1'` 代表数值 0，而**前导的 1 == 前导的零字节**。
        // 大数表示法会自动丢掉高位的零，所以这里先跳过，最后按个数统一补回。
        // 条件里的 `out.is_empty()` 很关键：只有还**没产生任何有效数字**时的 '1'
        // 才算前导零；中间出现的 '1' 是要参与运算的真数位（值为 0）。
        if ch == '1' && out.is_empty() {
            // 前导 1 表示 0 字节
            continue;
        }
        // 查表得到当前字符的数值 0..57：
        // - `.iter()` 产出 `&u8`（对 `&[u8]` 迭代得到引用）；
        // - 闭包参数写 `|&c|` 是**解构模式**：把 `&u8` 直接解成 `u8`（要求 `u8: Copy`），
        //   于是闭包内 `c` 就是 `u8`，不必写 `*c`；
        // - `.position(..)` 返回 `Option<usize>`（第一个满足条件的下标）；
        // - `.ok_or_else(|| ..)` 把 `None`（没找到 = 非法字符）转成 anyhow 错误，
        //   闭包形式保证只有真出错时才构造错误字符串。
        //
        // 注意 `ch as u8` 会**截断**非 ASCII 字符的码点：全角字符可能碰巧截到
        // 字母表内的字节值而被误判为合法。对本函数的使用场景（解析本地密钥文件）
        // 可接受，但若将来要处理任意外部输入，这里应先判 `ch.is_ascii()`。
        let value = ALPHABET
            .iter()
            .position(|&c| c == (ch as u8))
            .ok_or_else(|| anyhow::anyhow!("base58 中出现非法字符: {ch}"))?;
        // 下面是「大数 = 大数 * 58 + value」，carry 是跨字节的进位。
        // 用 `u32` 而不是 `u8`：单次乘法最大为 255 * 58 + 255 = 15045，远超 u8。
        let mut carry = value as u32;
        // `.iter_mut()` 产出 `&mut u8`（可变引用），`.rev()` 反向迭代——
        // 必须从**低位字节**往高位走，进位才能正确向高位传播。
        for byte in out.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            // 取低 8 位写回当前字节；`& 0xff` 等价于 `% 256`，位运算更快。
            *byte = (carry & 0xff) as u8;
            // 右移 8 位 = 除以 256，把进位留给下一个（更高的）字节。
            carry >>= 8;
        }
        // 乘完 58 之后仍有进位：说明大数需要**新增高位字节**，
        // 从低到高依次 `insert(0, ..)` 插到头部。
        // （`Vec::insert(0, ..)` 是 O(n) 的，但每轮最多新增 1-2 字节，可接受。）
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // 补齐前导零字节
    // `.take_while(|&c| c == '1')` 从头开始取连续的前导 '1' 并计数。
    // 注意闭包参数是 `|&c|`：`chars()` 产出 `char`，这里因解构而写成 `&c`——
    // 实际是 `Iterator<Item = char>` 上 `.take_while` 的闭包签名 `&char`，
    // 解构成 `char`。写成 `|c| c == &'1'` 是等价的另一种写法。
    let leading = input.chars().take_while(|&c| c == '1').count();
    // `vec![0u8; leading]` 是 **vec! 宏的重复形式**：造 `leading` 个 `0u8`。
    // 这里的 `0u8` 明确标注元素类型，避免整数字面量类型被推导成默认的 `i32`。
    let mut result = vec![0u8; leading];
    // `extend(..)` 把 `out` 的所有元素**移动到** result 尾部。
    // 参数是 `IntoIterator<Item = u8>`，`Vec<u8>` 本身满足，于是 `out` 在此被消耗（move）。
    result.extend(out);
    Ok(result)
}

/// base58 编码（用于由字节还原 Keypair，也用于测试中的往返验证）。
///
/// 与 [`bs58_decode`] 对称，算法是它的逆过程：把字节流看成 256 进制大数，
/// 反复「除以 58 取余数」得到 58 进制的各位数字，再映射回字母表。
/// 因为是从低位开始取余，最后得到的数字序列天然是**从高位到低位**的顺序，无需反转。
pub fn bs58_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // 注意 `digits` 里存的是**字母表下标 0..57**，不是 ASCII 字节——
    // 最后一步才映射成字符。这与 decode 里的 `out`（存真实字节）不同，别混淆。
    let mut digits: Vec<u8> = Vec::new();
    // `for &byte in bytes`：对 `&[u8]` 迭代得到 `&u8`，用 `&byte` 解构成 `u8`。
    for &byte in bytes {
        // 新字节相当于「大数 = 大数 * 256 + byte」，carry 初始即这个新字节的值。
        let mut carry = byte as u32;
        // 从**最低位数字**开始做除法：每位数字 *= 256，加上来自低位的进位，
        // 再除以 58 —— 商留作进位传给更高位，余数即本位的 58 进制数字。
        for d in digits.iter_mut().rev() {
            carry += (*d as u32) * 256;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        // 除完仍有商：需要在**最高位之前**新增数字位。
        while carry > 0 {
            digits.insert(0, (carry % 58) as u8);
            carry /= 58;
        }
    }
    // 前导零字节 → 前导 '1'（与 decode 的前导 '1' 处理严格互逆）。
    // `bytes.iter()` 产出 `&u8`，而 take_while 的闭包拿到的是 `&&u8`，
    // 所以写成 `|&&b| b == 0`——两层 `&` 分别对应「迭代器的引用」与「元素本身是引用」。
    let leading = bytes.iter().take_while(|&&b| b == 0).count();
    // `"1".repeat(leading)`：字符串重复，返回新的 `String`。
    // `let mut out` 是因为下面要 `push`。
    let mut out = "1".repeat(leading);
    // `for d in digits`：**按值**消耗 digits（不是 `&digits`），每轮拿到 `u8` 的所有权。
    for d in digits {
        // `ALPHABET[d as usize]` 取出 ASCII 字节，再 `as char` 转成字符。
        // 这个 `as char` 是安全的：u8 一定能表示一个 Unicode 标量值（Latin-1 范围）。
        out.push(ALPHABET[d as usize] as char);
    }
    // 末行无分号 = 返回 `out`。
    out
}

/// 单元测试模块。
///
/// 语法说明：`#[cfg(test)]` 表示只有 `cargo test` 时才编译；
/// `use super::*` 把父模块（本文件）的全部条目导入，于是可直接写 `keygen()`。
///
/// 这些测试全部**离线**：密钥生成与 base58 编解码都是纯计算，不触碰网络，
/// 因此它们跑得极快且不会因公共节点限流而 flaky。
#[cfg(test)]
mod tests {
    use super::*;

    /// JSON 数组格式的密钥导出后应能被原样解析回来，且推导出同一个公钥。
    #[test]
    fn keypair_json_round_trip() {
        let keypair = keygen();
        let json = keypair_to_json(&keypair);
        let restored = parse_keypair(&json).unwrap();
        // 不能比较私钥字节是否相等（不同表示的同一密钥），只能比公钥是否一致：
        // 公钥相同即说明还原出的是同一条 ed25519 密钥。
        assert_eq!(restored.pubkey(), keypair.pubkey());
    }

    /// base58 格式同样支持往返。
    #[test]
    fn keypair_base58_round_trip() {
        let keypair = keygen();
        // `keypair.to_bytes()` 是 64 字节，编码后应能被 `parse_keypair` 解析。
        let b58 = bs58_encode(&keypair.to_bytes());
        let restored = parse_keypair(&b58).unwrap();
        assert_eq!(restored.pubkey(), keypair.pubkey());
    }

    /// 非法私钥必须报错，而不是产生一个「看起来能用」的错误密钥。
    #[test]
    fn rejects_invalid_keypair() {
        // 连字符 `-` 不在 base58 字母表内，解码第一步就会失败。
        assert!(parse_keypair("not-a-key").is_err());
        // 合法的 JSON 数组，但长度只有 3 字节 -> 应被 `KEYPAIR_LENGTH` 校验拦下。
        //
        // `assert!(cond, "消息")` 的第二个参数会在失败时一并打印，用来说明**为什么**这条该失败。
        assert!(parse_keypair("[1,2,3]").is_err(), "长度不足应报错");
    }

    #[test]
    fn parses_known_addresses() {
        // 系统程序地址是 32 个零字节
        let system = parse_pubkey("11111111111111111111111111111111").unwrap();
        assert_eq!(system, Pubkey::default());
    }

    /// 长度校验的边界：完整的 64 字节可以，截断到 32 字节必须拒绝。
    #[test]
    fn keypair_length_is_validated() {
        let keypair = keygen();
        let full = keypair.to_bytes();
        assert!(keypair_from_bytes(&full).is_ok(), "完整 64 字节应可还原");
        // `&full[..32]` 是**区间索引**（range indexing），取前 32 个字节的切片。
        // 这正是「只给种子、丢了公钥」的常见误用，必须报错。
        assert!(
            keypair_from_bytes(&full[..32]).is_err(),
            "截断到 32 字节应报错"
        );
    }

    // ---- 无私钥构造（`build_transfer` 的底座）----
    //
    // 与 ETH 的做法一致：断言只基于 `assemble_unsigned` **真正交出去的字符串**，
    // 不在测试里重算序列化。判据则取自**官方签名路径**——
    // 我们声称的待签字节，必须让「手动签名」与「官方 tx.sign()」得到同一个签名。

    /// 用固定 blockhash 与确定性地址组装，绕开网络。
    fn fixed_unsigned() -> UnsignedTransfer {
        assemble_unsigned(
            Hash::new_from_array([0x5c; 32]),
            &Pubkey::new_from_array([0x11; 32]),
            &Pubkey::new_from_array([0x22; 32]),
            1_000_000,
        )
        .expect("固定输入应能组装成功")
    }

    /// 剥掉 `0x` 前缀后解出字节。
    fn decode_prefixed(raw: &str) -> Vec<u8> {
        hex::decode(raw.trim_start_matches("0x")).expect("应为合法十六进制")
    }

    /// 交出去的待签字节，必须与**官方签名路径**签的是同一串。
    ///
    /// 判据的构造方式（关键）：
    ///   1. 走官方 `Transaction::sign`，得到 `official_sig`；
    ///   2. 手动对我们自己声明的 `signing_payload_hex` 做 ed25519 签名，得到 `manual_sig`；
    ///   3. 两者必须相等。
    ///
    /// 若我们交出去的字节串有任何偏差（少了类型标志、字段顺序错、多算了哈希…），
    /// 两个签名会立刻分叉。这比「自己再算一遍 keccak/序列化」强得多——
    /// 那是拿实现验证实现，这里拿的是官方路径作真值。
    #[test]
    fn signing_payload_matches_official_signing_path() {
        let keypair = Keypair::new();
        // 付款方取真实密钥对的公钥，这样官方签名时签名槽位才对得上。
        let u = assemble_unsigned(
            Hash::new_from_array([0x5c; 32]),
            &keypair.pubkey(),
            &Pubkey::new_from_array([0x22; 32]),
            1_000_000,
        )
        .expect("应能组装");

        // 路径 A：官方。反序列化我们交出去的交易外壳，再走官方 sign。
        let mut tx: Transaction =
            bincode::deserialize(&decode_prefixed(&u.unsigned_tx_hex)).expect("外壳应可被反序列化");
        // 占位签名必须先被清成全零——这正是「未签名」的应有形态。
        assert!(
            tx.signatures[0].as_ref().iter().all(|b| *b == 0),
            "未签名交易的 signatures[0] 应为全零占位"
        );
        let blockhash = Hash::new_from_array([0x5c; 32]);
        tx.sign(&[&keypair], blockhash);
        let official_sig = tx.signatures[0];

        // 路径 B：手动对我们声明的待签字节签名。
        let manual_sig = keypair.sign_message(&decode_prefixed(&u.signing_payload_hex));

        assert_eq!(
            official_sig.as_ref().to_vec(),
            manual_sig.as_ref().to_vec(),
            "声明的待签字节与官方签名路径不一致"
        );
    }

    /// 交易外壳必须能被 `bincode::deserialize::<Transaction>` 原样解回。
    ///
    /// 这是**跨进程契约**：`../sign` 程序的 `signtx(chaintype="sol")`
    /// 正是这么解析我们交出去的字节。保留完整往返（解码→重编码→逐字节相等），
    /// 可同时排除「字段丢失」与「长度前缀写错」两类问题。
    #[test]
    fn unsigned_tx_round_trips_through_bincode() {
        let u = fixed_unsigned();
        let bytes = decode_prefixed(&u.unsigned_tx_hex);

        let tx: Transaction = bincode::deserialize(&bytes).expect("外壳应可被反序列化");
        // 解出来的交易，其 message 序列化后必须与声明的待签字节一致——
        // 这把「外壳」与「待签字节」两者的关系也一并钉住了。
        assert_eq!(tx.message.serialize(), decode_prefixed(&u.signing_payload_hex));
        // 重新序列化应与输入逐字节相同（ShortVec 的长度前缀是定长的，故可往返）。
        assert_eq!(
            bincode::serialize(&tx).expect("应可序列化"),
            bytes,
            "解码后重新序列化应与原字节一致"
        );
    }

    /// 待签字节必须以 header + 账户表开头，且第一个账户是付款方（fee payer）。
    ///
    /// 领域说明：`Message::new` 会把 fee payer 排在账户表**首位**并标记为需签名；
    /// 若哪天顺序变了而我们没跟着改，签出来的交易会被节点拒绝。
    #[test]
    fn wire_format_starts_with_header_then_fee_payer() {
        let u = fixed_unsigned();
        let wire = decode_prefixed(&u.signing_payload_hex);

        // header：1 个必需签名 / 0 个只读签名 / 1 个只读非签名（SystemProgram）。
        assert_eq!(&wire[..3], &[1, 0, 1]);
        // account_keys 的 compact-u16 长度 = 3（from / to / system program）。
        assert_eq!(wire[3], 3);
        // 第一个账户即 fee payer = 付款方。
        assert_eq!(&wire[4..36], &[0x11u8; 32]);
        // 第二个账户是收款方。
        assert_eq!(&wire[36..68], &[0x22u8; 32]);
    }

    /// base58 编解码互为逆运算（针对任意字节序列，不限于 32/64 字节）。
    #[test]
    fn base58_round_trip() {
        // `b"..."` 是字节串字面量，类型是 `&[u8; 16]`。
        let original = b"hello solana rpc";
        let encoded = bs58_encode(original);
        // 右侧 `original.to_vec()`：为了与 `Vec<u8>` 比较，把定长数组转成向量。
        // 直接写 `assert_eq!(bs58_decode(&encoded).unwrap(), original)` 会因类型不同编译失败。
        assert_eq!(bs58_decode(&encoded).unwrap(), original.to_vec());
    }
}
