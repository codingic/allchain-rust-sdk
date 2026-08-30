//! eth 链对统一 `ChainClient` 契约的实现。
//!
//! 复用 [`crate::queries`] 的参数解析逻辑，但把结果映射为 core 定义的结构化视图，
//! 不再直接打印。
//!
//! 一句话概括本文件的职责：**把 alloy 的类型翻译成 `allchain_core` 的 View**。
//! 上层（acli 的 CLI / HTTP / MCP 三种形态）只认识 `StatusView` / `TxView` 这些
//! 统一结构，永远不接触 `RootProvider` / `Transaction` 等 alloy 类型。
//! 因此新增一条链、或替换底层 SDK，都不会波及上层。

// `FromStr` 让 `Address::from_str` / `B256::from_str` 可用；trait 需先引入作用域。
use std::str::FromStr;

// 语法说明：`use Trait as _;` 是「**匿名导入** trait」——
// 只把 trait 的**方法**引入作用域以便调用 `tx.value()` 这样的写法，
// 但不把 `Transaction` 这个名字导入，从而避免与下面的
// `alloy::rpc::types::Transaction` 结构体撞名。
use alloy::consensus::Transaction as _;
// `BlockId`：区块引用（高度 / 哈希 / latest 标签）的统一抽象。
// `BlockNumberOrTag`：按高度寻址时用的「数字高度」变体（区别于 `Latest` 等命名标签）。
use alloy::eips::{BlockId, BlockNumberOrTag};
// `ReceiptResponse` / `TransactionResponse`：alloy 的跨网络抽象 trait，
// 让我们不必为每种交易类型各写一套代码。
use alloy::network::{ReceiptResponse, TransactionResponse};
use alloy::primitives::{Address, B256, U256};
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::types::Transaction;
// 地址派生所需的两个官方入口。之所以不自己算，是为了让「解压公钥」与
// 「keccak256 取后 20 字节」这两件事都由经过审计的实现来兜底：
// - `VerifyingKey` 来自 alloy 转出的 **k256**（RustCrypto 的 secp256k1 实现），
//   `from_sec1_bytes` 会顺带校验该点是否落在曲线上；
// - `public_key_to_address` 是 alloy 的官方派生函数。
use alloy::signers::k256::ecdsa::VerifyingKey;
use alloy::signers::utils::public_key_to_address;
use async_trait::async_trait;
// `json!` 宏用字面量语法直接构造 `serde_json::Value`，
// 用于往统一 View 的 `extra`（经 `#[serde(flatten)]` 平铺到顶层）里塞链专有信息。
use serde_json::json;

use allchain_core::{
    AddressView, BalanceView, BlockView, ChainClient, ChainKind, SdkError, StatusView,
    TransferRequest, TransferView, TxStatus, TxView, hexutil,
};

use crate::network::{self, NetworkArg};

/// ETH 链客户端。持有一个只读 HTTP Provider，可安全并发复用。
///
/// 领域说明：`RootProvider` 内部基于 `reqwest` 连接池，本身可 `Clone` 且线程安全，
/// 因此一个 `EthClient` 放进 `Arc` 后能同时服务多个请求，不必每次查询都重建连接。
///
/// 语法说明：三个字段都是 `String` 而非 `&str`——`&str` 字段必须带生命周期参数，
/// 会把结构体声明变成 `EthClient<'a>`，并把这个生命周期传染给所有持有它的地方。
/// 多一次堆分配换掉整套生命周期复杂度，这里很划算。
pub struct EthClient {
    /// 网络名：`mainnet` / `sepolia` / `localnet`；用了自定义端点时为 `custom`。
    network: String,
    /// 实际连接的 RPC 端点，回显给调用方以确认「打的是不是预期节点」。
    rpc_url: String,
    /// alloy 的只读 HTTP Provider，所有查询都经由它发出。
    provider: RootProvider,
}

impl EthClient {
    /// 构造客户端。`network` 为 `mainnet` / `sepolia` / `localnet`，
    /// 缺省用 `mainnet`；显式给出 `rpc_url` 时优先使用，网络名标记为 `custom`。
    ///
    /// 优先级设计：**显式端点 > 网络名 > 默认主网**。
    /// 之所以不把自定义端点也标注成具体网络，是因为无法从 URL 反推它连的是
    /// 主网还是测试网——编造一个反而误导，如实写 `custom` 更可靠。
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        // 三段链式调用，把「没传 / 传了空串 / 传了一串空格」全部归一化：
        //   `.map(str::trim)`            → 去掉首尾空白
        //   `.filter(|s| !s.is_empty())` → 空串折算成 None（这是 `Option` 上的 filter）
        //   `.map(str::to_string)`       → 借用的 &str 转成自有 String
        // `str::trim` / `str::to_string` 是**函数指针**，正好匹配这里需要的闭包签名，
        // 比写 `.map(|s| s.trim())` 更简洁。
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        // `match` 整体作为表达式，结果直接解构给 `(a, b)`。
        let (network_name, url) = match custom {
            // 显式端点：网络名如实标为 custom，不做任何猜测。
            Some(url) => ("custom".to_string(), url),
            // 否则按网络名查预设端点。
            None => {
                let net = parse_network(network)?;
                // `&'static str` 需要转成自有 `String` 才能存进结构体。
                (net.as_str().to_string(), net.rpc_url().to_string())
            }
        };

        // `map_err` 把 anyhow 的通用错误**翻译**成统一的 `SdkError`，
        // 从此往上层的错误类型收敛为单一形态。
        let provider = network::connect(&url).map_err(|e| fail("连接 RPC 端点失败", e))?;
        // 字段初始化简写：`network` 等价于 `network: network`。
        Ok(Self {
            network: network_name,
            rpc_url: url,
            provider,
        })
    }

    /// 把底层错误包装成带中文上下文的 `SdkError`。
    ///
    /// 这是**方法**版本，只是在 trait 实现里少写几个字的便捷转发，
    /// 真正的逻辑在同名的自由函数里。它接收 `&self` 却没用到任何字段——
    /// 这样设计是为了让调用点统一写成 `self.fail(..)`，读起来更顺。
    fn fail(&self, context: &str, err: impl std::fmt::Display) -> SdkError {
        fail(context, err)
    }
}

/// 解析网络名，`None` 与空串一律视为主网。
fn parse_network(raw: Option<&str>) -> Result<NetworkArg, SdkError> {
    // 与构造函数里同一套「归一化」写法。
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(NetworkArg::Mainnet),
        Some("mainnet") => Ok(NetworkArg::Mainnet),
        Some("sepolia") => Ok(NetworkArg::Sepolia),
        Some("localnet") => Ok(NetworkArg::Localnet),
        // `other` 绑定未匹配到的值，回显在错误信息里便于用户自查拼写。
        Some(other) => Err(SdkError::invalid_argument(format!(
            "ETH 不支持的网络: {other}（可选 mainnet / sepolia / localnet）"
        ))),
    }
}

/// 错误翻译的唯一入口：`上下文 + 底层错误` → `SdkError`。
///
/// 语法说明：参数 `impl std::fmt::Display` 是 **`impl Trait` 参数位置**
/// （泛型参数的语法糖）：任何实现了 `Display` 的类型都能传进来
/// （alloy 的 `RpcError`、anyhow 的 `Error` 都行），
/// 与写成 `<E: Display>` 等价，但省掉一个泛型参数名。
///
/// 领域说明：`classify` 会按错误文本里的关键词（not found / timeout / invalid …）
/// 推断出 `ErrorCode`，从而让 HTTP 层能返回恰当的响应。
fn fail(context: &str, err: impl std::fmt::Display) -> SdkError {
    allchain_core::error::classify(&format!("{context}: {err}"))
}

/// 为 `EthClient` 实现跨链统一契约。
///
/// 语法说明：`#[async_trait]` 必须同时出现在 trait 定义（core/src/traits.rs）
/// 与这里的 impl 块上：它在编译期把每个 `async fn` 改写成返回
/// `Pin<Box<dyn Future + Send>>` 的普通 fn，代价是每次调用一次堆分配，
/// 换来的是 `Box<dyn ChainClient>` 这种 trait object 依然可用——
/// 上层正是靠它在运行期按链名分发。
#[async_trait]
impl ChainClient for EthClient {
    /// 所属链。同步方法，只返回编译期常量，无需 IO。
    fn kind(&self) -> ChainKind {
        ChainKind::Eth
    }

    /// 网络名。返回 `&str` 是**借用**内部字段，不产生分配。
    ///
    /// 语法说明：此处发生**生命周期省略**，编译器按规则把返回值的生命周期
    /// 绑到 `&self` 上，含义是「返回的引用不能活得比 `self` 更久」。
    fn network(&self) -> &str {
        // `&self.network` 的类型是 `&String`，会被**自动解引用强制转换**
        // （deref coercion）成返回类型要求的 `&str`。
        &self.network
    }

    /// 实际 RPC 端点。
    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// 链与节点状态：客户端版本 + chain id + 最新区块。
    async fn status(&self) -> Result<StatusView, SdkError> {
        // 三次独立 RPC 调用，串行 await。它们之间没有依赖，串行写法最简单
        // （若要并发可用 `tokio::try_join!`）。
        let version = self
            .provider
            .get_client_version()
            .await
            .map_err(|e| self.fail("查询客户端版本失败", e))?;
        let chain_id = self
            .provider
            .get_chain_id()
            .await
            .map_err(|e| self.fail("查询链 ID 失败", e))?;
        let block = self
            .provider
            .get_block(BlockId::latest())
            .await
            .map_err(|e| self.fail("查询最新区块失败", e))?
            // `get_block` 返回 `Option`：节点在同步中或极端情况下可能返回空。
            // `ok_or_else(闭包)` **惰性**构造错误——成功路径不会执行闭包，零开销
            // （与之相对的 `ok_or(值)` 会无条件先把那个值算出来）。
            .ok_or_else(|| SdkError::not_found("节点未返回最新区块"))?;

        Ok(
            StatusView::new(ChainKind::Eth, &self.network, &self.rpc_url)
                .with_height(block.header.number)
                .with_hash(block.header.hash.to_string())
                .with_version(version)
                // chain id 是 ETH 专有概念，统一 schema 里没有对应字段，
                // 因此塞进 `extra`，由 `#[serde(flatten)]` 平铺到顶层输出。
                .with_extra(json!({ "chain_id": chain_id })),
        )
    }

    /// 查询地址余额。
    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        // 先**本地**校验地址格式，不合法就不发网络请求，省一次往返。
        let addr = parse_address(address)?;
        let balance = self
            .provider
            .get_balance(addr)
            .await
            .map_err(|e| self.fail("查询余额失败", e))?;
        // 余额是 `U256`，统一模型用 `u128`，这里做一次带溢出检查的收窄。
        let raw = to_u128(balance)?;
        Ok(BalanceView::new(
            ChainKind::Eth,
            &self.network,
            // 回显**用户原始输入**而非解析后的地址，
            // 便于批量查询时把结果对回具体请求。
            address,
            raw,
        ))
    }

    /// 链头高度：最新区块的高度（裸 `u64`）。
    ///
    /// 比 [`ChainClient::block_by_height`] 轻——只取最新区块头一次 RPC，
    /// 不反序列化整块与交易列表，轮询同步进度时优先用它。
    async fn last_block_height(&self) -> Result<u64, SdkError> {
        let block = self
            .provider
            .get_block(BlockId::latest())
            .await
            .map_err(|e| self.fail("查询最新区块失败", e))?
            // 节点在同步中或极端情况下 `get_block` 可能返回 `None`。
            // `ok_or_else` 惰性构造错误，成功路径零开销。
            .ok_or_else(|| SdkError::not_found("节点未返回最新区块"))?;
        // alloy 的 `header.number` 即为 `u64`，无需转换，可直接喂给 `last_block_height`。
        Ok(block.header.number)
    }

    /// 按高度查询区块。
    async fn block_by_height(&self, height: u64) -> Result<BlockView, SdkError> {
        // `BlockId::Number(...)` 是「按数字高度寻址」这一支；
        // `BlockNumberOrTag::Number(height)` 把 `u64` 包成「精确高度」，
        // 区别于 `Latest` / `Finalized` 等命名标签。
        let block_id = BlockId::Number(BlockNumberOrTag::Number(height));
        let block = self
            .provider
            .get_block(block_id)
            .await
            .map_err(|e| self.fail("查询区块失败", e))?
            .ok_or_else(|| {
                SdkError::not_found("节点未返回该区块（高度超前或不存在，历史区块需归档节点）")
            })?;

        // 借用 header 而非移动：下面要用它读好几个字段。
        let header = &block.header;
        Ok(
            BlockView::new(ChainKind::Eth, &self.network, header.hash.to_string())
                .with_height(header.number)
                .with_parent(header.parent_hash.to_string())
                // `as i64` 是**显式类型转换**。区块时间戳是 `u64`（Unix 秒），
                // 统一模型用 `i64` 以承接 1970 年之前的创世时间，此处转换不会溢出。
                .with_timestamp(header.timestamp as i64)
                // `.len()` 返回 `usize`（宽度随平台），统一模型要求 `u64`，故转换。
                .with_tx_count(block.transactions.len() as u64)
                .with_extra(json!({
                    // `beneficiary` 即区块头里的「矿工 / 受益地址」，
                    // 合并（PoS）之后是验证者的提款地址。
                    "miner": header.beneficiary.to_string(),
                    "gas_used": header.gas_used,
                    "gas_limit": header.gas_limit,
                })),
        )
    }

    /// 查询交易详情与执行结果。
    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        let tx_hash = parse_hash(hash)?;
        // 类型标注不可省：`get_transaction_by_hash` 是泛型方法，
        // 要靠它确定把响应反序列化成哪个具体交易类型。
        let tx: Option<Transaction> = self
            .provider
            .get_transaction_by_hash(tx_hash)
            .await
            .map_err(|e| self.fail("查询交易失败", e))?;
        let tx = tx.ok_or_else(|| {
            SdkError::not_found("交易不在该节点数据中，历史交易请使用归档节点端点")
        })?;

        // 回执需要**单独**请求：内存池里的交易查不到回执，这是正常状态而非错误。
        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|e| self.fail("查询交易回执失败", e))?;

        // 三档判定，与 core 的 `TxStatus` 语义一一对应：
        //   有回执且 status = true  → 成功
        //   有回执但 status = false → 已上链但 revert（失败交易同样耗 gas 并留痕）
        //   无回执                 → 仍在内存池
        // `Some(r) if r.status()` 是**守卫模式**：先解构，再判断附加条件。
        let status = match &receipt {
            Some(r) if r.status() => TxStatus::Success,
            Some(_) => TxStatus::Failed,
            None => TxStatus::Pending,
        };

        // `mut` 是必需的：下面要按条件往 view 上叠加字段并重新赋值。
        let mut view = TxView::new(ChainKind::Eth, &self.network, hash, status)
            // `tx.from()` 由签名**恢复**得出，并不存在于交易字段里。
            .with_from(tx.from().to_string())
            .with_amount(to_u128(tx.value())?);

        // `tx.to()` 为 `None` 表示合约创建交易——EVM 特有语义，不是错误。
        if let Some(to) = tx.to() {
            view = view.with_to(to.to_string());
        }
        // 尚未入块的交易没有区块高度。
        if let Some(height) = tx.block_number() {
            view = view.with_height(height);
        }
        if let Some(r) = &receipt {
            // 手续费 = 实际 gas 用量 × 实际结算单价。
            // `as u128` 提升左操作数类型，避免 u64 × u128 的类型不匹配；
            // 两项之积在实务上远小于 2^128。
            let fee = r.gas_used() as u128 * r.effective_gas_price();
            view = view.with_fee(fee).with_extra(json!({
                "nonce": tx.nonce(),
                "gas_used": r.gas_used(),
                // input 长度可快速区分「纯转账」（0 字节）与「合约调用」。
                "input_bytes": tx.input().len(),
            }));
        }

        Ok(view)
    }

    /// 转账：本地构造、签名并广播（`dry_run` 为 `true` 时只签名不广播）。
    ///
    /// 私钥只在本地参与 ECDSA 签名运算，从不进入任何请求体。
    async fn transfer(&self, req: TransferRequest) -> Result<TransferView, SdkError> {
        let to = parse_address(&req.to)?;
        // 金额是人类可读的 ether 字符串，先转成最小单位 wei（纯整数运算）。
        let value = crate::units::parse_amount(&req.amount, "ether")
            .map_err(|e| SdkError::invalid_argument(format!("非法金额: {e}")))?;
        let amount_raw = to_u128(value)?;
        // 解析私钥 → 本地签名器 → 由私钥推导付款地址（纯本地，不发请求）。
        let signer = crate::transactions::parse_signer(&req.private_key)
            .map_err(|e| SdkError::invalid_argument(e.to_string()))?;
        let from = signer.address().to_string();

        // dry-run：只签名不广播，`broadcast` 字段如实写 false。
        if req.dry_run {
            let signed =
                crate::transactions::build_signed_transfer(&self.rpc_url, &signer, to, value)
                    .await
                    .map_err(|e| self.fail("本地签名转账失败", e))?;
            return Ok(TransferView::new(
                ChainKind::Eth,
                &self.network,
                Some(from),
                req.to,
                amount_raw,
                Some(signed.tx_hash.to_string()),
                false,
            )
            .with_extra(json!({
                "signed_raw": signed.signed_raw,
                "chain_id": signed.chain_id,
                "nonce": signed.nonce,
                "max_fee_gwei": crate::units::format_wei(U256::from(signed.max_fee_per_gas), 9),
                "max_priority_fee_gwei": crate::units::format_wei(U256::from(signed.max_priority_fee_per_gas), 9),
            })));
        }

        // 真发：广播并等回执，用一个四元组一次拿全结果。
        let (tx_hash, success, block_number, gas_used) =
            crate::transactions::transfer_silent(&self.rpc_url, signer, to, value)
                .await
                .map_err(|e| self.fail("广播转账失败", e))?;

        Ok(TransferView::new(
            ChainKind::Eth,
            &self.network,
            Some(from),
            req.to,
            amount_raw,
            Some(tx_hash.to_string()),
            true,
        )
        .with_extra(json!({
            "success": success,
            "block_number": block_number,
            "gas_used": gas_used,
        })))
    }

    /// 由 secp256k1 公钥派生地址。**纯本地计算**，不访问 RPC。
    ///
    /// 领域说明（ETH 地址是怎么来的）：
    ///   1. 把公钥还原成**未压缩**的 64 字节坐标（去掉 SEC1 的 `04` 前缀，即 x || y）；
    ///   2. 对这 64 字节做 `keccak256`，得到 32 字节哈希；
    ///   3. 取哈希的**后 20 字节**（即 `[12..32]`）作为地址。
    ///
    /// 两个易踩的坑：
    /// - 用的是 **Keccak-256** 而不是标准化的 SHA3-256（两者填充位不同），
    ///   这是以太坊的历史选择，混用会得到完全不同的地址；
    /// - 哈希输入必须是**完整**的 x||y。压缩公钥只存了 x 加一个奇偶位，
    ///   必须先把 y 解出来——这是椭圆曲线运算，交给 alloy 的 `k256` 做，不自己实现。
    ///
    /// 接受三种写法（与 BTC / CKB 保持一致，调用方不必预先归一化）：
    /// - 33 字节**压缩**公钥（`02`/`03` + x）；
    /// - 65 字节未压缩公钥（`04` + x + y）；
    /// - 64 字节裸坐标（x || y，无前缀）。
    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        let (address, coords, input_format) = derive_address_from_pubkey(pubkey)?;

        Ok(AddressView::new(
            ChainKind::Eth,
            &self.network,
            // 展示**归一化后**的 64 字节坐标：它就是真正被哈希的输入，
            // 便于调用方用自己的 keccak256 独立复算一遍做校验。
            hexutil::encode_hex_prefixed(&coords),
            // `to_checksum(None)` 生成 **EIP-55 校验和地址**：
            // 对地址的小写十六进制串再做一次 keccak256，由哈希位决定每个字母的大小写。
            // 它不改变地址的值，只是在显示层面提供「打错字能被发现」的能力；
            // 参数是 EIP-155 的 chain id，传 `None` 表示不参与计算（绝大多数场景如此）。
            address.to_checksum(None),
            // `eoa` = externally owned account（外部账户），区别于合约地址。
            "eoa",
            coords.len(),
        )
        .with_extra(json!({
            // 同时给出全小写形式，方便与不区分大小写的旧系统对接。
            "lowercase": hexutil::encode_hex_prefixed(address.as_slice()),
            "derivation": "keccak256(uncompressed_pubkey)[12..32]",
            // 回吐输入形态，便于调用方确认自己传的是哪一种。
            "input_format": input_format,
        })))
    }
}

/// 由公钥十六进制串派生 ETH 地址。
///
/// 返回 `(地址, 未压缩的 64 字节坐标, 输入形态描述)`。
///
/// 设计要点：**先把三种输入统一成 SEC1 未压缩格式，再交给 alloy 解析**。
/// 这样 33 / 64 / 65 三种写法最终走的是同一条官方路径，
/// 不会出现「两个分支、两套算法」的隐患——那种结构正是 CKB 地址
/// 历史上出过问题的地方。
fn derive_address_from_pubkey(raw: &str) -> Result<(Address, [u8; 64], &'static str), SdkError> {
    let bytes = hexutil::decode_hex(raw)?;
    // 归一化成 65 字节 SEC1 未压缩格式（`0x04 || x || y`）。
    let (sec1, input_format) = match bytes.len() {
        // 33 字节压缩（`02`/`03` + x）或 65 字节未压缩：本就是 SEC1，原样透传。
        // 首字节是否合法由下面的 `from_sec1_bytes` 把关，这里不再重复判断。
        33 => (bytes.clone(), "compressed"),
        65 => (bytes.clone(), "uncompressed"),
        // 64 字节裸坐标：补上未压缩标志 `0x04`。
        //
        // `Vec::with_capacity(65)` 预留容量后 push，只分配一次堆内存。
        64 => {
            let mut v = Vec::with_capacity(65);
            v.push(0x04);
            v.extend_from_slice(&bytes);
            (v, "raw-coords")
        }
        other => {
            return Err(SdkError::invalid_argument(format!(
                "ETH 公钥需为 33 字节压缩、64 字节裸坐标或 65 字节带 04 前缀的十六进制，\
                 实际 {other} 字节"
            )))
        }
    };

    // `VerifyingKey::from_sec1_bytes` 是 alloy 转出的 **k256 官方入口**，
    // 一次做完三件事：解析 SEC1、压缩格式下**解压出 y 坐标**、
    // 以及**校验该点确实落在 secp256k1 曲线上**。
    //
    // 最后这点是本函数此前缺失的一项防护：旧实现直接拿 64 字节去哈希，
    // 一个不在曲线上的坐标也能算出「地址」，但那个地址对应的私钥并不存在
    // ——钱打过去就永远取不出来。
    //
    // k256 返回的是通用的 `signature::Error`（打印出来只是 "signature error"），
    // 本身不说明原因，所以这里补一句针对本场景的解释，免得调用方对着
    // "signature error" 猜半天。
    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| {
        SdkError::invalid_argument(format!(
            "非法 secp256k1 公钥（{format_hint}）：未通过 secp256k1 校验。\
             最常见的原因是坐标不在曲线上——这样的公钥没有对应的私钥，\
             算出来的地址也无人可控，因此必须拒绝。底层错误: {e}",
            format_hint = match input_format {
                "compressed" => "压缩格式，33 字节，应为 02/03 开头",
                "uncompressed" => "未压缩格式，65 字节，应为 04 开头",
                _ => "裸坐标，64 字节",
            }
        ))
    })?;

    // `public_key_to_address` 是 alloy 的**官方派生函数**：
    // 内部把点编码成未压缩形式、去掉 `0x04`、做 keccak256、取后 20 字节。
    // 不自己写这四步，是为了避免「实现与官方不一致却自往返通过」这类问题。
    let address = public_key_to_address(&verifying_key);

    // 同时取回未压缩坐标，供返回值与展示使用。
    // `to_encoded_point(false)` 的 `false` 表示「不压缩」，得到 65 字节（含 `0x04`）。
    let encoded = verifying_key.to_encoded_point(false);
    let mut coords = [0u8; 64];
    // `encoded.as_bytes()` 是 65 字节，跳过首字节前缀后正好 64 字节。
    // `copy_from_slice` 要求两侧等长，长度由上面两步保证。
    coords.copy_from_slice(&encoded.as_bytes()[1..]);

    Ok((address, coords, input_format))
}

/// 校验并解析 ETH 地址字符串（`0x` + 40 位十六进制）。
///
/// 注意：alloy 的 `FromStr` 只校验长度与字符集，**不做** EIP-55 校验和验证——
/// 大小写混写但校验和对不上时不会报错。这是有意的：链上地址本质不区分大小写。
fn parse_address(raw: &str) -> Result<Address, SdkError> {
    Address::from_str(raw.trim()).map_err(|_| {
        SdkError::invalid_argument(format!("非法 ETH 地址: {raw}（期望 0x + 40 位十六进制）"))
    })
}

/// 校验并解析交易哈希（`0x` + 64 位十六进制）。
///
/// `B256` 是 alloy 的 32 字节定长哈希类型，与 `Address`（20 字节）同族。
fn parse_hash(raw: &str) -> Result<B256, SdkError> {
    B256::from_str(raw.trim()).map_err(|_| {
        SdkError::invalid_argument(format!("非法交易哈希: {raw}（期望 0x + 64 位十六进制）"))
    })
}

/// 把 `U256` 收敛到 `u128`，溢出即报错。
///
/// 领域说明：ETH 侧的面值远小于 2^128，但 `U256` 能表示到 2^256；
/// 统一模型用 `u128` 承载金额，所以这里必须做一次**带检查**的收窄。
fn to_u128(value: alloy::primitives::U256) -> Result<u128, SdkError> {
    // `try_from` 失败即超出 u128 范围，属于数据问题而非参数问题，
    // 因此错误码用 `ParseError`。
    u128::try_from(value)
        .map_err(|_| SdkError::new(allchain_core::ErrorCode::ParseError, "金额超出 u128 范围"))
}

/// 单元测试模块：`#[cfg(test)]` 保证只在 `cargo test` 时编译。
#[cfg(test)]
mod tests {
    // 把父模块的条目全部导入，于是可直接写 `derive_address_from_pubkey`。
    use super::*;
    // `keccak256` 只在测试里用（用于独立复算一遍派生公式、与 alloy 的官方实现对照），
    // 生产代码已完全交给 `public_key_to_address`，因此放在这里导入而非文件顶部。
    use alloy::primitives::keccak256;

    // 私钥 0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318 的公钥。
    // 向量由独立的纯 Python 实现（secp256k1 点乘已用 2G/3G/nG 校验，Keccak 已用
    // 空串与 "abc" 公开向量校验）交叉验证过。
    //
    // 为什么要交叉验证：地址派生是**不可逆**的单向计算，
    // 若测试向量本身也来自被测代码，测试就失去了意义。

    /// 64 字节裸坐标形式（x || y）。
    const COORDS_HEX: &str = "4e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de";
    /// 65 字节 SEC1 未压缩形式（04 || x || y）。
    const UNCOMPRESSED_HEX: &str = "044e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de";
    /// 33 字节压缩形式（02 || x）。y 的末字节是 `0xde`（偶数），故前缀取 `02`。
    const COMPRESSED_HEX: &str = "024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e";
    /// 期望的 EIP-55 校验和形式（大小写混写）。
    const EXPECT_CHECKSUM: &str = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23";
    /// 期望的全小写形式，与上者表示同一个地址。
    const EXPECT_LOWER: &str = "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23";

    /// 64 字节裸坐标 → 校验和地址。
    #[test]
    fn derives_address_from_64_byte_coords() {
        let (address, coords, format) = derive_address_from_pubkey(COORDS_HEX).unwrap();
        assert_eq!(coords.len(), 64);
        assert_eq!(format, "raw-coords");
        assert_eq!(address.to_checksum(None), EXPECT_CHECKSUM);
    }

    /// 直接重算一遍「keccak 取后 20 字节」，确认派生公式没被写错。
    ///
    /// 这条测试**刻意不调用** `public_key_to_address`，而是自己走一遍
    /// `keccak256` + 切片——若 alloy 的官方实现与「教科书公式」有出入，这里会红。
    #[test]
    fn address_matches_keccak_last_20_bytes() {
        let (address, coords, _) = derive_address_from_pubkey(COORDS_HEX).unwrap();
        let hash = keccak256(coords);
        let manual = Address::from_slice(&hash[12..]);
        assert_eq!(manual, address, "alloy 的派生结果与手算公式不一致");
        assert_eq!(
            hexutil::encode_hex_prefixed(address.as_slice()),
            EXPECT_LOWER
        );
        assert_eq!(address.to_checksum(None), EXPECT_CHECKSUM);
    }

    /// 三种写法（压缩 33B / 裸坐标 64B / 未压缩 65B）必须得到**同一个**地址。
    ///
    /// 这是本模块最重要的契约：调用方不必预先归一化公钥格式。
    /// 同时它也反向验证了 k256 的解压实现——压缩格式能还原出正确的 y。
    #[test]
    fn all_three_pubkey_encodings_yield_same_address() {
        let (from_raw, coords_raw, _) = derive_address_from_pubkey(COORDS_HEX).unwrap();
        let (from_compressed, coords_compressed, fmt_c) =
            derive_address_from_pubkey(COMPRESSED_HEX).unwrap();
        let (from_uncompressed, coords_uncompressed, fmt_u) =
            derive_address_from_pubkey(UNCOMPRESSED_HEX).unwrap();

        assert_eq!(fmt_c, "compressed");
        assert_eq!(fmt_u, "uncompressed");
        // 三种输入归一化后必须是同一份坐标（x || y）。
        assert_eq!(coords_raw, coords_compressed);
        assert_eq!(coords_raw, coords_uncompressed);
        // 地址自然也完全相同。
        assert_eq!(from_raw, from_compressed);
        assert_eq!(from_raw, from_uncompressed);
        assert_eq!(from_raw.to_checksum(None), EXPECT_CHECKSUM);
    }

    /// `0x` 前缀与全大写写法同样被接受（十六进制解析的宽容性）。
    #[test]
    fn accepts_0x_prefix_and_uppercase() {
        let a = derive_address_from_pubkey(UNCOMPRESSED_HEX).unwrap().0;
        let b = derive_address_from_pubkey(&format!("0x{COORDS_HEX}"))
            .unwrap()
            .0;
        let c = derive_address_from_pubkey(&COORDS_HEX.to_uppercase())
            .unwrap()
            .0;
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    /// **不在曲线上**的坐标必须被拒绝。
    ///
    /// 这是换用官方 SDK 后新增的防护：坐标 (1, 1) 满足 `1 != 1 + 7 (mod p)`，
    /// 显然不在 secp256k1 上。旧实现会照样算出「地址」，
    /// 但那个地址没有对应私钥——资金打进去就再也取不出来。
    #[test]
    fn rejects_off_curve_point() {
        // x = 1, y = 1（各占 32 字节，末字节为 1，其余补零）。
        let mut off_curve = [0u8; 64];
        off_curve[31] = 1;
        off_curve[63] = 1;
        let hex = hexutil::encode_hex(&off_curve);
        assert!(
            derive_address_from_pubkey(&hex).is_err(),
            "不在曲线上的坐标必须被拒绝"
        );
    }

    /// 非法长度、非法十六进制、非法 SEC1 前缀都必须被拒绝。
    #[test]
    fn rejects_bad_length_and_malformed_input() {
        assert!(derive_address_from_pubkey("02").is_err());
        // 32 字节：比裸坐标少一个字节，多见于抄漏。
        assert!(derive_address_from_pubkey(&"ab".repeat(32)).is_err());
        // 65 字节但首字节不是 04 —— 典型的压缩公钥被误当成未压缩传入。
        assert!(derive_address_from_pubkey(&format!("02{}", "ab".repeat(64))).is_err());
        let err = derive_address_from_pubkey("not-hex").unwrap_err();
        assert!(err.message.contains("非法十六进制"));
    }
}
