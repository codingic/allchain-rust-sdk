//! Arweave 链对统一 `ChainClient` 契约的实现（公共网关 REST）。
//!
//! 上游的坑（都是实际踩过的）：
//! - `GET /wallet/{addr}/balance` 返回的是**纯文本**的 winston 整数，不是 JSON，
//!   所以走 `get_text` 而非 `get_value`，且必须自己 `parse::<u128>()`；
//! - 交易的状态不在 `GET /tx/{id}` 里，要**额外**请求 `GET /tx/{id}/status`；
//!   这个端点对不存在的交易会返回非 2xx，因此用 `.ok()` 降级为「查不到」；
//! - 区块里标识自己的字段叫 `indep_hash`（AR 的区块标识是「独立哈希」），
//!   不叫 `hash`；父块字段叫 `previous_block`；
//! - `GET /tx/{id}` 里的 `owner` 是 **RSA 公钥模数 n 的 base64url**，
//!   不是地址，必须再算一次 `base64url(sha256(n))` 才是我们认识的 43 字符地址；
//! - 交易没有「失败上链」的概念，进了区块就算成功，因此状态只有 Success / Pending 两态。
//!
//! 写路径的两段式（无私钥）实现见 [`crate::tx`]，本文件只负责联网取依赖
//! （`last_tx` 与手续费）与最终广播。

use async_trait::async_trait;
// base64 crate 的用法分两步：先 `use base64::Engine` 把 trait 引入作用域
// （`decode` / `encode` 都是它的**方法**，不引入就调不到），
// 再挑一个具体的引擎实例。
use base64::Engine;
// `URL_SAFE_NO_PAD`：URL 安全字母表（`-` `_` 代替 `+` `/`）且**不加** `=` 填充。
// Arweave 全链的地址、交易 ID、owner 字段用的都是这一套，因此选它。
// 对比 `STANDARD`（带 `+` `/` 和填充），两者绝不通用。
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
// sha2 crate：`Digest` trait 提供 `digest()` 一次性哈希的便捷方法，
// 与 sha3 crate 的 `new()/update()/finalize()` 三段式是同一套 trait 的两种用法。
use sha2::{Digest, Sha256};

use allchain_core::{
    AddressView, BalanceView, BlockView, BuildTransferRequest, BuildTransferView, ChainClient,
    ChainKind, ErrorCode, SdkError, StatusView, SubmitRequest, SubmitView, TransferRequest,
    TransferView, TxStatus, TxView, hexutil, parse_units,
};
use chain_rpcutil::{Http, field_u64};

use crate::network;

/// Arweave 客户端：绑定一个网关 URL + 一个 reqwest 连接池。
///
/// 语法说明：字段用拥有所有权的 `String` 而非 `&str`。若用 `&str`，
/// 结构体必须写成 `ArClient<'a>`，生命周期会传染到所有持有它的地方。
pub struct ArClient {
    /// 网络名；使用自定义端点时为 `"custom"`。
    network: String,
    /// 实际网关 base URL，回显给调用方确认「打的是不是预期网关」。
    rpc_url: String,
    /// 共享 HTTP 客户端（内部 `Arc`，克隆廉价）。只读端点走它。
    http: Http,
    /// 专供**写路径**复用的 reqwest 客户端。
    ///
    /// 为什么单独留一份：`chain_rpcutil::Http` 只暴露 GET（`get_text` / `get_value`），
    /// 而广播交易要 `POST /tx`。若每次广播都 `reqwest::Client::new()`，
    /// 就等于每次都新建一个连接池——TLS 握手与 keep-alive 全部无法复用，
    /// 长驻的 HTTP / MCP 服务里这是实打实的开销。
    ///
    /// 注意版本：这里是 `reqwest` **0.11**（与 arweave-rs 对齐），
    /// 而 `Http` 内部用的是 0.13（workspace 版），两者并存、互不干扰。
    client: reqwest::Client,
}

impl ArClient {
    /// 构造客户端：`rpc_url` 优先，否则按 `network` 取预置网关（缺省主网）。
    pub fn new(network: Option<&str>, rpc_url: Option<&str>) -> Result<Self, SdkError> {
        // trim → 过滤空串 → 转成 `String`（取得所有权，不再依赖调用方的临时借用）。
        let custom = rpc_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        // `match` 是表达式：两个分支必须返回同一类型，这里都是 `(String, String)`。
        let (network_name, url) = match custom {
            Some(url) => ("custom".to_string(), url),
            None => {
                // `?` 在 `Err` 时立即提前返回，在 `Ok` 时取出值继续。
                let net = network::parse(network)?;
                (net.as_str().to_string(), net.gateway_url().to_string())
            }
        };
        let http = Http::new(&url)?;
        let client = reqwest::Client::builder().build().map_err(|e| {
            SdkError::new(ErrorCode::Internal, format!("构造 AR 广播客户端失败: {e}"))
        })?;
        Ok(Self {
            network: network_name,
            rpc_url: url,
            http,
            client,
        })
    }
}

// trait 实现块：实现之后本类型即可被 `Box<dyn ChainClient>` 持有，
// 上层 acli 因而能在运行期按链名分发，完全不认识 `ArClient`。
#[async_trait]
impl ChainClient for ArClient {
    /// 所属链（同步方法，值在编译期就定死了）。
    fn kind(&self) -> ChainKind {
        ChainKind::Ar
    }

    /// 网络名。`&str` 借用的是 `self` 内部的 `String`，
    /// 生命周期自动绑定为「不比 `self` 活得更久」。
    fn network(&self) -> &str {
        &self.network
    }

    /// 实际网关 URL。
    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    async fn status(&self) -> Result<StatusView, SdkError> {
        // `GET /info` 一次拿回高度、当前区块哈希（字段名就叫 `current`）、网络名等。
        let info = self.http.get_value("/info").await?;
        let mut view = StatusView::new(ChainKind::Ar, &self.network, &self.rpc_url);
        // `if let Ok(h)`：这里**故意**忽略解析失败——网关版本差异可能导致
        // `height` 是字符串或缺失，不该让整个 status 查询失败。
        if let Ok(h) = field_u64(&info, "height") {
            view = view.with_height(h);
        }
        if let Some(current) = info.get("current").and_then(Value::as_str) {
            view = view.with_hash(current);
        }
        // 下面的 `get(k).cloned().unwrap_or(Value::Null)` 是固定套路：
        // `get` → `Option<&Value>`，`.cloned()` → `Option<Value>`，
        // `unwrap_or(Null)` 把「键缺失」变成显式的 null，
        // 于是输出的 schema 稳定（键一定在，值可能是 null）。
        Ok(view.with_extra(json!({
            "network": info.get("network").cloned().unwrap_or(Value::Null),
            "version": info.get("version").cloned().unwrap_or(Value::Null),
            "release": info.get("release").cloned().unwrap_or(Value::Null),
            "peers": info.get("peers").cloned().unwrap_or(Value::Null),
            // `blocks` 是 weave 中已存区块总数，与 `height` 是两回事。
            "blocks": info.get("blocks").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn balance(&self, address: &str) -> Result<BalanceView, SdkError> {
        validate_address(address)?;
        // 网关返回纯文本 winston 余额。
        //
        // 为什么用 `get_text`：该端点的 `Content-Type` 是 `text/plain`，
        // 不是 JSON；若用 `get_value` 会因反序列化失败而报 ParseError。
        let text = self
            .http
            .get_text(&format!("/wallet/{}/balance", address.trim()))
            .await?;
        // `parse::<u128>()` 里的 `::<u128>` 是 **turbofish** 语法，显式指定泛型参数。
        // 之所以选 u128：winston 精度 12 位，AR 总量 6600 万，
        // 最大余额约 6.6e19，已经超出 `u64::MAX`（1.8e19）。
        let raw = text.trim().parse::<u128>().map_err(|_| {
            SdkError::new(ErrorCode::ParseError, format!("非法 winston 余额: {text}"))
        })?;
        Ok(BalanceView::new(ChainKind::Ar, &self.network, address, raw))
    }


    /// 查询交易。注意 Arweave 的「交易」默认是**存数据**，未必是转账。
    /// 链头高度：最新区块高度（裸 `u64`）。
    async fn last_block_height(&self) -> Result<u64, SdkError> {
        let info = self.http.get_value("/info").await?;
        field_u64(&info, "height")
    }

    /// 按高度查询区块。
    async fn block_by_height(&self, height: u64) -> Result<BlockView, SdkError> {
        let block = self.http.get_value(&format!("/block/height/{height}")).await?;
        let hash = block
            .get("indep_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| SdkError::new(ErrorCode::ParseError, format!("区块缺少 indep_hash: {block}")))?
            .to_string();
        let height_v = field_u64(&block, "height").ok();
        let timestamp = field_u64(&block, "timestamp").ok().map(|t| t as i64);
        let tx_count = block.get("txs").and_then(Value::as_array).map(|txs| txs.len() as u64);
        let mut view = BlockView::new(ChainKind::Ar, &self.network, hash);
        if let Some(h) = height_v { view = view.with_height(h); }
        if let Some(t) = timestamp { view = view.with_timestamp(t); }
        if let Some(n) = tx_count { view = view.with_tx_count(n); }
        if let Some(parent) = block.get("previous_block").and_then(Value::as_str) {
            view = view.with_parent(parent);
        }
        Ok(view.with_extra(json!({
            "nonce": block.get("nonce").cloned().unwrap_or(Value::Null),
            "reward_addr": block.get("reward_addr").cloned().unwrap_or(Value::Null),
            "weave_size": block.get("weave_size").cloned().unwrap_or(Value::Null),
        })))
    }

    async fn tx(&self, hash: &str) -> Result<TxView, SdkError> {
        validate_txid(hash)?;
        let id = hash.trim();
        let tx = self.http.get_value(&format!("/tx/{id}")).await?;
        // 确认状态：已上链时带 block_height；内存池中的交易无该字段。
        //
        // `.ok()` 是有意为之：对不存在/未确认的交易，网关在 status 端点上
        // 会返回 404，而「交易本身查得到、但状态查不到」应当降级为 Pending，
        // 不该让整个 `tx` 查询失败。
        let status_text = self.http.get_text(&format!("/tx/{id}/status")).await.ok();
        // 该端点可能返回 JSON，也可能返回纯文本（旧版网关），
        // 因此 `serde_json::from_str` 失败时同样降级为 `None` 而不是报错。
        let status_value: Option<Value> = status_text.and_then(|t| serde_json::from_str(&t).ok());
        // `.as_ref()` 很关键：`status_value` 是 `Option<Value>`，
        // 若直接 `.and_then(..)` 会把 `Value` **移动**进闭包，之后就没法再用了。
        // 而下面还要从同一个 `status_value` 里取 `number_of_confirmations`，
        // 所以这里必须先借用。
        let block_height = status_value
            .as_ref()
            .and_then(|s| s.get("block_height"))
            .and_then(Value::as_u64);
        let confirmations = status_value
            .as_ref()
            .and_then(|s| s.get("number_of_confirmations"))
            // 这里要拿所有权（放进 `json!`），所以先 `.cloned()` 再 `unwrap_or(Null)`。
            .cloned()
            .unwrap_or(Value::Null);

        let status = if block_height.is_some() {
            // Arweave 没有“失败上链”的概念，进入区块即成功。
            TxStatus::Success
        } else {
            TxStatus::Pending
        };

        let mut view = TxView::new(ChainKind::Ar, &self.network, id, status);
        if let Some(h) = block_height {
            view = view.with_height(h);
        }
        // owner 是 RSA 公钥模数（base64url），链上地址 = base64url(sha256(owner_bytes))。
        //
        // **let 链**语法：`if let Some(owner) = .. && let Ok(addr) = ..`
        // 把两层嵌套 `if let` 压平成一条，前一层匹配成功才继续下一层。
        if let Some(owner) = tx.get("owner").and_then(Value::as_str)
            && let Ok(addr) = owner_to_address(owner)
        {
            view = view.with_from(addr);
        }
        // 纯数据存储交易没有 `target` 或它是空串——只有真转账才有收款方。
        if let Some(target) = tx.get("target").and_then(Value::as_str)
            && !target.is_empty()
        {
            view = view.with_to(target);
        }
        // `quantity`（转账金额）与 `reward`（给矿工的费用）在响应里都是**字符串**十进制，
        // 需要 `parse::<u128>()`；解析失败时静默跳过，不污染整笔查询结果。
        if let Some(q) = tx.get("quantity").and_then(Value::as_str)
            && let Ok(amount) = q.parse::<u128>()
        {
            view = view.with_amount(amount);
        }
        if let Some(r) = tx.get("reward").and_then(Value::as_str)
            && let Ok(fee) = r.parse::<u128>()
        {
            view = view.with_fee(fee);
        }
        Ok(view.with_extra(json!({
            "data_size": tx.get("data_size").cloned().unwrap_or(Value::Null),
            "format": tx.get("format").cloned().unwrap_or(Value::Null),
            "content_type": tx.get("content_type").cloned().unwrap_or(Value::Null),
            "tags_count": tx.get("tags").and_then(Value::as_array).map(|t| t.len()),
            "number_of_confirmations": confirmations,
        })))
    }

    /// 由 RSA 公钥模数派生地址：**纯本地计算**，不访问网络。
    ///
    /// 输入格式：base64url（无填充）编码的 RSA 公钥**模数 n**。
    /// 注意不是完整的 JWK、也不是 PEM——只取模数那一段。
    async fn address_from_pubkey(&self, pubkey: &str) -> Result<AddressView, SdkError> {
        derive_address(pubkey, &self.network)
    }

    /// 转账：本地构造、RSA-PSS 签名并广播（`dry_run` 为 `true` 时只签名不广播）。
    ///
    /// AR 的「转账」本质是构造一笔 **ANS-104 数据交易**：带 `target` + `quantity`、
    /// `data` 为空。私钥（JWK JSON）只在本地参与 RSA 签名，绝不外发；
    /// 广播经由网关的 `POST /tx`。
    ///
    /// 领域说明：AR 是全链唯一用 **RSA-4096 + PSS** 的，交易 ID = `base64url(sha256(签名))`，
    /// 由 arweave-rs 的 `Provider` 完成 deep-hash 与签名，本方法复刻其 `sign_transaction`。
    async fn transfer(&self, req: TransferRequest) -> Result<TransferView, SdkError> {
        use arweave_rs::crypto::base64::Base64 as ArBase64;
        use arweave_rs::crypto::hash::ToItems;
        use arweave_rs::crypto::sign::Signer as ArSigner;
        use arweave_rs::crypto::Provider as ArProvider;
        use arweave_rs::transaction::client::TxClient;
        use arweave_rs::transaction::Tx;
        use jsonwebkey::JsonWebKey;
        use std::str::FromStr;
        use url::Url;

        // AR 私钥是 JWK JSON；解析出钱包签名器（纯本地，不触网）。
        let jwk: JsonWebKey = req
            .private_key
            .parse()
            .map_err(|e| SdkError::invalid_argument(format!("非法 AR JWK 私钥: {e}")))?;
        let signer = ArSigner::from_jwk(jwk);
        let provider = ArProvider::new(Box::new(signer));
        let from = provider.wallet_address().to_string();

        // 收款地址：AR 地址固定 43 字符 base64url。
        validate_address(&req.to)?;
        let target = ArBase64::from_str(&req.to)
            .map_err(|e| SdkError::invalid_argument(format!("非法 AR 收款地址: {e}")))?;
        // 金额：人类可读 AR → winston（u128，精度 12）。
        let amount_raw = parse_units(&req.amount, self.kind().decimals())?;

        // 用自定义网关构造交易客户端（负责取 last_tx / 估算 fee / 广播）。
        let base_url = Url::parse(self.rpc_url.trim_end_matches('/'))
            .map_err(|e| SdkError::invalid_argument(format!("非法 AR 网关 URL: {e}")))?;
        // `.clone()` 是廉价操作：`reqwest::Client` 内部是 `Arc`，克隆只加引用计数、
        // 共享同一个连接池，不会新建连接。
        let tx_client = TxClient::new(self.client.clone(), base_url).map_err(|e| {
            SdkError::new(ErrorCode::RpcError, format!("构造 AR 交易客户端失败: {e}"))
        })?;

        let last_tx = tx_client.get_last_tx().await.map_err(|e| {
            SdkError::new(ErrorCode::RpcError, format!("获取 AR last_tx 失败: {e}"))
        })?;
        let fee = tx_client.get_fee(target.clone(), Vec::new()).await.map_err(|e| {
            SdkError::new(ErrorCode::RpcError, format!("获取 AR 手续费失败: {e}"))
        })?;

        // 构造一笔「纯转账」交易（data 为空）。
        let mut tx = Tx::new(
            &provider,
            target,
            Vec::new(),
            amount_raw,
            fee,
            last_tx,
            vec![],
            false,
        )
        .map_err(|e| SdkError::new(ErrorCode::Internal, format!("构造 AR 交易失败: {e}")))?;

        // 本地签名：对交易的 deep hash 做 RSA-PSS 签名，再用签名的 sha256 当交易 ID。
        let deep_hash_item = tx.to_deep_hash_item().map_err(|e| {
            SdkError::new(ErrorCode::Internal, format!("AR deep hash 失败: {e}"))
        })?;
        let signature_data = provider.deep_hash(deep_hash_item);
        let signature = provider.sign(&signature_data).map_err(|e| {
            SdkError::new(ErrorCode::Internal, format!("AR 本地签名失败: {e}"))
        })?;
        let id = provider.hash_sha256(&signature.0);
        tx.signature = signature;
        tx.id = ArBase64(id.to_vec());

        // dry-run：只签名不广播，返回本地算出的交易 ID。
        if req.dry_run {
            let tx_id = tx.id.to_string();
            let signed_raw = serde_json::to_string(&tx)
                .map_err(|e| SdkError::new(ErrorCode::Internal, format!("序列化 AR 交易失败: {e}")))?;
            return Ok(TransferView::new(
                ChainKind::Ar,
                &self.network,
                Some(from),
                req.to,
                amount_raw,
                Some(tx_id),
                false,
            )
            .with_extra(json!({ "reward": fee, "signed_raw": signed_raw })));
        }

        // 真发：POST 已签名交易到网关 `/tx`。
        let (id, reward) = tx_client.post_transaction(&tx).await.map_err(|e| {
            SdkError::new(ErrorCode::RpcError, format!("广播 AR 交易失败: {e}"))
        })?;
        let tx_id = id.to_string();
        Ok(TransferView::new(
            ChainKind::Ar,
            &self.network,
            Some(from),
            req.to,
            amount_raw,
            Some(tx_id),
            true,
        )
        .with_extra(json!({ "reward": reward, "success": true })))
    }

    /// **无私钥**构造转账：取锚点与手续费 → 组装交易 → 算 deep hash → 交回调用方。
    ///
    /// 与 [`Self::transfer`] 的分工：
    /// - `transfer` 是**一体式**——私钥进 SDK，签名与广播都在 SDK 内完成；
    /// - `build_transfer` 是**两段式**的第一段——SDK 只负责构造，
    ///   签名交给调用方（agent）用自己的私钥做，私钥从不进入本进程。
    ///
    /// 领域说明——为什么 AR **必须**提供 `public_key`：
    /// 交易里有个 `owner` 字段，内容是 RSA 公钥的**模数 n**，
    /// 而 AR 地址 = `base64url(sha256(n))` —— 地址对模数是**单向**的，
    /// 无法从地址反推 `owner`。这与 EVM / BTC 完全不同：它们要么能从签名
    /// 恢复公钥，要么把公钥直接放在见证里，构造阶段不需要它。
    /// AR 是十条链里唯一「构造阶段就必须要公钥」的。
    ///
    /// 这里顺手做一次交叉校验：`sha256(n)` 必须等于 `from`，
    /// 否则说明调用方给错了公钥（或者给的是别人的地址），
    /// 立刻拦下——不拦的话会构造出一笔永远验不过签的交易。
    async fn build_transfer(&self, req: BuildTransferRequest) -> Result<BuildTransferView, SdkError> {
        let from = req.from.trim();
        validate_address(from)?;
        validate_address(&req.to)?;

        let public_key = req.public_key.as_deref().ok_or_else(|| {
            SdkError::invalid_argument(
                "AR 必须提供 public_key（RSA 模数 n 的 base64url）：\
                 交易的 owner 字段要写模数，而地址只是 sha256(模数)，无法反推",
            )
        })?;
        let modulus = crate::tx::decode_base64url(public_key)?;
        // 交叉校验：公钥 ↔ 地址必须对得上。
        //
        // 为什么用 `!=` 直接比字符串而不是先 `validate_address`：
        // 派生出的地址一定合法（sha256 输出 32 字节 → base64url 恒 43 字符），
        // 所以这里只需判断「是不是同一个人」。
        let derived = crate::tx::modulus_address(&modulus);
        if derived != from {
            return Err(SdkError::invalid_argument(format!(
                "public_key 与 from 不匹配：该模数派生出的地址是 {derived}，而 from 是 {from}"
            )));
        }

        // 金额：人类可读 AR → winston（12 位小数）。
        let amount_raw = parse_units(&req.amount, self.kind().decimals())?;
        let target = crate::tx::decode_base64url(&req.to)?;

        // 锚点交易（`last_tx`）：AR 用它做简单的重放保护，
        // 每个新块都会换一个，构造时必须现取。
        //
        // 为什么用 `get_text`：这个端点返回**纯文本**的 base64url，不是 JSON。
        let anchor = self.http.get_text("/tx_anchor").await.map_err(|e| {
            SdkError::new(ErrorCode::RpcError, format!("获取 AR last_tx 失败: {e}"))
        })?;
        let last_tx = crate::tx::decode_base64url(anchor.trim())?;

        // 手续费：`GET /price/{data_len}/{target}`。
        //
        // 注意分母里的 `0`：纯转账的 `data` 为空，按 0 字节计价；
        // 而 `target` 之所以要带上，是因为给**尚未上链**的地址转账会额外
        // 收取一笔「开户费」，网关只有知道收款方才算得出来。
        let price_path = format!("/price/0/{}", req.to.trim());
        let fee_value = self
            .http
            .get_value(&price_path)
            .await
            .map_err(|e| SdkError::new(ErrorCode::RpcError, format!("获取 AR 手续费失败: {e}")))?;
        let fee = chain_rpcutil::loose_u64(&fee_value).map_err(|e| {
            SdkError::new(ErrorCode::ParseError, format!("解析 AR 手续费失败: {e}"))
        })?;

        // 构造未签名交易。纯转账不带 tag——
        // 这与一体式的 `transfer` 有一处**有意的**差异：arweave-rs 的 `Tx::new`
        // 会自动塞一个 `User-Agent: arweave-rs/<版本>` 的 tag，
        // 两段式不该替调用方打上游的指纹，故这里为空。
        // 副作用是两条路径对同一笔输入会算出不同的 deep hash，
        // 这属于预期行为（tag 本身就是交易内容的一部分）。
        let tx = crate::tx::new_unsigned_tx(&modulus, &target, amount_raw, fee, &last_tx, vec![]);
        let digest = crate::tx::signing_digest(&tx)?;
        let unsigned_hex = crate::tx::tx_json_hex(&tx)?;
        let context =
            crate::tx::build_context(&self.network, &tx, &digest, from, req.to.trim());

        // 盐长：PSS 的**最大**盐长。交给调用方时必须写明——
        // 按「盐长 = 摘要长度（32）」的常规直觉签出来的签名，
        // 我们这边验得过（验签自动探测盐长），但**主网会拒收**。
        let salt_len = crate::tx::pss_salt_len(modulus.len());

        Ok(BuildTransferView::new(
            ChainKind::Ar,
            &self.network,
            from,
            req.to.trim(),
            amount_raw,
            unsigned_hex,
            // **真正要签的是 48 字节 deep hash**，不是上面的交易 JSON。
            hexutil::encode_hex_prefixed(&digest),
            "rsa-pss-sha256",
            // payload 已是最终待签对象，调用方**不要**再哈希；
            // RSA-PSS 内部会自己再做一次 sha256。
            "none",
        )
        .with_extra(json!({
            "last_tx": tx.last_tx.to_string(),
            "reward": fee,
            "data_size": 0,
            // —— 调用方指引 ——
            "signature_encoding": "hex 或 base64url",
            "signature_length": modulus.len(),
            "public_exponent": "65537",
            "pss_salt_length": salt_len,
            "pss_salt_rule": "modulus_len - 2 - 32（PSS 最大盐长）",
            "deep_hash_algorithm": "sha384（级联 deep hash，输出 48 字节）",
            "sighash_algorithm": "deep_hash(tx) → sha256 → RSA-PSS 签名",
            "unsigned_tx_encoding": "hex(utf8(交易 JSON))",
            "tx_id_note": "交易 ID = base64url(sha256(签名))，签名前不存在",
            // —— 广播阶段要原样回传 ——
            "submit_context": context,
            "note": "请用 RSA-PSS（SHA-256，盐长 = 模数字节数 - 34）对 signing_payload_hex 签名；\
                     把签名放进 SubmitRequest.signatures[0]（hex 或 base64url 均可，\
                     若用 base64url 请把 SubmitRequest.encoding 设为 base64url），\
                     并把 submit_context 原样放进 SubmitRequest.context，再调用 submit_tx。\
                     signed_tx_hex 在 AR 上不使用（留空即可）。",
            "next": "submit_tx",
        })))
    }

    /// 广播已签名交易。AR 收的是**单个签名 + 上下文**，不是拼好的交易字节。
    ///
    /// 领域说明——为什么不让 agent 自己填 `signature` 字段：
    /// 交易体是 JSON，字段顺序、`quantity` / `reward` 的字符串化、
    /// tag 的 base64url 编码都得与构造时一致，否则 deep hash 就变了。
    /// 让调用方照着文档重抄，出错时只会拿到一句 `invalid signature`，
    /// 无从判断是抄错了还是签错了。所以这里只收签名，由 SDK 重建并验签。
    ///
    /// 参数约定：
    /// - `signatures`：**恰好一个** RSA 签名，长度等于模数字节数；
    /// - `context`：`build_transfer` 下发的 `extra.submit_context`，原样回传；
    /// - `signed_tx_hex`：AR **不使用**（设为 `""` 即可）。
    async fn submit_tx(&self, req: SubmitRequest) -> Result<SubmitView, SdkError> {
        let encoding = req
            .encoding
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("hex");

        let context_value = req.context.ok_or_else(|| {
            SdkError::invalid_argument(
                "AR 广播必须回传 build_transfer 下发的 extra.submit_context：\
                 交易的 owner / last_tx / quantity / reward 都不在签名里，\
                 缺了它无法重组交易",
            )
        })?;
        let context: crate::tx::SubmitContext = serde_json::from_value(context_value)
            .map_err(|e| SdkError::invalid_argument(format!("submit_context 解析失败: {e}")))?;

        // 跨网护栏：AR 主网与测试网的交易字节与签名算法**完全相同**，
        // 链本身不做网络校验，所以这一步只能由 SDK 在广播前拦。
        if context.network != self.network {
            return Err(SdkError::invalid_argument(format!(
                "网络不匹配：该上下文是在 {} 构造的，当前客户端是 {}",
                context.network, self.network
            )));
        }

        let raw_signatures = req.signatures.ok_or_else(|| {
            SdkError::invalid_argument(
                "AR 广播需要 signatures 数组：请放入一个 RSA-PSS 签名（长度等于模数字节数）",
            )
        })?;
        // 用 `!=` 而不是 `<`：多给签名说明调用方把多签的语义套到 AR 上了，
        // 静默取第一个会掩盖这个误解。
        if raw_signatures.len() != crate::tx::SIGNATURE_COUNT {
            return Err(SdkError::invalid_argument(format!(
                "AR 一笔交易只需一个签名，收到 {} 个",
                raw_signatures.len()
            )));
        }
        let signature = crate::tx::parse_signature(&raw_signatures[0], encoding)?;

        // 重建交易（内含 deep hash 自检），再验签。
        let rebuilt = crate::tx::rebuild_tx(&context)?;
        let modulus = crate::tx::decode_base64url(&context.owner)?;
        crate::tx::verify_signature(&modulus, &rebuilt.signing_digest, &signature)?;

        // 长度要在 `attach_signature` 把 `signature` 移动进交易之前取下来。
        //
        // 语法说明：`attach_signature(tx, signature: Vec<u8>)` 按值接收，
        // 调用后 `signature` 就被**移动**了，之后不能再读它的长度——
        // 这是 Rust 所有权规则里最容易在重构时踩到的一条。
        let signature_length = signature.len();

        // 验签通过后才填签名——ID 由签名决定，故 `attach_signature` 一并算了 ID。
        let mut tx = rebuilt.tx;
        crate::tx::attach_signature(&mut tx, signature);
        let tx_id = tx.id.to_string();
        let body = crate::tx::tx_json(&tx)?;

        // 广播是唯一**不可逆**的操作，前面所有校验都是为了走到这里时已万无一失。
        post_tx_body(&self.client, &self.rpc_url, &body).await?;

        Ok(SubmitView::new(ChainKind::Ar, &self.network, tx_id.clone()).with_extra(json!({
            "broadcast": true,
            "tx_id": tx_id,
            "from": context.from,
            "to": context.to,
            "quantity_winston": context.quantity,
            "reward_winston": context.reward,
            "last_tx": context.last_tx,
            "signature_length": signature_length,
            "note": "AR 交易进入待确认池后即返回；是否最终上链请用 tx() 查询",
        })))
    }
}

/// `POST /tx`：把已签名交易交给网关。
///
/// 为什么不用 arweave-rs 的 `TxClient::post_transaction`：那份实现里有
/// `dbg!()` 调试输出（会往 stderr 打印整笔交易），在 MCP stdio / HTTP 长驻
/// 服务里是噪音；而且它失败时会自动 sleep 重试，把「广播」变成一个
/// 可能耗时数十秒的调用，不适合放在同步接口里。
async fn post_tx_body(client: &reqwest::Client, base: &str, body: &str) -> Result<(), SdkError> {
    let url = format!("{}/tx", base.trim_end_matches('/'));
    let resp = client
        .post(&url)
        // AR 网关只认 `application/json`；`reqwest` 的 `.json()` 会自己再序列化一遍
        // 字符串（于是发出 `"...\"..."` 这种二次编码的 JSON 字符串字面量），
        // 所以这里用 `.body()` 直接送已经拼好的原文。
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| SdkError::new(ErrorCode::RpcError, format!("广播 AR 交易失败: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        // 网关在拒绝时会在响应体里给出原因（`tx_already_in_weave` / `invalid_signature` …），
        // 这个信息非常关键，一定要带出来。
        let text = resp.text().await.unwrap_or_default();
        return Err(SdkError::new(
            ErrorCode::RpcError,
            format!("广播 AR 交易失败: HTTP {status}; 响应: {}", truncate(&text)),
        ));
    }
    Ok(())
}

/// 截断字符串，避免把整页 HTML 塞进错误信息。
fn truncate(s: &str) -> String {
    const MAX: usize = 300;
    if s.chars().count() <= MAX {
        s.to_string()
    } else {
        let head: String = s.chars().take(MAX).collect();
        format!("{head}…（已截断）")
    }
}

/// RSA 公钥模数（base64url）→ Arweave 地址（base64url(sha256(n))）。
///
/// 领域说明：Arweave 是唯一用 **RSA** 的链（4096 位，PSS 填充）。
/// 地址 = `base64url(sha256(模数 n 的原始大端字节))`：
/// - sha256 输出 32 字节；
/// - 32 字节按 base64url 编码无填充恰好是 **43 个字符**（ceil(32*8/6) = 43）；
/// - 因此地址长度恒为 43，这也是 `validate_address` 里那条硬约束的由来。
///
/// 与其余链的对比：ETH 取 keccak256 的后 20 字节，APT 取 sha3-256 的全部 32 字节，
/// CKB 取 blake2b 的前 20 字节——Arweave 是唯一先哈希再整体 base64url 的。
fn derive_address(pubkey: &str, network: &str) -> Result<AddressView, SdkError> {
    // `URL_SAFE_NO_PAD.decode` 是 `Engine` trait 的方法，返回 `Result<Vec<u8>, DecodeError>`。
    // `map_err` 把 base64 自己的错误换成统一错误码，并保留原文便于排查。
    let modulus = URL_SAFE_NO_PAD.decode(pubkey.trim()).map_err(|e| {
        SdkError::invalid_argument(format!("AR 公钥需为 base64url 的 RSA 模数 n: {e}"))
    })?;
    // Arweave 主网使用 4096 位 RSA（模数 512 字节）；不强制长度，只记录真实字节数。
    //
    // 为什么**不**校验长度：arlocal 与部分测试环境用 2048 位密钥（256 字节），
    // 卡死 512 会把这些环境挡在门外；而地址派生本身对任何长度都成立。
    // 因此这里只如实记录 `modulus.len()`，交由调用方判断。
    //
    // `Sha256::digest(&modulus)` 是 `Digest` trait 提供的**一次性**便捷方法，
    // 等价于 `Sha256::new().chain_update(&modulus).finalize()`。
    let digest = Sha256::digest(&modulus);
    // `Vec<u8>` → `&[u8]` 的 deref coercion 由 `&` 自动完成。
    let address = URL_SAFE_NO_PAD.encode(digest);
    // 派生完立刻自检：既验证实现对，也保证下游拿到的地址一定是合法的 43 字符。
    validate_address(&address)?;
    Ok(AddressView::new(
        ChainKind::Ar,
        network,
        // 回填 trim 后的原始输入（而非重新编码），便于调用方核对。
        pubkey.trim(),
        address,
        "rsa-modulus-sha256",
        modulus.len(),
    )
    .with_extra(json!({
        "derivation": "base64url(sha256(rsa_modulus_bytes))",
    })))
}

/// 把交易里的 `owner` 字段（RSA 模数的 base64url）转成 43 字符地址。
///
/// 与 [`derive_address`] 的算法完全一致，区别只在错误处理：
/// 这里是解析**上游返回的数据**，出问题属于 `PARSE_ERROR`（可重试的上游异常）；
/// 而 `derive_address` 处理的是**调用方输入**，出问题属于 `INVALID_ARGUMENT`（不可重试）。
fn owner_to_address(owner_b64url: &str) -> Result<String, SdkError> {
    let modulus = URL_SAFE_NO_PAD.decode(owner_b64url).map_err(|e| {
        SdkError::new(
            ErrorCode::ParseError,
            format!("owner 不是合法 base64url: {e}"),
        )
    })?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(modulus)))
}

/// 校验 Arweave 地址 / 交易 ID：base64url 无填充，地址固定 43 字符。
///
/// 两道关卡：
/// 1. 长度必须恰好 43，且字符只可能是 `A-Za-z0-9-_`（base64url 字母表）；
/// 2. 再真正 `decode` 一次，挡住形似而神不似的输入
///    （比如长度凑够但含非法 base64 序列的字符串）。
fn validate_address(raw: &str) -> Result<(), SdkError> {
    let t = raw.trim();
    // 用 `.bytes()` 而非 `.chars()`：地址恒为 ASCII，按字节遍历更快，
    // 也顺带拒绝任何非 ASCII（比如中文）——`bytes()` 取出的字节必然 > 127，
    // 不可能通过 `is_ascii_alphanumeric`。
    if t.len() != 43
        || !t
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(SdkError::invalid_argument(format!(
            "非法 AR 地址: {raw}（期望 43 字符 base64url 字符串）"
        )));
    }
    URL_SAFE_NO_PAD
        .decode(t)
        .map_err(|e| SdkError::invalid_argument(format!("非法 AR 地址: {e}")))?;
    Ok(())
}

/// 校验交易 / 区块 ID：同样是 43 字符 base64url，但**不做** decode 复检。
///
/// 与 [`validate_address`] 的差异是刻意的：地址会被送去派生、会被反复使用，
/// 值得多花一次 decode；而 ID 只是拼进 URL 交给网关，网关自己会拒绝非法值，
/// 本地没必要重复校验。
fn validate_txid(raw: &str) -> Result<(), SdkError> {
    let t = raw.trim();
    if t.len() != 43
        || !t
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(SdkError::invalid_argument(format!(
            "非法 AR 交易/区块 ID: {raw}（期望 43 字符 base64url 字符串）"
        )));
    }
    Ok(())
}

/// 单元测试模块。
///
/// 语法说明：`#[cfg(test)]` 是**条件编译属性**：只在 `cargo test` 时编译，
/// 正式构建里完全不存在，不占体积。Rust 的惯例是把测试就地写在被测代码旁边。
#[cfg(test)]
mod tests {
    // `use super::*` 把父模块的所有条目导入，于是可直接写 `validate_address`。
    use super::*;

    #[test]
    fn validates_arweave_ids() {
        // 64 字符的字符串其实是「完整 base64url（带填充语义）的公钥」，
        // 不是地址——长度校验必须把它挡掉。
        assert!(
            validate_address("vmcOl107fL4JN0UDrQwCxA_zkp32MlAsWvsKZ3Wea8si7YZbnvNG-xku3QUenAPE")
                .is_err()
        ); // 64 字符，超长
        assert!(validate_txid("CwaasGHuRNeJqkPiVwnqfj3BHb0XJaO41JHUeNc4kow").is_ok()); // 43
        assert!(validate_txid("short").is_err());
        // 中文字符按 UTF-8 是 3 字节/字，`t.len()` 会远超 43，被长度校验挡下。
        assert!(
            validate_txid("含有中文字符________________base64url_____________________").is_err()
        );
    }

    #[test]
    fn derives_address_from_owner() {
        // 全 0x03 的 512 字节模数，派生结果稳定。
        let n = URL_SAFE_NO_PAD.encode([3u8; 512]);
        let view = derive_address(&n, "mainnet").unwrap();
        assert_eq!(view.address.len(), 43);
        assert_eq!(view.pubkey_bytes, 512);
        // 与 owner_to_address 路径一致。
        assert_eq!(view.address, owner_to_address(&n).unwrap());
    }
}
