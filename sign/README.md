# sign — 本地离线签名服务

`sign` 是 `allchain-rust-sdk` 下的一个**离线签名器**：在进程内生成密钥对、按地址存入内存、对未签名交易签名并组装成可广播交易。

- 监听地址：`127.0.0.1:7878`（**回环、无鉴权**，只接受本机信任进程的调用）
- 私钥**绝不落盘**：仅在 `getprikey` 响应中出现一次，并驻留进程内存；进程退出即清空。
- 支持链：`eth`（secp256k1）+ `sol` / `near` / `apt` / `sui` / `ton`（ed25519）。
- 延后链（暂未实现）：`btc` / `ckb` / `fil`（secp256k1）、`ar`（RSA）。

---

## 1. 构建与运行

```bash
cd allchain-rust-sdk
export PATH="/Users/wangbinmac/.cargo/bin:$PATH"
cargo +1.93.0 build -p sign --release
# 或直接运行
cargo +1.93.0 run -p sign
# 可选自定义监听地址（仍建议保持回环）
cargo +1.93.0 run -p sign -- --host 127.0.0.1 --port 7878
```

启动后监听 `http://127.0.0.1:7878`。

---

## 2. 端点

所有响应复用 `allchain-core` 的统一信封 `Envelope<T>`（`{chain, network, took_ms, data/error, code}`），与 `acli` 的 CLI / HTTP / MCP 三形态保持一致。

### 2.1 `GET /v1/getprikey?chaintype=<chain>`

为指定链随机生成密钥对、派生原生地址、写入内存密钥库，并返回私钥（32 字节种子，hex）+ 地址。

成功响应 `data`：

```json
{
  "chain": "sol",
  "scheme": "ed25519",
  "address": "<原生地址>",
  "private_key": "0x<64hex 种子>",
  "public_key": "<公钥展示：hex 或 base58，随链>"
}
```

`chaintype` 取值：`eth` / `sol` / `near` / `apt` / `sui` / `ton`。其它值返回 `Unsupported`。

> **务必保存返回的 `address`**：后续 `signtx` 的 `fromaddress` 必须与此完全一致（内存库按地址精确索引）。

### 2.2 `POST /v1/signtx`

请求体：

```json
{
  "chaintype": "eth",
  "txdatahex": "0x<未签名交易的原始字节，hex 可带 0x 前缀>",
  "fromaddress": "<此前 getprikey 返回的地址>"
}
```

行为：

1. 解码 `txdatahex` 为原始字节；
2. 按 `fromaddress` 从内存库取种子（不在库中 → `InvalidArgument`，须先 `getprikey`）；
3. 按链重建签名器，对未签名交易签名并组装完整可广播交易；
4. 返回 `signature` 与 `signed_tx`。

成功响应 `data`：

```json
{
  "chain": "eth",
  "from_address": "0x...",
  "scheme": "ed25519",
  "signature": "0x<签名字节>",
  "signed_tx": "0x<完整签名交易，可直接广播>",
  "encoding": "hex",
  "note": null
}
```

- `encoding`：`hex` 或 `base64`（见下表）。
- `signed_tx`：TON 为 `null`（仅返回签名，完整 external message 需钱包 code/state-init 组装）。

### 2.3 `GET /v1/chains`

返回能力清单：每条链的 `scheme`、`signed_tx_encoding`、`assembles_full_tx`。

### 2.4 `GET /`

简短服务说明。

---

## 3. 各链 `txdatahex` 契约（未签名交易格式）

`signtx` 并不构造交易，它只**解析你提供的未签名交易字节并签名**。构造合法未签名交易（填好 nonce / gas / fee / 指令等）是调用方的责任——通常先用各链 SDK 或 RPC（`simulateTransaction` / `getFee` / `createTransaction` 等）拿到未签名体，再交给本服务签名。

| 链 | `txdatahex` = 未签名交易的序列化字节 | 解析方式 | `signed_tx` 编码 | 组装产物 |
|----|--------------------------------------|----------|------------------|----------|
| `eth` | EIP-2718 类型化交易（**无签名段**）的 RLP：`0x02` ‖ RLP(\[chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList\]) | `alloy::consensus::TypedTransaction::decode_unsigned` | hex | `EthereumTxEnvelope`（rlp）可直接 `eth_sendRawTransaction` |
| `sol` | `solana_sdk::transaction::Transaction` 的 **bincode** 字节（签名槽留空） | `bincode::deserialize` | base64 | 填好 `signatures[0]` 的 `Transaction` 可直接 `sendTransaction` |
| `near` | `near_primitives::transaction::Transaction` 的 **Borsh** 字节（签名 = None） | `borsh::BorshDeserialize::try_from_slice` | hex | `SignedTransaction`（Borsh）可直接 `broadcast_tx_commit` |
| `apt` | `aptos_sdk::transaction::types::RawTransaction` 的 **BCS** 字节 | `bcs::from_bytes` | hex | `SignedTransaction`（BCS）可直接 `submit` |
| `sui` | `sui_sdk_types::Transaction` 的 **BCS** 字节 | `bcs::from_bytes` | base64 | `SignedTransaction`（BCS）可直接 `sui_executeTransactionBlock` |
| `ton` | 待签名的 external message 负载字节 | 直接 `sk.sign(msg)` | —（返回 `signature`，`signed_tx=null`） | 仅 ed25519 签名；完整 cell 需钱包 code/state-init |

> **地址格式（各链 `fromaddress` 必须匹配 `getprikey` 返回）**
> - `eth` / `apt` / `sui`：`0x` + 40 hex（小写）
> - `sol`：base58 公钥
> - `near`：`ed25519:<base58>`
> - `ton`：`0x` + 64 hex（原始 ed25519 公钥）

---

## 4. 调用示例（curl）

```bash
# 1) 生成 SOL 密钥
curl "http://127.0.0.1:7878/v1/getprikey?chaintype=sol"
# => {"data":{"address":"<base58>","private_key":"0x...","public_key":"<base58>",...}}

# 2) 对一条未签名 SOL 交易签名（txdatahex 换成真实 bincode 字节的 hex）
curl -X POST "http://127.0.0.1:7878/v1/signtx" \
  -H 'Content-Type: application/json' \
  -d '{"chaintype":"sol","txdatahex":"0x...","fromaddress":"<上一步的 address>"}'
# => {"data":{"signature":"0x...","signed_tx":"<base64 完整交易>","encoding":"base64",...}}
```

---

## 5. 安全模型

- **无持久化**：密钥仅存进程内存，退出即失；不写文件、不进日志、不进信封 `error`。
- **无鉴权 + 回环**：仅绑定 `127.0.0.1`，不可对外暴露；任何能访问该端口的本地进程都能取私钥与签名。
- **密钥复用风险**：同一 `address` 再次 `getprikey` 会覆盖旧种子；`signtx` 不校验 nonce，由调用方保证交易不重放。
- **延后链**：`btc` / `ckb` / `fil`（secp256k1，需 UTXO / 地址脚本语义）与 `ar`（RSA）尚未实现，调用返回 `Unsupported`。

---

## 6. 测试

```bash
cargo +1.93.0 test -p sign
```

覆盖：`is_supported` 矩阵、`getprikey` 对 6 链的「生成 → 存入 → 取回」往返（种子/算法族一致性）、ed25519 种子重建密钥对的独立 sign/verify、地址格式与 `scheme` 分配。
