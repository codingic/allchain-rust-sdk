# allchain-rust-sdk

一套 Rust 实现的多链统一操作 SDK（查询 + 原生资产转账），对外提供**统一接口**：

- 一条命令 / 一个 HTTP 端点 / 一个 MCP 工具，操作 **ETH / BTC / SOL / NEAR / APT / AR / CKB / FIL / SUI / TON** 十链；
- 返回**结构完全一致**的 JSON 信封，错误码跨链统一，agent 无需按链分支解析；
- 前四链基于官方 Rust SDK（alloy、rust-bitcoin、solana-rpc-client、near-jsonrpc-client）；后六链为避免拖入庞大依赖树，统一走共享轻量 HTTP 库 `chain-rpcutil`（REST / JSON-RPC / GraphQL）直连公共端点。

> **能力边界**：十链全部支持只读四件套 `status` / `balance` / `block` / `tx` 与本地 `address_from_pubkey`（TON 除外，其地址由钱包合约 StateInit 决定、不能仅由公钥派生）；`transfer` 本地签名目前仅 ETH / BTC / SOL / NEAR 实现，其余六链返回 `UNSUPPORTED`。`acli chains` 可查看每链实时能力清单。

---

## 1. 快速开始

```bash
git clone <this-repo>
cd allchain-rust-sdk
cargo build --release          # 首次约 10-20 分钟（Solana 依赖树较大）
./target/release/acli chains
```

产物只有一个二进制：`target/release/acli`（本 workspace 所有链 crate 均为库，只被 acli 引用）。工具链由 `rust-toolchain.toml` 锁定为 **1.93.0**（NEAR SDK 0.22 的硬性要求）。

---

## 2. 三种接入形态

### 2.1 命令行（默认输出 JSON）

```bash
acli chains
acli status  --chain btc
acli balance --chain eth --address 0x00000000219ab540356cbb839cbe05303d7705fa
acli getbalance --chain eth --address 0x...                  # balance 的别名
acli block   --chain sol --reference 340000000
acli tx      --chain near --hash <tx_hash>@<sender.near>
acli address-from-pubkey --chain eth --pubkey 0x04...        # 公钥 -> 地址（本地计算）
acli transfer --chain eth --to 0x... --amount 0.01 --dry-run  # 转账（--dry-run 只本地签名，不广播）
acli status  --chain btc --format text          # 人类可读的对齐文本
```

转账的参数（私钥格式随链而异）：

| 参数 | 说明 |
|---|---|
| `--to` | 收款地址 / 账户（NEAR 传账户名） |
| `--amount` | 金额，原生单位（如 `0.01`）；BTC 还支持 `10000sat` |
| `--private-key` | 私钥：ETH 32 字节十六进制 / BTC WIF / SOL JSON 数组或 base58 / NEAR `ed25519:...` |
| `--dry-run` | 只本地构造并签名，返回预期 `tx_hash` / `txid` / `signature`，**绝不广播** |
| `--from` | 源账户（NEAR 命名账户必填；省略时按私钥派生隐式账户） |

私钥缺省时按链读环境变量：`ETH_SECRET_KEY` / `BTC_WIF` / `SOL_KEYPAIR` / `NEAR_SECRET_KEY`
（避免出现在 shell 历史里）。**先 `--dry-run` 审计，再正式转账。**

公共参数：

| 参数 | 说明 |
|---|---|
| `--chain` | `eth` / `btc` / `sol` / `near` / `apt` / `ar` / `ckb` / `fil` / `sui` / `ton`（别名：aptos / arweave / nervos / filecoin） |
| `--network` | 网络名，十链缺省均为 `mainnet` |
| `--rpc-url` | 自定义端点（BTC 上是 Esplora 索引器，SUI 上是 GraphQL 端点） |
| `--format` | `json`（默认）或 `text` |

退出码：成功 `0`，失败 `1`（错误详情在 JSON 的 `error` 字段里）。

### 2.2 本地 HTTP 服务

```bash
acli serve --port 8787
```

```bash
curl 'http://127.0.0.1:8787/v1/chains'
curl 'http://127.0.0.1:8787/v1/status?chain=btc'
curl 'http://127.0.0.1:8787/v1/balance?chain=eth&address=0x...'
curl 'http://127.0.0.1:8787/v1/getbalance?chain=eth&address=0x...'   # balance 的别名
curl 'http://127.0.0.1:8787/v1/block?chain=sol&reference=340000000'
curl 'http://127.0.0.1:8787/v1/tx?chain=near&hash=<tx_hash>@<sender.near>'
curl 'http://127.0.0.1:8787/v1/address-from-pubkey?chain=btc&pubkey=02...'
# 转账（POST，敏感字段放 body）：
curl -X POST 'http://127.0.0.1:8787/v1/transfer' -H 'Content-Type: application/json' \
  -d '{"chain":"eth","to":"0x...","amount":"0.01","dry_run":true}'
```

HTTP 状态码映射：`INVALID_ARGUMENT → 400`、`NOT_FOUND → 404`、`NETWORK_ERROR / RPC_ERROR → 502`、`UNSUPPORTED → 501`、`PARSE_ERROR / INTERNAL → 500`。

### 2.3 MCP stdio（agent 原生接入）

```bash
acli mcp
```

进程从 stdin 读 JSON-RPC，往 stdout 写 JSON-RPC（MCP `2024-11-05` stdio 传输）。

在支持 MCP 的客户端里加一条服务器配置即可：

```json
{
  "mcpServers": {
    "allchain": {
      "command": "/absolute/path/to/allchain-rust-sdk/target/release/acli",
      "args": ["mcp"]
    }
  }
}
```

暴露 8 个工具，agent 通过 `tools/list` 自动发现、无需读文档：

| 工具 | 必填参数 | 说明 |
|---|---|---|
| `chain_catalog` | — | 支持的链、精度、默认网络 |
| `chain_status` | `chain` | 节点与链状态 |
| `chain_balance` | `chain`, `address` | 余额 |
| `chain_get_balance` | `chain`, `address` | 余额（`chain_balance` 的别名） |
| `chain_block` | `chain`，`reference`（SOL 必填为 slot；SUI 为 checkpoint 序号；TON 为主链 seqno） | 区块 |
| `chain_tx` | `chain`, `hash` | 交易（NEAR 需 `<hash>@<account>`，TON 需 `<hash>:<lt>@<address>`） |
| `chain_address_from_pubkey` | `chain`, `pubkey` | 公钥 → 地址（本地计算；TON 不支持） |
| `chain_transfer` | `chain`, `to`, `amount` | 原生资产转账（**仅 eth/btc/sol/near**；可选 `private_key` / `dry_run` / `from`） |

除 `chain_catalog` 外都可选 `network` 与 `rpc_url`。
`chain_balance` 另接受别名 `chain_get_balance` / `get_balance` / `getbalance`；
`chain_address_from_pubkey` 另接受别名 `get_address_from_pubkey` / `getaddressfrompubkey`。

---

## 3. 统一响应契约

三种形态返回**完全相同**的结构。成功：

```json
{
  "ok": true,
  "chain": "btc",
  "network": "mainnet",
  "took_ms": 312,
  "data": {
    "chain": "btc",
    "network": "mainnet",
    "rpc_url": "https://mempool.space/api",
    "latest_height": 964458,
    "latest_hash": "0000000000000000000...",
    "node_version": null
  }
}
```

失败：

```json
{
  "ok": false,
  "chain": "near",
  "network": "testnet",
  "took_ms": 402,
  "error": {
    "code": "NOT_FOUND",
    "message": "查询账户失败: ...",
    "retryable": false
  }
}
```

`ok=true` 时**不会**出现 `error` 键，反之亦然。

错误码：`INVALID_ARGUMENT` / `NOT_FOUND` / `RPC_ERROR` / `NETWORK_ERROR` / `PARSE_ERROR` / `UNSUPPORTED` / `INTERNAL`。
`retryable=true` 的只有 `NETWORK_ERROR` 与 `RPC_ERROR`。

### 数据模型

`data` 的顶层字段在十链上**稳定存在**，链间无对应值的字段为 `null`；链专有字段通过 `extra` 平铺在同一层级，不破坏公共 schema。

| 动作 | 公共字段 |
|---|---|
| `status` | `latest_height`、`latest_hash`、`node_version` |
| `balance` | `address`、`balance_raw`（最小单位整数字符串）、`balance_ui`（可读）、`symbol`、`decimals` |
| `block` | `height`、`hash`、`parent_hash`、`timestamp`、`tx_count` |
| `tx` | `hash`、`status`、`from`、`to`、`amount_raw`、`amount_ui`、`fee_raw`、`height`、`timestamp`、`confirmations` |
| `address_from_pubkey` | `pubkey`、`address`、`address_type`、`pubkey_bytes` |

金额一律用**字符串**承载最小单位整数（wei / satoshi / lamport / yoctoNEAR / octa / winston / shannon / attoFIL / MIST / nanoton），避免 JSON number 在大整数上的精度丢失。

### `address_from_pubkey`：公钥派生地址

**纯本地计算，完全不联网**，因此无速率限制、无端点依赖、可用于冷环境。

```bash
acli address-from-pubkey --chain eth  --pubkey 0x04<128 位十六进制>   # 或 64 字节裸坐标
acli address-from-pubkey --chain btc  --pubkey 02<66 位十六进制>      # 压缩公钥
acli address-from-pubkey --chain sol  --pubkey <base58 或 64 位十六进制>
acli address-from-pubkey --chain near --pubkey ed25519:<base58>
acli address-from-pubkey --chain apt  --pubkey <64 位十六进制 32B ed25519>
acli address-from-pubkey --chain ar   --pubkey <RSA 模数 n 的 base64url>
acli address-from-pubkey --chain ckb  --pubkey 02<66 位十六进制 33B 压缩>
acli address-from-pubkey --chain fil  --pubkey 04<130 位十六进制 65B 未压缩>
acli address-from-pubkey --chain sui  --pubkey [ed25519:|secp256k1:]<hex>
# TON 不支持：地址是钱包合约 StateInit 的哈希，依赖具体钱包版本（V3/V4R2/W5），公钥无法唯一确定
```

| 链 | 接受的公钥 | 主地址 `address` | `address_type` | `extra` 里的额外信息 |
|---|---|---|---|---|
| ETH | 64 字节坐标 或 65 字节带 `04` 前缀（hex） | EIP-55 校验和地址 | `eoa` | `lowercase`、`derivation` |
| BTC | 33 字节**压缩**公钥（hex） | P2WPKH（`bc1q...`） | `p2wpkh` | `alternatives.p2pkh` / `.p2sh_p2wpkh` / `.p2tr` |
| SOL | base58 或 64 位十六进制的 32 字节 ed25519 公钥 | base58（与公钥同串） | `ed25519` | `pubkey_hex`、`derivation` |
| NEAR | `ed25519:<base58>`（或裸 base58 / hex） | 隐式账户（64 位十六进制） | `implicit` | `account_id`、`key_type` |
| APT | 32 字节 ed25519 公钥（hex） | `0x` + 64 位十六进制 | `ed25519` | `derivation`（sha3-256(pk‖0x00)） |
| AR | RSA 公钥模数 n（base64url，4096-bit） | 43 字符 base64url | `rsa-sha256` | `derivation`（base64url(sha256(n))） |
| CKB | 33 字节压缩 secp256k1 公钥（hex） | full 格式 `ckb1...` | `secp256k1-blake160-full` | `alternatives.short_deprecated`、`lock_args` |
| FIL | 65 字节**未压缩** secp256k1 公钥（hex） | `f1...`（主网）/ `t1...` | `f1-secp256k1` | `protocol`、`derivation` |
| SUI | 32B ed25519（默认）或 33B secp256k1，可带方案前缀 | `0x` + 64 位十六进制 | `ed25519-blake2b` 等 | `scheme`、`flag`、`derivation` |

响应示例（BTC，字段已精简）：

```json
{
  "ok": true, "chain": "btc", "network": "mainnet", "took_ms": 0,
  "data": {
    "chain": "btc", "network": "mainnet",
    "pubkey": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "address_type": "p2wpkh",
    "pubkey_bytes": 33,
    "alternatives": {
      "p2pkh": "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
      "p2sh_p2wpkh": "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
      "p2tr": "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9"
    }
  }
}
```

注意：

1. **ETH 不接受压缩公钥**（`02`/`03` 开头的 33 字节），需先解压为 64 字节坐标；
2. **BTC / CKB 不接受未压缩公钥**，需先压缩为 33 字节；**FIL 相反，要求 65 字节未压缩公钥**；
3. BTC / CKB / FIL 的地址前缀随网络变化（如 BTC `mainnet → bc1`、`testnet → tb1`；CKB `ckb` / `ckt`；FIL `f` / `t`），`--network` 会影响结果。

---

## 4. 各链差异与注意事项

**十链默认均为主网**，需要测试网时显式传 `--network`。

| 链 | 默认网络 | 可选网络 | 地址格式 |
|---|---|---|---|
| ETH | `mainnet` | `mainnet` / `sepolia` / `localnet` | `0x` + 40 位十六进制 |
| BTC | `mainnet` | `mainnet` / `testnet` / `testnet4` / `signet` / `regtest` | 各类比特币地址 |
| SOL | `mainnet` | `mainnet` / `devnet` / `testnet` / `localnet` | base58 公钥 |
| NEAR | `mainnet` | `mainnet` / `testnet` / `localnet` | 账户名，如 `example.near` |
| APT | `mainnet` | `mainnet` / `testnet` / `devnet` / `localnet` | `0x` + 64 位十六进制 |
| AR | `mainnet` | `mainnet` / `localnet` | 43 字符 base64url |
| CKB | `mainnet` | `mainnet` / `testnet` / `local` | bech32：`ckb1...` / `ckt1...` |
| FIL | `mainnet` | `mainnet` / `calibration` / `local` | `f0/f1/f2/f3...`（测试网 `t` 前缀） |
| SUI | `mainnet` | `mainnet` / `testnet` / `devnet` / `localnet` | `0x` + 64 位十六进制（GraphQL 端点） |
| TON | `mainnet` | `mainnet` / `testnet` / `localnet` | raw `wc:64hex` 或 EQ/UQ 用户友好地址 |

必须知道的坑：

1. **十链默认就是主网**。只读查询无风险；`transfer` 直接动主网资金（仅前四链支持），务必先 `--dry-run` 确认收款方与 `--network`，切测试网要显式指定。
2. **SOL 按 slot 查区块**，不是区块高度，且 `block` 必须显式传 `--reference`；公共节点只保留最近约 1–2 天的区块，mainnet 公共端点对 `getBlock` 限流较严，生产建议换私有 RPC。
3. **NEAR 查交易必须带发送者**：`--hash <tx_hash>@<sender.near>`。历史交易还要改用归档端点 `--rpc-url https://archival-rpc.mainnet.near.org`。
4. **BTC 的 `--rpc-url` 是 Esplora 索引器地址**，不是 bitcoind 的 JSON-RPC 端点；余额、UTXO 类查询必须有索引器。
5. **SUI 只走 GraphQL**：官方公共 fullnode 的 JSON-RPC 已废弃，主网端点是 `https://graphql.mainnet.sui.io/graphql`；区块叫 checkpoint（传序号），交易数取相邻 checkpoint 的 `networkTotalTransactions` 差值。
6. **TON 公共端点（toncenter）限速约 1 req/s**，客户端已内置 1.1s 串行节流（可设 `TONCENTER_API_KEY` 提速）；查交易必须三要素 `<tx_hash>:<lt>@<address>`，只给 hash 查不到。
7. **FIL 回执**：Glif 公共端点不提供 `ChainGetReceipt`，实现改用 `StateSearchMsg` 获取 ExitCode / GasUsed / 上链高度；刚广播未上链的消息为 `pending`。

BTC 的交易没有单一「金额」语义（多输入多输出），`amount_raw` 为 `null`，完整 `inputs` / `outputs` 明细在同层级的 extra 字段里。

---

## 5. 工程结构

```
allchain-rust-sdk/
├── core/                 统一契约：ChainKind / 数据模型 / 错误码 / ChainClient trait
├── chain/
│   ├── rpcutil/          共享轻量 HTTP：REST GET / JSON-RPC POST / GraphQL POST（chain-rpcutil）
│   ├── eth/              alloy 2.1          + adapter（官方 SDK，含本地签名 transfer）
│   ├── btc/              rust-bitcoin 0.32  + adapter（官方 SDK，含 transfer）
│   ├── sol/              solana-rpc 4.2     + adapter（同步 API，内部 spawn_blocking，含 transfer）
│   ├── near/             near-jsonrpc 0.22  + adapter（官方 SDK，含 transfer）
│   ├── apt/ ar/ ckb/ fil/ sui/ ton/  六新链 adapter（rpcutil 直连，只读 + 地址派生）
└── acli/                 统一门面：CLI / HTTP / MCP 三种形态
```

每个链 crate 都是纯库（`eth_sdk` / `btc_sdk` / … / `sui_sdk` / `ton_sdk`），只被 `acli` 引用，全仓只有一个二进制 `acli`。

### 新增一条链

1. 在 `core/src/chain.rs` 的 `ChainKind` 加变体，补齐 `parse` 别名 / `symbol` / `unit_name` / `decimals` / `default_network`，并在 `capabilities()` 如实声明能力；
2. 建 `chain/<new>/src/{lib,network,adapter}.rs`（优先用 `chain-rpcutil` 直连，避免拖入官方 SDK 依赖树），实现 `ChainClient`（`status` / `balance` / `block` / `tx` 必做；可选 `address_from_pubkey`——trait 有默认实现，不实现会返回 `UNSUPPORTED`；`transfer` 同理）；
3. 在 `acli/src/dispatch.rs` 的 `build_client` 加分支、`private_key_env` 补穷尽分支；
4. 把新 crate 加进根 `Cargo.toml` 的 `members` 与 `acli` 的依赖；同步 `main.rs` 帮助文本与 `mcp.rs` 的 chain enum / 工具描述。

MCP 工具与 HTTP 端点**无需改动**，会自动支持新链。

新增一个**动作**则要动三处：`acli/src/dispatch.rs` 的 `Action` 枚举 + `run_action` 分支、
`main.rs` 的子命令、`http.rs` 的路由与参数结构体，以及 `mcp.rs` 的工具定义与 `execute` 分支。

---

## 6. 验证

```bash
cargo check --workspace --all-targets   # 零 error 零 warning
cargo test --workspace                  # 单测
cargo clippy --workspace --all-targets  # 零警告
```

上线前建议对每条链跑一次真实只读查询（见 `各链 README` 的实测记录）。
