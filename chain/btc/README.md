# btc-rpc-cli

> 注：该单链 CLI 已并入统一入口 [`acli`](../README.md)（CLI / HTTP / MCP 三种形态，`transfer` 支持 dry-run）。
> 本目录现在是一个纯库 `btc_sdk`，被 acli 引用；以下为历史实现说明。

Bitcoin 链上交互库，基于 rust-bitcoin 官方生态：

- `bitcoincore-rpc` 0.19 — Bitcoin Core JSON-RPC 客户端（自建节点数据源）
- `bitcoin` 0.32 — 地址、私钥、交易结构与离线签名
- Esplora REST（`mempool.space` 等） — 免节点的查询与广播数据源

**双数据源设计**：没有本地 bitcoind 也能完整使用（走 Esplora 公共索引器）；配置了节点参数后，节点可用的查询与广播优先走自己的节点。

## 技术栈

| 组件 | 版本 | 说明 |
| --- | --- | --- |
| `bitcoincore-rpc` | 0.19 | Bitcoin Core JSON-RPC（最新稳定版） |
| `bitcoin` | 0.32 | 与 bitcoincore-rpc-json 0.19 内部依赖一致 |
| `reqwest` / `tokio` | — | Esplora HTTP 客户端与异步运行时 |

版本必须配对：bitcoincore-rpc 0.19 依赖 `bitcoin ^0.32`，混用 0.31 会类型冲突。

## 构建

```bash
cargo build --release -p btc-sdk
```

## 命令

全局参数：

- `-n/--network`：`mainnet`（默认）/ `testnet` / `testnet4` / `signet` / `regtest`
- `--esplora-url`：索引器地址（默认 mainnet 用 `https://mempool.space/api`）
- `--node-url`：自建 bitcoind 地址（不带值时用该网络默认本地端口）
- `--node-user` / `--node-pass` / `--cookie`：节点认证

```bash
# 链状态
cargo run -- status

# 区块（缺省链尖，可传高度或哈希）
cargo run -- block 964458
cargo run -- block 000000000000000000013a9cb1b95e144781b3c92f0dfca614b75a0a82f21ae6

# 交易（--hex 同时打印 raw hex）
cargo run -- tx <txid> --hex

# 地址余额与统计
cargo run -- address bc1q...

# 地址 UTXO 列表
cargo run -- utxos bc1q...

# 费率估计（sat/vB）
cargo run -- fee

# 由 WIF 私钥离线派生公钥与三类地址
BTC_WIF=<wif> cargo run -- derive

# 转账：本地构造 + 签名 + 广播
BTC_WIF=<wif> cargo run -- transfer <to_address> 0.001 --fee-rate 10
# 只构造不广播，输出 raw hex
BTC_WIF=<wif> cargo run -- transfer <to_address> 0.001 --dry-run

# 广播已签名交易 / 本地解析交易
cargo run -- broadcast <raw_hex>
cargo run -- decode <raw_hex>
```

金额支持 `0.001`（默认 BTC）与 `25000sat` 两种写法。

## 代码结构

```
src/
├── main.rs          # clap CLI 定义与分发
├── backend.rs       # 数据源抽象：Esplora 与本地节点的能力协商
├── esplora.rs       # Esplora REST 客户端
├── network.rs       # 网络参数、端点、浏览器地址
├── queries.rs       # 各视图的格式化输出、地址解析、交易解码
├── transactions.rs  # Wallet（WIF 派生）、本地构造与签名、广播
└── units.rs         # BTC <-> sat、费率解析、vsize/手续费估算、单位换算
```

## 转账要点

1. **UTXO 获取**：Esplora 查地址 UTXO（`--legacy` 同时扫 P2PKH）。
2. **选币**：最大优先；带找零时用 2 输出估算手续费，找零低于 546 sat（尘埃阈值）则并入手续费，只保留收款输出。
3. **体积**：`10.5 + 68 × 输入 + 31 × 输出` vB（P2WPKH），P2PKH 输入 148 vB / 输出 34 vB。
4. **签名在本地完成**（`bitcoin` crate 的 sighash + secp256k1），私钥不出进程；仅广播环节需要网络。
5. **RBF**：`--rbf` 开启可替换提价。
6. 建议先 `--dry-run` 检查 raw hex 再广播。

## 实测记录（2026-08，mainnet 走 mempool.space）

| # | 用例 | 结果 |
| --- | --- | --- |
| 1 | `status` | 高度 964458，链尖哈希与 `block` 结果一致 |
| 2 | `block 964458` | 4229 笔交易，1.57 MB，weight 3993919 WU |
| 3 | `tx <区块内真实交易>` | 完整输入输出、手续费 0.0009 BTC、费率 473.68 sat/vB、确认数 1 |
| 4 | `address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` | 余额 57.43043089 BTC，65569 笔交易，78460 个 UTXO |
| 5 | `fee` | 1/3/6/12/144 区块目标对应 4/4/3/2/1 sat/vB |
| 6 | `derive`（离线） | 由 WIF 正确派生压缩公钥、P2WPKH、P2PKH、Taproot 地址；网络不匹配时明确报错 |
| 7 | `utxos bc1qwqdg…` | 列出 151 个 UTXO 及所在区块高度 |
| 8 | `cargo test` | 6 passed（单位换算、vsize/费率、P2WPKH 与 P2PKH 签名、地址派生） |

## API 注意点（bitcoincore-rpc 0.19 / bitcoin 0.32）

- `GetRawTransactionResult` **没有** `fee`、`weight`、`blockheight` 字段；Vin 也没有 `prevout`，手续费需自行查前序交易（本工具在 Esplora 数据源下直接取索引器算好的值）。
- `vout.script_pub_key.address` 是 `Option<Address<NetworkUnchecked>>`，需 `assume_checked()` 才能格式化。
- `block::Version`、`Option<BlockHash>` 等类型不实现 `Display`，打印要用 `{:?}`。
- `Address::p2wpkh` 需要 `CompressedPublicKey`（用 `CompressedPublicKey::from_private_key`），传 `PublicKey` 不通过。
- `bitcoin::Address` 默认泛型是 `NetworkChecked`；解析用户输入要用 `parse::<Address<_>>()` 再 `require_network(network)`。
- WIF 自带网络信息，与主网/测试网选择不一致时应直接拒绝，避免把测试网地址当主网用。
