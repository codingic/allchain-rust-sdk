# sol-rpc-cli

> 注：该单链 CLI 已并入统一入口 [`acli`](../README.md)（CLI / HTTP / MCP 三种形态，`transfer` 支持 dry-run）。
> 本目录现在是一个纯库 `sol_sdk`，被 acli 引用；以下为历史实现说明。

基于 Solana 官方 Rust SDK（`solana-rpc-client` 4.2 系列）的 Solana 链上交互库。

## 技术栈

Solana 4.x 已模块化，没有单一的 `solana-sdk` 聚合依赖（`solana-sdk` 停在 4.1.0，与 rpc-client 4.2.1 的 `solana-short-vec` 要求冲突）。因此按依赖树引入细分 crate：

| 组件 | 版本 | 说明 |
| --- | --- | --- |
| `solana-rpc-client` | 4.2.1 | JSON-RPC 客户端（同步阻塞 API） |
| `solana-rpc-client-types` | 4.2.1 | `RpcBlockConfig` / `RpcTransactionConfig` |
| `solana-transaction-status-client-types` | 4.2.1 | `UiConfirmedBlock`、`UiTransactionEncoding` |
| `solana-keypair` | 3.1.2 | ed25519 密钥对 |
| `solana-transaction` | 4.1.6 | `Transaction::new_signed_with_payer` |
| `solana-system-interface` | 3.2.0 | `transfer` 指令 |
| `solana-pubkey` / `solana-signer` / `solana-signature` | 4.2.1 / 3.0.1 / 3.4.1 | 地址、签名 trait、签名类型 |
| `solana-message` / `solana-instruction` / `solana-hash` / `solana-commitment-config` | 见 Cargo.toml | 消息、指令、哈希、commitment |

**版本必须取自同一依赖树**：先 `cargo add solana-rpc-client`，再用 `cargo tree | grep solana-` 查看解析出的版本，按其结果添加其余 crate，否则会出现 `solana-short-vec` 之类的冲突。

编译要求 rustc ≥ 1.89（sdk 4.x 的 MSRV），本项目用 `rust-toolchain.toml` 锁定 1.93.0。

## 构建

```bash
cargo build --release -p sol-sdk
```

## 命令

全局参数：`-c/--cluster`（devnet 默认 / mainnet / testnet / localnet）、`--rpc-url`（覆盖，或 `SOL_RPC_URL`）、`--commitment`（processed / confirmed / finalized）。

```bash
# 节点版本与当前 slot
cargo run -- status

# 区块（按 slot）
cargo run -- get-block 489462274

# 交易详情（按签名）
cargo run -- get-tx <signature>

# 余额
cargo run -- balance <address>

# 生成密钥对（Solana CLI 兼容的 JSON 数组格式）
cargo run -- keygen --out ~/.config/solana/id.json

# 转账（构造 -> 签名 -> 广播并等待确认）
cargo run -- send-tx <to_address> 0.001 --keypair ~/.config/solana/id.json

# 只签名不广播
cargo run -- send-tx <to_address> 0.001 --keypair <path> --dry-run
```

私钥三种传入方式：`--keypair <文件>`（JSON 数组，Solana CLI 格式）、`--secret '<JSON 数组或 base58>'`、缺省读 `~/.config/solana/id.json`。

## 代码结构

```
src/
├── main.rs       # clap CLI 定义与分发
├── cluster.rs    # 集群端点、commitment、RpcClient 构造
├── queries.rs    # status / get_block / get_tx / balance
├── tx.rs         # send_tx：transfer 指令 -> 签名 -> 广播；keygen 与密钥解析
└── units.rs      # SOL <-> lamports 换算
```

## 交易与查询要点

1. **v0 交易版本协商**：`getBlock` / `getTransaction` 的便捷方法不带 `maxSupportedTransactionVersion`，遇到 v0 交易会被节点以 `-32015` 拒绝。必须用 `get_block_with_config` / `get_transaction_with_config` 并显式设置 `max_supported_transaction_version: Some(0)`。
2. **空 slot**：Solana 会跳 slot，直接查 `当前 slot - N` 常得到 `Block not available`。可先用 `getBlocksWithLimit` 找真实存在的 slot。
3. **广播**：`send_and_confirm_transaction` 会先做模拟执行，账户无资金时返回 `Attempt to debit an account but found no record of a prior credit`。
4. **手续费**：基础 5000 lamports/签名，本工具未做优先费（priority fee）配置。

## 实测记录（2026-08，devnet 公共 RPC）

| # | 用例 | 结果 |
| --- | --- | --- |
| 1 | `status` | node_version 4.3.0-beta.2，slot 489462112，blockhash 正常 |
| 2 | `keygen --out` | 生成 ed25519 密钥并写入文件，格式与 Solana CLI 兼容 |
| 3 | `get-block 489462274` | 34 笔交易，block_height 477261649，时间 2026-08-28 16:40:11 UTC |
| 4 | `get-tx <区块内真实签名>` | 完整输出 slot、费用 5201 lamports、CU 454、日志、余额前后变化，并正确识别失败原因 |
| 5 | `send-tx --dry-run` | 构造并本地签名，输出 signature 与 explorer 链接，未广播 |
| 6 | `send-tx` 真实广播（新账户零余额） | 节点返回 `Transaction simulation failed: Attempt to debit an account but found no record of a prior credit`，证明序列化与传输链路连通 |
| 7 | `cargo test` | 10 passed（lamports 换算、密钥 JSON/base58 往返、长度校验、base58 编解码、日期换算） |

## 4.2 API 注意点

- `Keypair` 没有 `from_bytes`，只有 `from_base58_string`（内部 unwrap，会 panic）。还原密钥需先自行校验长度，再 base58 编码后构造。
- `keypair.pubkey()` 来自 `solana_signer::Signer` trait，调用处必须 `use solana_signer::Signer`。
- `get_block_with_config` 返回 `UiConfirmedBlock`，其 `transactions` / `rewards` 是 `Option`；`get_block` 便捷方法返回的是 `EncodedConfirmedBlock`（字段非 Option），两者字段不同。
- `UiTransactionStatusMeta` 的 `compute_units_consumed`、`log_messages` 是 `OptionSerializer<T>`，不是 `Option<T>`。
- `UiMessage` 是枚举（`Parsed` / `Raw`），没有 `as_ref()`，取 `recent_blockhash` 需要 match。
- `TransactionVersion` 没有实现 `Default`，打印 `Option<TransactionVersion>` 只能直接用 `{:?}`。
