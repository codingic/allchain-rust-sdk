# near-rpc-cli

> 注：该单链 CLI 已并入统一入口 [`acli`](../README.md)（CLI / HTTP / MCP 三种形态，`transfer` 支持 dry-run）。
> 本目录现在是一个纯库 `near_sdk`，被 acli 引用；以下为历史实现说明。

基于 **NEAR 官方 Rust JSON-RPC SDK**（[`near-jsonrpc-client`](https://github.com/near/near-jsonrpc-client-rs)）的链上交互库，覆盖只读查询与离线签名交易两类能力。

## 技术栈

| 组件 | 版本 | 说明 |
| --- | --- | --- |
| `near-jsonrpc-client` | 0.22 | NEAR 官方 JSON-RPC 客户端（methods 模块按 RPC 方法组织） |
| `near-jsonrpc-primitives` | 0.37 | RPC 请求/响应与错误类型 |
| `near-primitives` | 0.37 | 链上基础类型、`Transaction`/`Action` 定义 |
| `near-crypto` | 0.37 | `InMemorySigner`、`SecretKey`/`PublicKey`、ed25519 签名 |
| `tokio` | 1 | 异步运行时 |
| `clap` | 4 (derive) | CLI 参数解析 |
| `anyhow` | 1 | 错误聚合 |

版本需成对匹配：0.22.x 的 client 对应 0.37.x 的 primitives/crypto，跨大版本混用会导致类型不兼容。

## 构建

```bash
cargo build --release -p near-sdk
```

## 命令

全局参数：

- `-n/--network`：默认 `testnet`，可选 `mainnet` / `testnet` / `localnet`
- `--rpc-url`：自定义端点（优先级高于 `--network`，也可用环境变量 `NEAR_RPC_URL`）
- `NEAR_SECRET_KEY`：签名私钥环境变量，避免出现在 shell 历史里

### 只读查询

```bash
# 节点状态
cargo run -- -n mainnet status

# 账户详情（余额 / 存储 / code hash）
cargo run -- -n mainnet account near

# 仅余额
cargo run -- -n testnet balance <account>.testnet

# access key 的 nonce 与权限
cargo run -- -n testnet access-key <account>.testnet ed25519:...

# 区块（缺省最新 final；可传高度或哈希）
cargo run -- -n mainnet block 150000000

# 交易执行结果（--wait-until 可选 none|included|executed-optimistic|included-final|executed|final，默认 final）
cargo run -- -n mainnet tx <tx_hash> <sender.near> --wait-until final

# 历史交易需走归档端点（常规节点只保留近期数据）
cargo run -- --rpc-url https://archival-rpc.mainnet.near.org tx <tx_hash> <sender.near>

# 合约只读方法调用
cargo run -- -n mainnet view wrap.near ft_balance_of '{"account_id":"near"}'

# 生成 ed25519 密钥对
cargo run -- keygen [--seed <seed>]
```

### 签名交易（私钥不出本机）

```bash
# 转账 0.01 NEAR（FROM / TO / AMOUNT 为位置参数）
NEAR_SECRET_KEY=ed25519:... cargo run -- -n testnet transfer alice.testnet bob.testnet 0.01

# 调用合约变更方法：附带 1 NEAR、100 TGas
NEAR_SECRET_KEY=ed25519:... cargo run -- -n mainnet call \
  app.near do_something --args '{"id":1}' \
  --signer alice.near --deposit-near 1 --gas 100

# 手动指定 nonce（跳过链上查询，用于离线签名或联调）
cargo run -- -n testnet transfer alice.testnet bob.testnet 0.01 \
  --secret-key ed25519:... --nonce 12345
```

## 代码结构

```
src/
├── main.rs          # clap CLI 定义与子命令分发
├── network.rs       # 网络端点常量与 JsonRpcClient 构造
├── queries.rs       # status / get_block / get_tx / view_account / view_access_key / call_function
├── transactions.rs  # send_tx：nonce 获取 -> 本地签名 -> broadcast_tx_commit
└── units.rs         # NEAR <-> yoctoNEAR、TGas <-> gas 的精确换算
```

## 交易构造要点

1. **nonce**：`view_access_key` 查询得到当前值，交易使用 `nonce + 1`；同一 key 并发交易必须串行递增，否则会被判定为 `InvalidNonce`。
2. **block_hash**：取自 `status.sync_info.latest_block_hash`，作为交易有效性锚点，超过约 12 小时（约 43,200 区块）会被拒绝。
3. **签名**：对 `Transaction::get_hash_and_size().0` 用 `Signer::sign` 签名，再 `SignedTransaction::new(signature, tx)` 组装；私钥不经过网络。
4. **广播**：`broadcast_tx_commit` 会等待交易达到最终性；若只需异步提交，可替换为 `broadcast_tx_async`。
5. **gas 上限**：单笔交易 300 TGas，工具在 `units::parse_tgas` 中做了校验。

## 安全提示

- 私钥优先通过 `NEAR_SECRET_KEY` 环境变量传入，避免进入 shell 历史或进程列表。
- 涉及真实资金的账户建议使用 full access key 之外的受限 key（function call key）。
- 生产环境应使用自己的 RPC 端点（如 QuickNode、Pagoda），公共端点有速率限制。

## 实测记录（2026-08，mainnet / testnet）

| # | 用例 | 命令 | 结果 |
| --- | --- | --- | --- |
| 1 | `get_block` 最新 final 区块 | `-n mainnet block` | height 213296108，10 chunks |
| 2 | `get_block` 指定高度 | `-n mainnet block 213292737` | hash 与 `status` 的 latest_block_hash 一致 |
| 3 | `get_tx` 主网新交易 | `-n mainnet tx 2Vvu9maK... sweat-relayer.near --wait-until final` | `SuccessValue('')`，0.77 TGas，8 receipts |
| 4 | `get_tx` 阶段参数 | 同上 `--wait-until included` | 同上，参数生效 |
| 5 | `get_tx` 历史交易 | `--rpc-url https://archival-rpc.mainnet.near.org tx 9FtHUFBQ... miraclx.near` | `SuccessValue('')`，0.22 TGas |
| 6 | `send_tx` 构造+签名+广播 | `-n testnet transfer ... --nonce 1` | 完整产出 tx_hash/nonce/block_hash，节点返回 `SignerDoesNotExist`（账户不存在，符合预期） |
| 7 | `send_tx` 默认 nonce 路径 | `-n testnet transfer ...`（无 --nonce） | 在 access key 查询阶段被拦截：`AccessKeyNotFound` |
| 8 | 离线签名单测 | `cargo test` | 3 passed（含 hash 一致性与签名验签） |

单元测试覆盖 `get_block` / `get_tx` / `send_tx` 之外的部分无需网络；真实转账需要持有私钥的账户，可用 `keygen` 生成后从 testnet 水龙头领取测试币再验证。

## 0.37 / 0.22 版本 API 差异要点

- `Transaction` 是 `V0(TransactionV0)` / `V1(TransactionV1)` 枚举，需显式构造 `V0`。
- `near_crypto::Signer` 是枚举（非 trait），`InMemorySigner::from_secret_key` 直接返回 `Signer`。
- 余额类型 `Balance = near_token::NearToken`，gas 类型 `Gas = near_gas::NearGas`，不能与 `u128`/`u64` 混用。
- RPC 查询响应使用 `near_jsonrpc_primitives::types::query::QueryResponseKind`（与 `near_primitives::views::QueryResponseKind` 同名但不同类型）。
- `AccountView` 不含 `account_id` 字段，余额需 `amount.as_yoctonear()`。
- `RpcTransactionStatusRequest` 必须显式传 `wait_until`。
- SDK 0.22 要求 rustc ≥ 1.93，本项目通过 `rust-toolchain.toml` 锁定 1.93.0。
