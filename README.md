# oblivious-transfer-java

本地运行的不经意传输（Oblivious Transfer, OT）协议服务。协议双方在**单个进程内**
通过有界阻塞队列交互，不依赖外部网络或第三方服务。发送方持有多组消息对，
接收方按选择位取回且仅取回被选择的一条消息：发送方无法获知选择位，
接收方无法获知未被选择的消息。

## 功能

1. **1 选 2 基础 OT**：基于素阶群上的 Diffie–Hellman/DDH 构造，安全性依赖
   离散对数困难假设。消息为任意字节串，两条消息长度不必一致。非法参数在会话
   建立前直接拒绝。
2. **批量随机 OT 扩展**：以 `kappa` 组基础 OT 为种子，用 IKNP 风格的
   κ 位向量构造扩展到任意数量；扩展阶段只使用 SHA-256 / HMAC-SHA-256 /
   HKDF / AES-GCM 等对称原语，相关鲁棒散列保证安全性不弱于逐次基础 OT。
3. **选择位批量提交与消息兑换分离**：接收方先提交完整选择向量，再按配置批大小
   分批或单条严格顺序兑换；越界、错位、重复、超批请求一律拒绝。
4. **多会话并发**：每会话独立通道、独立信封密钥与独立状态；共享的
   `SecureRandom`、线程池、会话注册表均并发安全；单个会话异常不影响其他会话。
5. **中止与故障处理**：任一方失败或主动中止都会通知对端，对端下一次收发即可
   检测到 `PEER_ABORTED` 并终止；中止/取消不通过错误消息泄漏选择位；
   128 位随机会话标识永不复用。
6. **消息完整性**：所有协议消息封装在统一信封中，携带会话标识、消息类型、
   单调序列号与 AES-128-GCM 密文。AAD 绑定 `sessionId || seq || type`，
   伪造、截断、重复、跨会话混用均被拒绝，并返回可区分的 `ErrorCode`。
7. **大批量分批推进与取消**：批大小可配置；扩展按批推进，单批工作内存
   `O(kappa × 批大小)`（原版 κ 位 IKNP 的矩阵列），与总传输量无关；
   扩展过程可取消，取消后擦除基础串与临时矩阵，不留可观察中间状态。

## 协议流程

### 基础 OT（DH/DDH）

群 `G` 为 RFC 3526 2048 位 MODP 群的素阶子群（生成元 4，阶 `q=(p-1)/2`）。

1. 发送方随机指数 `a`，公布 `C=g^a`。
2. 接收方选择位 `b`，随机 `r`，发送 `Pk=g^r·C^b`。
3. 发送方计算 `K0=Pk^a`、`K1=(Pk·C^{-1})^a`，用各自经 HKDF 导出的
   AES-GCM 密钥加密 `m0`、`m1`。
4. 接收方由 `C^r` 恰好得到 `K_b`，只能解密 `m_b`。

- 选择位隐私：`Pk` 在 `b=0/1` 下都为群上一致分布（信息论安全）。
- 未选择消息机密性：依赖 DDH（离散对数）困难假设。

### 批量扩展（IKNP 风格 κ 位向量）

1. 双方先执行 `kappa` 组基础 OT（角色互换：扩展发送方在此扮演基础 OT 接收方，
   选择向量 `s`；扩展接收方作为基础 OT 发送方，为每列 j 生成 κ 位串对
   `(t0_j, t1_j=t0_j⊕1)`）。
2. 接收方提交选择向量长度与承诺（SHA-256），随后按批发送 A/B 两个
   `n批 × κ` 位矩阵：A 行固定为 `t0_j`，B 行在 `r_i=0` 时为 `t0_j`、
   `r_i=1` 时为 `t1_j`。
3. 发送方按 `s_j` 选择恢复行 `R_i`，输出相关随机串对
   `(H(i,R_i), H(i,R_i⊕s))`；接收方 `r_i=0` 持有 `R_i`，
   `r_i=1` 持有 `R_i⊕s`。
4. 兑换时发送方用对应行密钥经 HKDF 派生 AES-GCM 密钥加密消息对，
   接收方只能解出选择位指定的一条。

## 随机数来源

全部随机性来自 JDK `new SecureRandom()`（`SymCrypto.secureRandom()` 单例，
内部线程安全）：在 macOS/Linux 上由内核熵播种（NativePRNG/DRBG）。
使用点包括：群指数、AES-GCM nonce、会话标识、基础串与扩展选择向量。

## 配置项（`OtConfig`）

| 配置 | 默认 | 说明 |
| --- | --- | --- |
| `securityBits` | 128 | 基础 OT 数量/安全位，支持 128/192/256，须为 8 的倍数 |
| `batchSize` | 1024 | 单批扩展与兑换的最大消息条数 |
| `channelCapacity` | 256 | 进程内通道有界队列容量（背压） |
| `stepTimeout` | 30s | 单步收发等待超时，超时返回 `TIMEOUT` |

## 使用示例

```java
OtService service = new OtService(OtConfig.defaults().batchSize(256));

List<MessagePair> pairs = ...;          // n 条消息对，长度可不同
byte[] choices = ...;                   // n 个 0/1
OtService.BatchSession session = service.createBatchSession(source, choices);
session.receiver().start(n, choices);   // 提交选择向量并完成基础 OT

while (session.receiver().cursor() < n) {
    byte[][] messages = session.receiver().redeemNextBatch();
    // messages[i] 恰好是 choices[cursor+i] 指定的那条
}
```

## 错误判定（`ErrorCode` 节选）

- 参数/状态：`INVALID_PARAMETER`、`INVALID_STATE`、`OUT_OF_RANGE`、
  `INDEX_MISMATCH`、`ALREADY_REDEEMED`
- 消息安全：`MESSAGE_TAMPERED`、`MESSAGE_TRUNCATED`、`MESSAGE_REPLAY`、
  `CROSS_SESSION_MESSAGE`、`DECRYPTION_FAILED`
- 生命周期：`SESSION_NOT_FOUND`、`SESSION_CLOSED`、`SESSION_ABORTED`、
  `PEER_ABORTED`、`SESSION_ID_REUSE`、`CANCELLED`、`TIMEOUT`

## 构建与测试

```bash
mvn test
```

测试覆盖：正确性（长度不一致、分批边界、单条兑换）、选择隐私、发送方隐私、
并发会话隔离、中途中止与取消、消息篡改/截断/重放/跨会话、大批量分批与
取消后内存清理。
