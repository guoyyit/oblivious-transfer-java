# oblivious-transfer-java

单进程、本地运行的 1 选 2 不经意传输（Oblivious Transfer）服务。不依赖外部网络或第三方，
会话之间状态完全隔离；支持基于离散对数的基础 OT，以及只用对称原语的 IKNP 批量扩展。

- 基础 1 选 2 OT（DDH / Chou–Orlandi 风格，MODP-2048 安全素数群）
- IKNP OT 扩展：128 次基础 OT 扩展到任意数量，扩展阶段仅用 HKDF / AES-GCM / HMAC
- 选择位批量提交与按批次 / 单条兑换分离，严格一致性与范围校验
- 多会话并发、线程安全的随机源与注册表、会话状态隔离
- 中途中止 / 取消检测；会话 id 墓碑化、不可重用
- 每条消息携带会话标识、严格序号与 HMAC 完整性标签；
  拒绝伪造、截断、重放、乱序、跨会话消息，并给出可区分错误码
- 大批量扩展按批推进，批大小可配置、单批内存有界，可随时取消

## 构建与测试

```bash
mvn compile
mvn test
```

## 快速使用

基础 OT：

```java
OtService service = new OtService();
List<byte[][]> pairs = List.of(
    new byte[][]{"msg0-a".getBytes(), "msg1-a".getBytes()},
    new byte[][]{"msg0-b".getBytes(), "msg1-b".getBytes()});
boolean[] choices = {true, false};
byte[][] chosen = service.executeBase(pairs, choices);
// chosen[0] = msg1-a, chosen[1] = msg0-b
```

扩展 OT（少量基础 OT -> 大量消息）：

```java
OtService service = new OtService();
int n = 1_000_000;
boolean[] choices = ...;                              // 接收方选择向量
byte[][] result = service.executeExtension(
    i -> new byte[][]{senderMessage0(i), senderMessage1(i)},
    choices,
    8192);                                             // 批大小
```

手动控制会话（分批 / 单条兑换 / 取消）：

```java
OtService.ExtensionSession s = service.createExtensionSession(n, 4096);
Future<?> sender = OtService.startExtensionSender(s, i -> pairAt(i));
s.receiver().submitChoices(choices);
byte[] one  = s.receiver().redeemOne(0);
byte[][] lot = s.receiver().redeemRange(1, 4095);
// s.receiver().cancel();                            // 随时取消，不留中间状态
```

## 配置

`OtProperties(defaultBatchSize, maxBatchSize, queueCapacity)`，批大小下限为 128：

```java
OtService service = new OtService(
    new OtProperties(8192, 1 << 20, 8), new SessionRegistry());
```

随机数统一来自线程安全的 `SecureRandom`（Linux `NativePRNGNonBlocking`、macOS `NativePRNG`）。

## 文档

协议流程、安全假设、随机数来源与配置项详见 [`docs/OT_PROTOCOL.md`](docs/OT_PROTOCOL.md)。
