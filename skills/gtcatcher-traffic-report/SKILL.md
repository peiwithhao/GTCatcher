---
name: gtcatcher-traffic-report
description: 分析任意 GTCatcher tweak 日志，重建流量指纹、收发逻辑、跨层关联、协议轮廓，并基于当前仓库实际 hook 能力输出通用、可复核的逆向分析报告，不依赖特定主机、域名或业务。
---

# GTCatcher 流量分析报告

当任务是分析任意真实 `GTCatcher` 日志，并输出一份严格、可复核、与目标主机无关的分析报告时，使用这个 skill。

适用目标：

- 提取流量指纹
- 重建 send/receive 逻辑
- 分析 BSD / TLS / Network.framework 三层关联
- 判断可能的协议结构
- 明确当前 hook 集合能证明什么、不能证明什么
- 产出下一步更深入逆向的具体动作

这个 skill 已经内嵌了当前仓库实现的关键原理摘要，不要求每次重新阅读 `Tweak.xm`、`GTExtraContext.m`、`README.md` 才能开始分析。除非用户明确要求验证最新代码细节，否则应直接以本 skill 中的规则为准展开分析。

不要把这类日志当成通用抓包或标准 pcap 来解释。

这个 skill 的目标是：

- 不预设目标域名、目标主机、目标端口、业务协议
- 让分析逻辑完全由日志字段驱动
- 遇到陌生主机、私有协议、非 HTTP 流量时也能输出高质量报告

## 当前实现原理摘要

下面这些结论已经来自当前仓库实现，可以直接作为分析前提使用。

### 1. 日志的本质

日志是 hook 级应用内遥测，不是链路抓包。

每条 `[GTCatcher] {json}` 都表示：

- 某个 hook 点在某个时间观察到的一次发送、接收、解密、加密或高层 API 调用
- 它描述的是“调用点看到的数据”
- 它不保证完整包、完整流、完整重组

### 2. 三层 hook 模型

当前实现同时观察三层：

- BSD socket 层
- TLS 明文层
- Network.framework 高层 API

它们对应的大致路径是：

```text
业务对象 / 序列化结果
-> Network.framework 发送内容
-> TLS 明文输入 / 输出
-> BSD 层密文或自定义 framing 读写
```

但注意：

- 这个路径在部分流上能成立
- 并不是每条流都能完整打通三层
- `network -> tls -> bsd` 的桥接在当前实现里仍不完全

### 3. BSD 层当前如何工作

BSD 层会 hook：

- `connect`
- `send`, `sendto`, `write`, `writev`, `sendmsg`
- `recv`, `recvfrom`, `read`, `readv`, `recvmsg`

BSD 层的最强主键是：

- `flow_id`
- `fd_conn_id`
- `conn_id`

连接建立后，一般长这样：

```text
pid:<pid>|fd:<fd>|seq:<n>|<local>-><peer>
```

`bytes_in` / `bytes_out` 是 fd 会话累计计数，来自 hook 侧更新，不是严格的 TCP 流重组结果。

### 4. TLS 层当前如何工作

TLS 层同时覆盖两类实现：

- SecureTransport
  - `SSLWrite`
  - `SSLRead`
- BoringSSL / OpenSSL 风格
  - `SSL_write`
  - `SSL_read`
  - 以及若干 fd / bio 关联路径

如果 TLS 事件里出现这些字段：

- `fd`
- `fd_conn_id`
- `flow_id`
- `local`
- `peer`

说明当前 TLS 事件已经部分成功回填到 BSD 会话，可以优先并回 BSD 流。

如果没有这些字段，就只能按：

- `tls_conn_id`
- 或 `conn_id`

单独分组。

### 5. Network.framework 层当前如何工作

Network 层会记录：

- `nw_connection_send`
- `nw_connection_receive`
- `nw_connection_receive_message`
- `nw_connection_receive_callback`
- `nw_connection_receive_message_callback`

其中最关键的事实是：

- `nw_connection_receive`
  - 表示注册了一次 receive 请求
- `nw_connection_receive_callback`
  - 表示这次 receive 的 completion 真正触发了
  - 可能带有响应内容

因此新版日志里，`network` 层已经能直接看到一部分响应，而不只是请求。

### 6. `receive_seq` 的真实含义

当前实现会给每个 `nw_conn:*` 维护一个 `receive_seq`。

它的作用是：

- 第 N 次 `nw_connection_receive`
- 对应第 N 次 `nw_connection_receive_callback`

这只能证明“调用级配对”，不能自动证明“业务请求级配对”。

尤其在：

- HTTP/2
- 多路复用
- 长连接多轮交互

场景下，不能把一个 callback 机械当成一个完整业务响应。

### 7. HTTP 元数据是前缀解析结果

当前实现会对可读前缀做 HTTP 元数据提取，因此日志里可能出现：

- `http_method`
- `http_path`
- `http_host`
- `http_version`
- `http_content_type`
- `http_content_encoding`
- `http_status_code`
- `http_reason`
- `http_kind=request/response`

这些字段的本质是：

- 基于当前可见 payload 前缀解析得出
- 很有价值
- 但不等价于完整 HTTP 会话重组

### 8. preview 与 payload_capture 的区别

- `preview_hex` / `preview_ascii`
  - 只是 payload 前缀预览
- `payload_capture_*`
  - 只在命中扩展捕获策略时出现
  - 比 preview 更长，但仍未必是整条消息完整内容

### 9. 栈聚类的意义

`stack_hash` 是过滤噪音后的调用栈聚类键，用来回答：

- 哪些流量来自同一调用路径
- 哪些事件虽然目标不同，但其实由同一业务逻辑发起

它尤其适合：

- 发现批量上报
- 发现某一类长连接
- 发现相同序列化逻辑产生的多条流

### 10. 当前实现的已知限制

这些限制应默认成立：

- 不能完成严格 TCP 重组
- 不能把所有 `nw_conn:*` 精确映射回 BSD fd
- 不能保证每条 TLS 都能成功映射到 fd
- `preview_*` 不是完整 payload
- `network` callback 虽然能看响应，但不等于自动完成请求-响应重组

## 当前 Tweak 实际会产出什么

仓库会输出前缀为 `[GTCatcher]` 的 JSON 行日志。每条 JSON 都是某个 hook 点观察到的一次“应用内传输事件”，不是完整链路抓包。

三层事件：

- `bsd`
  - `connect`, `send`, `sendto`, `write`, `writev`, `sendmsg`
  - `recv`, `recvfrom`, `read`, `readv`, `recvmsg`
- `tls`
  - SecureTransport: `SSLWrite`, `SSLRead`
  - BoringSSL/OpenSSL 风格: `SSL_write`, `SSL_read`
- `network`
  - `nw_connection_send`
  - `nw_connection_receive`
  - `nw_connection_receive_message`
  - `nw_connection_receive_callback`
  - `nw_connection_receive_message_callback`

## 这版日志相对旧版最重要的变化

新版 `Tweak.xm` 已经包装了 `nw_connection_receive*` 的 completion block，因此 `network` 层不再只有“注册 receive 请求”，还会在 callback 真正触发时记录响应内容。

新增或值得重点关注的字段：

- `receive_seq`
  - 每个 `nw_conn:*` 连接内部的 receive 序号
  - 用于把 `nw_connection_receive` 与后续 `nw_connection_receive_callback` 配对
- `receive_kind`
  - `stream` 或 `message`
- `content_context`
  - Network.framework 传下来的内容上下文指针
- `has_content`
  - callback 是否带了内容
- `is_complete`
  - 当前上下文是否完整
- `has_error` / `error`
  - receive callback 是否伴随错误
- `http_status_code`, `http_reason`
  - 当响应头可解析时，`network` 与 `tls` 层都可能出现
- `http_kind`
  - 现在既可能是 `request`，也可能是 `response`
- `payload_capture_*`
  - 命中扩展捕获策略时可拿到更长 payload，而不只 32 字节 preview

## 仓库语义细节

分析时必须记住：

- `preview_hex` 和 `preview_ascii` 不是完整 payload，只是前缀预览
- `len` 是本次 hook 调用的数据长度，不是整条流的累计长度
- `bytes_in` / `bytes_out` 是 fd 级累计计数，由 hook 侧 opportunistic 更新
- `stack_hash` 是过滤噪音栈帧后得到的聚类键
- `frames` 只有在启用栈采集且该 hook 选择 `includeStack=YES` 时才有
- `network` 层的 callback 响应内容现在可见，但依旧不是“自动完成请求-响应语义重组”

## 通用分析原则

这个 skill 必须对未知主机、未知域名、未知协议也适用，因此：

- 不要把特定样例中的域名、路径、IP、端口写死成规则
- 不要把“像 HTTP”之外的流量视为低价值
- 不要默认 443 就一定是标准 HTTPS
- 不要默认 `sendto/recvfrom` 一定是 UDP 工具流，有些应用会在 datagram 上跑主业务
- 不要默认可读 ASCII 前缀就代表完整业务协议明文
- 不要因为看不到 HTTP 字段就忽略该流，二进制流同样要做时间线和指纹分析

面对任意日志时，优先从这些维度抽象：

- 目标集合：有哪些 peer / host / 端口
- 传输风格：stream、message、datagram、长连接、短连接
- 收发节奏：一次请求一次响应、流式、多轮握手、心跳、批量上报
- 内容特征：HTTP、HTTP/2、JSON、gzip、二进制 framing、疑似 protobuf、疑似自定义协议
- 跨层可见性：BSD only、TLS 明文可见、Network 明文可见、Network 响应可见

## 关联规则

按下面的优先级做关联，不要跳级：

### 1. BSD `flow_id` / `fd_conn_id` 是最强锚点

对于 `bsd` 事件，主键优先使用：

- `flow_id`
- 或等价的 `fd_conn_id`
- 或 `conn_id`

连接建立后，格式通常是：

```text
pid:<pid>|fd:<fd>|seq:<n>|<local>-><peer>
```

### 2. `pending_fd:*` 不能轻易并到已连接流

`pending_fd:*` 常见于：

- UDP `sendto` / `recvfrom`
- 早期 `getpeername()` 还拿不到远端地址的场景

不要把 `pending_fd:*` 机械合并到后续连接成功的 TCP 流，除非日志里有非常直接的证据。

### 3. TLS 事件优先看 `fd_conn_id`

[GTExtraContext.m](/Users/peiwithhao/repo/GTCatcher/GTExtraContext.m) 会尝试给 `tls` 事件补：

- `fd`
- `fd_conn_id`
- `flow_id`
- `fd_state`
- `local`
- `peer`

如果这些字段存在，TLS 分组应优先并回 BSD `flow_id/fd_conn_id`。

如果不存在，再退回：

- `tls_conn_id`
- 或 `conn_id`

### 4. Network.framework 现在能做“连接内 receive 配对”

新版 `network` 分析优先键：

- `conn_id = nw_conn:<pointer>`
- `receive_seq`

配对原则：

- `nw_connection_receive` 与 `nw_connection_receive_callback`
  - 同一个 `conn_id`
  - 同一个 `receive_seq`
  - 这是 `confirmed by key`
- `nw_connection_receive_message` 与 `nw_connection_receive_message_callback`
  - 同理

这解决的是“哪次 receive 注册对应哪次 callback”，不是“哪一个应用请求必然对应哪一个业务响应”。

### 5. `network` 到 `tls` / `bsd` 仍然主要靠推断

当前代码仍未把 `nw_conn:*` 直接桥到 fd 或 TLS ctx。

因此 `network -> tls -> bsd` 的跨层关联依旧按下面顺序判断：

1. 完全相同的明文 payload 前缀
2. 相近时间窗口
3. 相同或相近的业务路径、Host、HTTP 方法
4. 相同 stack 家族

关联标签必须明确标注：

- `confirmed by key`
- `strongly inferred`
- `weakly inferred`

## 事件含义解释

- `write` / `send` / `sendmsg` / `writev`
  - BSD 层出站数据
- `read` / `recv` / `recvmsg` / `readv`
  - BSD 层入站数据
- `sendto` / `recvfrom`
  - 往往是 datagram 风格，常见 UDP
- `SSL_write` / `SSLWrite`
  - 进入 TLS 前的明文
- `SSL_read` / `SSLRead`
  - TLS 解密后的明文
- `nw_connection_send`
  - 应用通过 Network.framework 发送的高层内容
- `nw_connection_receive`
  - 注册了一次 receive 请求，不代表已经收到数据
- `nw_connection_receive_callback`
  - 这次 receive 真正回调了，可能带响应内容
- `nw_connection_receive_message`
  - 注册了一次 message receive
- `nw_connection_receive_message_callback`
  - 这次 message receive 真正回调了

## 对新版日志的解释规则

### 1. `network` callback 的价值

新版日志里，`nw_connection_receive_callback` 常常能直接看到：

- HTTP 响应行
- 响应头
- 部分响应体前缀
- `http_status_code`
- `http_reason`

这意味着：

- `network` 层现在可以直接分析响应，而不只是分析请求
- 对 HTTP/1.1 请求/响应，`network` 层的可见度明显提高

### 2. `receive_seq` 只保证“receive 调用级关联”

`receive_seq` 的意义是：

- 第 N 次 `nw_connection_receive`
- 对应第 N 次 `nw_connection_receive_callback`

它不能单独证明：

- 这个 callback 就一定属于某一个具体 HTTP 请求
- 尤其在 HTTP/2 多路复用场景，这种业务级一一映射不能直接假设

### 3. callback 拿到的是 hook 级响应片段，不是完整重组

即使 `http_status_code` 已出现，也不要默认：

- 响应 body 已完整
- chunked body 已完整拼接
- HTTP/2 stream 已完整还原

### 4. 可读前缀不等于完整明文语义

可见：

- `HTTP/1.1 200 OK`
- `POST /...`
- `GET /...`
- `PRI * HTTP/2.0`

这些都很有价值，但它们只证明前缀可见，不代表整个协议体都已完全掌握。

### 5. 对未知协议必须给出结构化判断

如果流量不是明显 HTTP / JSON，也必须说明：

- 它是 `bsd only`、`tls plaintext` 还是 `network callback visible`
- 首字节/首 32 字节是否稳定
- 长度分布是否集中
- 是否存在固定 framing 前缀
- 是否像握手、心跳、批量推送、订阅流、文件下载、配置下发

分析中允许写“无法确定协议”，但不允许停在“看不懂所以略过”。

## 建议工作流

按这个顺序执行：

### 1. 只解析合法 JSON 行

非 JSON 行只用来记录：

- 缺失导出
- instrumentation 异常

### 2. 先做全量盘点

至少统计：

- 总行数
- 按 `layer` 计数
- 按 `event` 计数
- Top peer / host / endpoint
- 不同 `flow_id` 数量
- 不同 `tls_conn_id` 数量
- 不同 `nw_ptr` 数量
- Top `stack_hash`

如果目标主机很多，还应额外给出：

- Top 远端 IP:port
- Top `http_host`
- Top “无 host 但高频的二进制流”

### 3. 分层分组

分别分组：

- BSD：按 `flow_id`
- TLS：优先 `flow_id`，否则 `tls_conn_id`
- Network：按 `nw_conn:*`

每组至少汇总：

- 首次时间
- 最后时间
- 事件序列
- 本地/远端地址
- 最新 `bytes_in` / `bytes_out`
- 主导 `stack_hash`
- 代表性预览

### 4. 对 `network` 组额外做 receive 配对

对每个 `nw_conn:*`：

- 找出 `nw_connection_receive`
- 找出 `nw_connection_receive_callback`
- 用 `receive_seq` 配成对子

至少说明：

- 哪些 receive 只注册了但没看到 callback
- 哪些 callback 带了 `has_content`
- 哪些 callback 是 `HTTP/1.1 200` 这类清晰响应
- 哪些 callback 是二进制或 HTTP/2 前缀

### 5. 重建关键流时间线

对重要流叙述：

- 如何开始
- 首次出站长什么样
- 入站是立即响应、延迟响应还是流式回调
- 看起来像请求/响应、持续流、保活、长连接、文件下载还是本地 IPC
- payload 看起来是明文、gzip、TLS 明文、HTTP/2、二进制帧、还是未知自定义协议

### 6. 做跨层关联

优先级：

1. `flow_id` / `fd_conn_id` 精确匹配
2. TLS 自带 `fd_conn_id`
3. `network` callback 与 `tls` / `bsd` 在时间、前缀、Host/Path 上高度一致
4. 相同 stack 家族和相同业务路径

### 7. 提取流量指纹

每个主要流量家族提取：

- 目标 host / peer / 端口
- 发送频率
- payload 长度分布
- 固定前缀
- 重复的 `stack_hash`
- 请求路径 / JSON key / HTTP 状态
- 是否为 loopback、LAN、NTP、DNS、远程业务流

如果是非 HTTP 流量，还要尝试给出：

- 稳定 tag / magic bytes
- 小包与大包的交替模式
- 单向重流还是双向对称
- 是否存在固定长度心跳

### 8. 写清楚硬限制

必须明确：

- 不能证明完整 payload 全貌
- 不能做严谨 TCP 重组
- 不能精确完成 `nw_conn:* -> fd` 映射
- 不能仅凭 HTTP/2 前缀就自动知道 stream 级业务含义
- 不能把一个 receive callback 机械当成一个完整业务响应

### 9. 给出下一步逆向动作

动作要具体、可执行、可排序。

优先建议示例：

- 针对 `nw_connection_receive_callback` 命中的高价值连接开启更长 payload 捕获
- 给 BSD/TLS/Network 统一增加事件序号，减少人工时间线拼接成本
- 继续桥接 `nw_connection` 到 fd / TLS ctx
- 对 HTTP/2 连接增加 frame 头解析，提取 stream id
- 围绕高价值 `stack_hash` 向上追业务序列化逻辑
- 把同一 `nw_conn + receive_seq` 自动配对，输出结构化时间线
- 对未知二进制流增加定向全量捕获与长度统计
- 按 peer / host / stack_hash 自动挑选“最值得逆向的前 N 条流”

## 建议命令

优先用 `rg` 和轻量 Python。

按层统计：

```sh
rg -o '"layer":"[^"]+"' your.log | sort | uniq -c
rg -o '"event":"[^"]+"' your.log | sort | uniq -c
```

查看新的 network callback：

```sh
rg -n 'nw_connection_receive_callback|nw_connection_receive_message_callback' your.log
```

查看某个 `nw_conn` 的收发和 callback：

```sh
rg -n '"conn_id":"nw_conn:0xDEADBEEF"|\"nw_ptr\":\"0xDEADBEEF\"' your.log
```

查看某个 `receive_seq`：

```sh
rg -n '"conn_id":"nw_conn:0xDEADBEEF".*"receive_seq":2' your.log
```

找可读请求/响应前缀：

```sh
rg -n 'POST /|GET /|HTTP/1.1|PRI \* HTTP/2.0|Host: |Content-Type:' your.log
```

找一个 BSD 流：

```sh
rg -n 'pid:[0-9]+\\|fd:[0-9]+\\|seq:[0-9]+\\|' your.log
```

如果需要临时脚本，可以解析 `[GTCatcher] {json}` 后按 `flow_id`、`tls_conn_id`、`nw_conn + receive_seq` 输出时间线。除非用户要求复用工具，否则保持 task-local。

## 不要写死样例结论

这个 skill 不能假设：

- 目标一定是某个 Meituan、QQ 或其他固定应用
- 目标一定会出现 HTTP
- 目标一定会有明文 Host / Path
- 目标一定会走 TLS
- 目标一定会走 `network` 层

分析报告必须从当前日志实际出现的字段出发，而不是套用历史样例的结论。

## 输出契约

使用本 skill 时，报告必须按下面顺序输出：

1. `Hook Model`
2. `Log Schema And Correlation Rules`
3. `Traffic Inventory`
4. `Key Flow Timelines`
5. `Traffic Fingerprints`
6. `Cross-Layer Inferences`
7. `What The Current Log Cannot Prove`
8. `Recommended Next Instrumentation / Reverse Engineering Steps`

## 写作规则

- 每个结论都要能追溯到仓库代码或日志字段
- 必须把“确认事实”和“推断”分开写
- 优先使用具体字段名：`flow_id`、`fd_conn_id`、`tls_conn_id`、`nw_ptr`、`receive_seq`、`stack_hash`
- 不要宣称“包级真相”，这是 hook 级遥测
- 不要把 loopback、NTP、DNS、远程业务流混成一类
- 如果模式看起来像应用协议，但 payload 仍截断，要明确写出“还需要什么额外捕获”
- 遇到新版 `network` callback，必须说明它是“已收到响应”的证据，而不是旧版那种“只注册 receive”
- 即使目标主机、域名、协议完全陌生，也要完成 inventory、timeline、fingerprint、limits、next steps 这五件事，不能因为“不是已知样例”而退化成泛泛描述
- 默认直接使用本 skill 内嵌的实现原理摘要，不要把“先去读仓库源码”作为分析前置步骤；只有在用户明确要求校验最新实现差异时，才回头读取代码
