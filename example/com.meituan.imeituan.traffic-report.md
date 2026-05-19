# GTCatcher Traffic Report: `com.meituan.imeituan.log`

## Hook Model

这份 `com.meituan.imeituan.log` 是 GTCatcher 的 hook 级应用内遥测，不是链路抓包。每条 `[GTCatcher] {json}` 都表示某个 hook 点在某一时刻观察到的一次传输事件，描述的是“调用点看到的数据”，不保证完整包、完整流或完整重组。

本次样本共包含：

- 2428 条有效 JSON 事件
- 1 条非 JSON instrumentation 提示

第 1 行提示：

```text
[GTCatcher] export not found: null!SSL_set_fd
```

这说明当前样本里存在一条 TLS 关联路径未命中，但不影响三层总体可见性。

日志覆盖了三层：

- `bsd`: 1022
- `tls`: 718
- `network`: 688

因此这不是单层日志，而是：

```text
业务对象 / 序列化结果
-> Network.framework 高层发送 / 接收
-> TLS 明文读写
-> BSD socket 层密文或自定义 framing 读写
```

但当前样本并没有让所有流都完整打通三层，尤其 `network -> tls -> bsd` 的桥接仍主要依赖推断。

## Log Schema And Correlation Rules

### 1. BSD 层主键

BSD 层最强锚点是：

- `flow_id`
- `fd_conn_id`
- `conn_id`

已连接 TCP 流通常长这样：

```text
pid:10078|fd:45|seq:1|192.168.64.25:53948->103.63.160.60:443
```

对于 `bsd` 事件，本报告优先按 `flow_id` 分组。

### 2. `pending_fd:*` 的含义

`pending_fd:*` 在本样本里主要出现在 datagram / UDP 类场景，例如：

- NTP 风格 `sendto/recvfrom`
- 本地 DNS 查询到 `192.168.64.1:53`
- 一些 `peer:...:0` 的 datagram / ICMP 风格交互

这些流不能机械并入后续 TCP 连接。

### 3. TLS 分组规则

本样本 718 条 TLS 事件都能看到 `boringssl_bio:*` 级别标识，但没有可复核的 `fd_conn_id/peer/http_host` 回填。因此实际分组键主要是：

- `flow_id`，这里表现为 `boringssl_bio:0x...`

这意味着：

- `tls -> bsd` 在本样本里缺少键级确认
- 只能依赖明文前缀、时间窗口、收发节奏来做强推断

### 4. Network 分组与 receive 配对

`network` 层按 `conn_id = nw_conn:0x...` 分组。

在每个 `nw_conn:*` 内部：

- `nw_connection_receive`
- `nw_connection_receive_callback`

可通过：

- 同一个 `conn_id`
- 同一个 `receive_seq`

做 `confirmed by key` 的调用级配对。

这只证明：

- 第 N 次 `receive` 注册
- 对应第 N 次 `receive callback`

它不能单独证明业务请求级一一对应，尤其不能自动解释 HTTP/2 多路复用。

### 5. 推断标签

本报告对跨层关联明确区分：

- `confirmed by key`
- `strongly inferred`
- `weakly inferred`

## Traffic Inventory

### 全量统计

- 总有效 JSON 行数：2428
- 非 JSON 行数：1
- 不同 `flow_id`：148
- 不同 `tls_conn_id`：54
- 不同 `nw_conn:*`：56

### 按 `event` 计数

- `read`: 545
- `SSL_read`: 498
- `write`: 267
- `nw_connection_receive`: 247
- `nw_connection_receive_callback`: 232
- `nw_connection_send`: 209
- `SSL_write`: 206
- `sendto`: 106
- `recvmsg`: 64
- `recvfrom`: 40
- `SSLRead`: 12
- `SSLWrite`: 2

### Top peer / endpoint

- `103.63.160.60:443`: 522
- `101.50.8.60:443`: 133
- `103.37.142.230:443`: 70
- `192.168.64.1:53`: 60
- `120.226.150.252:443`: 58
- `103.63.160.80:80`: 24
- `159.226.227.208:0`: 20
- `116.162.51.228:0`: 14
- `162.159.200.1:123`: 8
- `171.15.110.141:443`: 8

### Top `http_host`

- `portal-portm.meituan.com`: 24
- `p2.d.meituan.net`: 20
- `hcl0.d.meituan.net`: 16
- `p14.d.meituan.net`: 16
- `metrics-picture.dreport.meituan.net`: 16
- `o1.d.meituan.net`: 16
- `api-unionid.meituan.com`: 8
- `data-sdk-uuid-log.d.meituan.net`: 8
- `addressapi.meituan.com`: 8
- `i.waimai.meituan.com`: 7

### Top `stack_hash`

- `ed038938`: 267
- `41e70e2f`: 247
- `fcbe2bf9`: 232
- `6b4eb54d`: 209
- `e48a3b84`: 206
- `c48ebd4c`: 106

### 主要流量家族

从字段和前缀上，本样本至少可以稳定分出 4 类流量：

1. `HTTP/1.1 POST -> 200 OK` 的短轮询 / 上报类
2. `PRI * HTTP/2.0` 开头的长连接 / 多轮交互类
3. 本地 DNS 查询，主要发往 `192.168.64.1:53`
4. NTP / ICMP 风格 datagram，主要位于 `pending_fd:*`

## Key Flow Timelines

### 1. `p2.d.meituan.net` 的 `HTTP/1.1 POST -> 200 OK`

代表连接：

- `conn_id = nw_conn:0x117474c80`

关键行：

- 第 147 行：`nw_connection_send`
- 第 149 行：`nw_connection_receive`，`receive_seq=1`
- 第 202 行：`nw_connection_receive_callback`，`receive_seq=1`，`http_status_code=200`

第 147 行可见请求前缀：

```text
POST / HTTP/1.1
Host: p2.d.meituan.net
Content-Type: application/json; charset=utf-8
```

第 202 行可见响应前缀：

```text
HTTP/1.1 200 OK
Server: openresty
Content-Type: text/plain
```

同一连接后续又重复 4 轮：

- `receive_seq=2`: 第 409 / 457 行
- `receive_seq=3`: 第 1072 / 1109 行
- `receive_seq=4`: 第 2249 / 2288 行
- `receive_seq=5`: 第 2401 / 2419 行

可确认结论：

- 这是新版 `network callback` 已经观察到真实响应内容的明确证据
- 该连接表现为多轮 `POST` 上报，每轮都能看到 `200 OK`

### 2. `hcl0.d.meituan.net` 的重复上报

代表连接：

- `conn_id = nw_conn:0x129e02300`

关键行：

- 第 139 行：`nw_connection_send`
- 第 146 / 187 行：`receive_seq=1` 的 confirmed pair
- 第 414 / 421 行：`receive_seq=2`
- 第 1067 / 1076 行：`receive_seq=3`
- 第 2240 / 2260 行：`receive_seq=4`

请求前缀稳定为：

```text
POST / HTTP/1.1
Host: hcl0.d.meituan.net
```

响应前缀稳定为：

```text
HTTP/1.1 200 OK
Content-Length: 2
```

可确认结论：

- 这是一个短请求-短响应型上报流
- `receive_seq` 在这个连接内可以稳定配对

### 3. `p14.d.meituan.net`、`o1.d.meituan.net`、`metrics-picture.dreport.meituan.net`

代表连接：

- `p14.d.meituan.net`: `nw_conn:0x116055680`
- `o1.d.meituan.net`: `nw_conn:0x116056f80`
- `metrics-picture.dreport.meituan.net`: 第 450 行首次命中

这些连接的共同特征：

- 均以 `POST / HTTP/1.1` 开头
- `network` 层都能看到 `receive` 与 `callback`
- callback 可见 `HTTP/1.1 200 OK`
- `stack_hash` 家族一致，说明很可能来自同类业务调用路径

它们更像“多个上报目标的同类埋点/统计流”，而不是互不相干的独立协议族。

### 4. `HTTP/2` 长连接家族

代表连接：

- `conn_id = nw_conn:0x156769900`

关键行：

- 第 1269 行：`nw_connection_send`
- 第 1271 行：`nw_connection_receive`，`receive_seq=1`
- 第 1284 行：`nw_connection_receive_callback`，`receive_seq=1`

第 1269 行请求前缀：

```text
PRI * HTTP/2.0
```

这个连接的整体行为：

- 共 13 次 `nw_connection_send`
- 共 73 次 `nw_connection_receive`
- 共 72 次 `nw_connection_receive_callback`

callback 长度呈现明显大块分布，常见长度：

- `16384`
- `16420`
- `16402`
- `32768`
- `65295`
- 以及更大的 `229556`、`311548`、`425453`

同时夹杂多次约 101~103 字节的小发送。

可确认结论：

- 这是长连接上的持续多轮收发，不是简单的单请求单响应
- `receive_seq` 证明了 callback 的到达顺序

强推断：

- 这条连接更像 `HTTP/2` 多路复用或流式下发场景
- 大量 16KB 左右的回调块说明应用层看到的是分片到达的响应片段，而不是自动重组后的“完整业务响应”

### 5. BSD 层的大型 `:443` 连接

代表 `flow_id`：

- `pid:10078|fd:45|seq:1|192.168.64.25:53948->103.63.160.60:443`
- `pid:10078|fd:48|seq:1|192.168.64.25:53947->103.63.160.60:443`
- `pid:10078|fd:52|seq:1|192.168.64.25:53946->101.50.8.60:443`
- `pid:10078|fd:77|seq:1|192.168.64.25:54024->103.37.142.230:443`

其中最大的一条是 `fd:45`：

- 327 条事件
- `read=223`
- `write=104`
- `bytes_in=337208`
- `bytes_out=233083`

这类连接在 BSD 层可见稳定 framing，例如：

- 单字节 `00`
- `ff010150...`
- `ff010166...`

framing 后能看到 JSON 片段，例如：

```json
{"i":10,"p":2,"u":"c6ffa399032c433bae2648655b75be6da177628234835369090","v":"12.53.403"}
```

以及：

```json
{"t":1350367677919576163,"b":"scjgeifbdN0Qf8RXj"}
```

可确认结论：

- 至少部分业务 payload 在进入更底层前保留了可读 JSON 结构
- 前缀 `ff010150` / `ff010166` 很像稳定的私有 framing

但当前日志还不能证明这个 framing 的完整字段含义。

### 6. DNS、本地解析与 NTP/datagram

代表行：

- 第 805 行：`p1.meituan.net` 的 DNS 查询，`pending_fd:102`
- 第 524 行：`dnspod.meituan.httpdns.qcloud.com`
- 第 2~13 行：多个 `:123` 的 48 字节 `sendto/recvfrom`

可确认结论：

- 本样本里存在独立的本地 DNS 和时间同步类流量
- 它们属于 `pending_fd:*` datagram 家族，不应和远程业务 TCP 流混为一类

## Traffic Fingerprints

### 1. `HTTP/1.1` 上报家族

指纹：

- 固定请求前缀：`POST / HTTP/1.1`
- 常见 `Host`：
  - `p2.d.meituan.net`
  - `hcl0.d.meituan.net`
  - `p14.d.meituan.net`
  - `o1.d.meituan.net`
  - `metrics-picture.dreport.meituan.net`
- 响应前缀稳定为：`HTTP/1.1 200 OK`
- 连接模式通常是：
  - 一次请求头发送
  - 一次较大的 body 发送
  - 一次 receive callback 返回
- `stack_hash` 家族稳定为：
  - send: `6b4eb54d`
  - receive: `41e70e2f`
  - callback: `fcbe2bf9`

这说明它们高度可能来自同一业务框架下的多个上报目标。

### 2. `HTTP/2` 长连接家族

指纹：

- 连接起始前缀：`PRI * HTTP/2.0`
- 连接内 `receive_seq` 连续增长
- callback 以大块二进制内容为主
- callback 长度集中在 16KB 左右及其倍数附近
- 同一连接中穿插小尺寸上行数据

这更像：

- 长连接同步
- 流式下发
- 多路复用上的持续交互

而不是简单 REST 请求。

### 3. 自定义 framing + JSON 家族

指纹：

- 目标高度集中于：
  - `103.63.160.60:443`
  - `101.50.8.60:443`
  - `103.37.142.230:443`
- BSD 层稳定出现：
  - `00`
  - `ff010150`
  - `ff010166`
- framing 后可见 JSON 片段
- 同一业务族群共享 `stack_hash=ed038938`

可确认事实：

- 这是“带稳定头部的应用层自定义消息”，不是随机密文

仍待确认：

- 前缀字段是否是版本号、消息类型、长度字段或压缩标记

### 4. DNS / NTP / datagram 家族

指纹：

- DNS 目标集中到 `192.168.64.1:53`
- NTP 风格流量集中到多个 `:123`
- 另有若干 `peer:...:0` 的 datagram / ICMP 风格交互
- 大多出现在 `pending_fd:*`
- 主导 `stack_hash=c48ebd4c`

这类流量应从主业务逆向视图中单独分离。

## Cross-Layer Inferences

### Confirmed By Key

可以确认的关联：

- 在同一个 `nw_conn:*` 内，`nw_connection_receive` 与 `nw_connection_receive_callback` 可用 `receive_seq` 精确配对
- `p2.d.meituan.net`、`hcl0.d.meituan.net` 等连接里，`network` callback 已经直接证明“响应已到达”

### Strongly Inferred

强推断关联：

- `network` 层的 `HTTP/1.1 POST` 与 TLS 层的 `SSL_write` 明文前缀一致
  - 例如第 147 行的 `network POST p2.d.meituan.net`
  - 对应第 148 行的 `TLS SSL_write POST p2.d.meituan.net`
- `network` 层的 `HTTP/1.1 200 OK` 与 TLS 层的 `SSL_read` 响应前缀一致
  - 例如第 202 行的 `network callback`
  - 对应第 200 行的 `TLS SSL_read HTTP/1.1 200 OK`
- `network` 层的 `PRI * HTTP/2.0` 与 TLS 层的同前缀事件高度一致
  - 第 83 行 `network`
  - 第 84 行 `tls`
  - 第 1269 行 `network`
  - 附近有对应 `tls` 同类事件

因此可以强推断：

- `network -> tls` 的业务语义在本样本中高度一致

### Weakly Inferred

弱推断关联：

- `tls -> bsd` 缺少 `fd_conn_id` 级桥接，因此不能精确说某个 `boringssl_bio:*` 就是某个 `fd:45/48/52`
- `network -> bsd` 也无法仅凭当前字段做到一一映射

因此本报告不会宣称：

- 某个 `nw_conn:*` 已被精确映射到某个 `fd`

## What The Current Log Cannot Prove

当前日志不能严格证明：

- 完整 TCP 流重组结果
- 完整 payload 全貌
- 任意 `nw_conn:* -> tls ctx -> fd` 的精确桥接
- 任意一个 `receive callback` 就是一个完整业务响应
- 仅凭 `PRI * HTTP/2.0` 就恢复 stream 级语义
- 仅凭 `ff010150/ff010166` 就确定私有协议结构

还应明确：

- `preview_ascii` / `preview_hex` 只是前缀，不是完整消息
- `len` 是单次 hook 调用长度，不是整条流总长度
- `bytes_in` / `bytes_out` 是 hook 侧累计视角，不等于严格链路重组统计

## Recommended Next Instrumentation / Reverse Engineering Steps

1. 对 `HTTP/2` 长连接优先开启更长 `payload_capture`，首选 `nw_conn:0x156769900` 这类高价值连接。
2. 给 `network` 与 `tls` 增加稳定桥接键，优先尝试把 `nw_connection` 关联到 TLS ctx 或 fd。
3. 对 `HTTP/2` 连接增加最小 frame 头解析，只提取 `type/flags/stream_id/length`，先解决“流级轮廓”问题。
4. 对 BSD 层 `ff010150` / `ff010166` 这类 framing 做定向长度统计和字段拆解，验证是否存在固定头、版本号、消息类型与长度字段。
5. 围绕 `stack_hash=ed038938` 与 `6b4eb54d/41e70e2f/fcbe2bf9` 回溯上层调用栈，定位实际业务模块与序列化逻辑。
6. 自动输出 `nw_conn + receive_seq` 的结构化时间线，减少人工拼接成本。
7. 对 DNS / NTP / datagram 家族单独归档，避免干扰主业务流量逆向。
8. 针对 `103.63.160.60:443`、`101.50.8.60:443` 这类高频大流，优先补更长明文捕获，确认 framing 后的 JSON 是否固定对应某类业务对象。
