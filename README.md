[![zread](https://img.shields.io/badge/Ask_Zread-_.svg?style=for-the-badge&color=00b0aa&labelColor=000000&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTQuOTYxNTYgMS42MDAxSDIuMjQxNTZDMS44ODgxIDEuNjAwMSAxLjYwMTU2IDEuODg2NjQgMS42MDE1NiAyLjI0MDFWNC45NjAxQzEuNjAxNTYgNS4zMTM1NiAxLjg4ODEgNS42MDAxIDIuMjQxNTYgNS42MDAxSDQuOTYxNTZDNS4zMTUwMiA1LjYwMDEgNS42MDE1NiA1LjMxMzU2IDUuNjAxNTYgNC45NjAxVjIuMjQwMUM1LjYwMTU2IDEuODg2NjQgNS4zMTUwMiAxLjYwMDEgNC45NjE1NiAxLjYwMDFaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00Ljk2MTU2IDEwLjM5OTlIMi4yNDE1NkMxLjg4ODEgMTAuMzk5OSAxLjYwMTU2IDEwLjY4NjQgMS42MDE1NiAxMS4wMzk5VjEzLjc1OTlDMS42MDE1NiAxNC4xMTM0IDEuODg4MSAxNC4zOTk5IDIuMjQxNTYgMTQuMzk5OUg0Ljk2MTU2QzUuMzE1MDIgMTQuMzk5OSA1LjYwMTU2IDE0LjExMzQgNS42MDE1NiAxMy43NTk5VjExLjAzOTlDNS42MDE1NiAxMC42ODY0IDUuMzE1MDIgMTAuMzk5OSA0Ljk2MTU2IDEwLjM5OTlaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik0xMy43NTg0IDEuNjAwMUgxMS4wMzg0QzEwLjY4NSAxLjYwMDEgMTAuMzk4NCAxLjg4NjY0IDEwLjM5ODQgMi4yNDAxVjQuOTYwMUMxMC4zOTg0IDUuMzEzNTYgMTAuNjg1IDUuNjAwMSAxMS4wMzg0IDUuNjAwMUgxMy43NTg0QzE0LjExMTkgNS42MDAxIDE0LjM5ODQgNS4zMTM1NiAxNC4zOTg0IDQuOTYwMVYyLjI0MDFDMTQuMzk4NCAxLjg4NjY0IDE0LjExMTkgMS42MDAxIDEzLjc1ODQgMS42MDAxWiIgZmlsbD0iI2ZmZiIvPgo8cGF0aCBkPSJNNCAxMkwxMiA0TDQgMTJaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00IDEyTDEyIDQiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxLjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPgo8L3N2Zz4K&logoColor=ffffff)](https://zread.ai/peiwithhao/GTCatcher)
# GTCatcher Tweak

`GTCatcher` 是一个 Theos / MobileSubstrate tweak，用来在应用内观察网络相关调用，并把结果输出成统一的 JSON 日志。

它不是系统级抓包工具，也不是 pcap 采集器。它记录的是 hook 点当时看到的发送、接收、解密、加密和 `Network.framework` 调用。

## 它能做什么

- 记录 BSD socket 层收发
- 记录 TLS 明文层收发
- 记录 `Network.framework` 的 send / receive / receive callback
- 把事件统一输出为 `[GTCatcher] {json}` 格式
- 为每个 App 生成单独日志文件

## 安装

### 前提

- 已有可用的 Theos 构建环境
- 目标设备已越狱
- 目标设备支持 rootless 包安装
- 设备已安装 `mobilesubstrate`

当前包信息：

- 包名：`com.iie.gtcatcher`
- 方案：`rootless`

### 1. 构建

```sh
CLANG_MODULE_CACHE_PATH=$PWD/.clang-module-cache make package
```

构建完成后，生成的 `.deb` 会出现在 `packages/` 目录下。

### 2. 安装到设备

如果你的 Theos 设备变量已经配置好，可以直接：

```sh
CLANG_MODULE_CACHE_PATH=$PWD/.clang-module-cache make install
```

如果你更喜欢手动安装 `.deb`，把 `packages/` 里的包传到设备后执行：

```sh
dpkg -i /path/to/com.iie.gtcatcher_*.deb
```

安装后建议执行一次用户空间重启或重载 tweak 环境，确保注入生效。

常见做法：

```sh
sbreload
```

## 如何使用

### 1. 确认注入范围

当前 [`GTCatcher.plist`](/Users/peiwithhao/repo/GTCatcher/GTCatcher.plist) 配置为广泛注入 UIKit App：

- `com.apple.UIKit`

这意味着大部分 UIKit 应用都会被注入。

如果你只想分析某个 App，可以把 `Bundles` 改成目标 App 的 bundle id，再重新安装或重载 tweak。

### 2. 启动目标 App 并触发网络行为

安装并生效后，直接打开目标 App，执行你要分析的动作，例如：

- 启动首页
- 登录
- 刷新数据
- 上传图片
- 触发长连接或消息同步

### 3. 查看日志

GTCatcher 会输出两类日志：

- 系统日志前缀：`[GTCatcher]`
- 每个 App 的本地日志文件

日志目录：

```text
/var/jb/var/mobile/Library/Logs/GTCatcher/
```

示例文件：

- `com.tencent.mqq.log`
- `com.meituan.imeituan.log`

如果只想快速看某个 App：

```sh
tail -f /var/jb/var/mobile/Library/Logs/GTCatcher/com.example.app.log
```

### 4. 理解日志内容

把 `[GTCatcher] {json}` 当成 hook 级应用内遥测，不要当成完整抓包。

需要注意：

- 一行只代表一次 hook 调用看到的内容
- `preview_hex` / `preview_ascii` 只是前缀预览
- `len` 是本次调用长度，不是整条流大小
- `bytes_in` / `bytes_out` 是 hook 侧累计值，不是严格 TCP 重组结果
- `nw_connection_receive_callback` 表示 receive completion 真正触发了

常见三层视角：

- `bsd`: socket 层
- `tls`: TLS 明文层
- `network`: `Network.framework` 高层

### 5. 快速做本地分析

常用命令：

```sh
rg -o '"layer":"[^"]+"' your.log | sort | uniq -c
rg -o '"event":"[^"]+"' your.log | sort | uniq -c
rg -n 'nw_connection_receive_callback|nw_connection_receive_message_callback' your.log
rg -n 'POST /|GET /|HTTP/1.1|PRI \* HTTP/2.0|Host: |Content-Type:' your.log
rg -n 'pid:[0-9]+\|fd:[0-9]+\|seq:[0-9]+\|' your.log
```

推荐的分析顺序：

1. 先按 `layer` 和 `event` 做全量盘点
2. 再看高频 `peer`、`http_host`、`stack_hash`
3. BSD 按 `flow_id` 分组
4. TLS 优先按 `flow_id` 或 `tls_conn_id` 分组
5. `network` 按 `nw_conn:*` 分组，并用 `receive_seq` 配对 receive 与 callback

仓库内已经有一份真实日志分析示例：

- [skills/com.meituan.imeituan.traffic-report.md](/Users/peiwithhao/repo/GTCatcher/skills/com.meituan.imeituan.traffic-report.md)

## 卸载

### 直接卸载包

包名是：

```text
com.iie.gtcatcher
```

可直接执行：

```sh
dpkg -r com.iie.gtcatcher
```

如果你使用的是包管理器，也可以在包管理器里直接移除 `GTCatcher`。

### 卸载后生效

卸载后同样建议执行一次用户空间重启或重载 tweak 环境：

```sh
sbreload
```

### 清理日志

卸载包不会自动清理你已经采集到的日志。如果你想把历史日志也删掉，再手动清理：

```sh
rm -rf /var/jb/var/mobile/Library/Logs/GTCatcher
```

## 当前 hook 覆盖

- BSD socket 层：`connect`, `close`, `send`, `sendto`, `write`, `writev`, `sendmsg`, `recv`, `recvfrom`, `read`, `readv`, `recvmsg`
- SecureTransport：`SSLSetConnection`, `SSLWrite`, `SSLRead`
- BoringSSL / OpenSSL 风格导出：`SSL_set_fd`, `SSL_set_bio`, `SSL_write`, `SSL_read`
- `Network.framework`：
  - `nw_connection_start`
  - `nw_connection_send`
  - `nw_connection_receive`
  - `nw_connection_receive_message`
  - wrapped completion blocks:
    - `nw_connection_receive_callback`
    - `nw_connection_receive_message_callback`

## 日志能力边界

当前实现擅长做行为重建，但有明确边界。

它更擅长证明：

- 哪些 host / peer / port 活跃
- 数据在哪一层可见
- 某次 `receive` 是否真的触发了 callback
- 是否出现了可读的 HTTP / HTTP/2 前缀
- 哪些流共享相同 `stack_hash`

它不能单独严格证明：

- 完整 TCP 流重组
- 对每条流都精确建立 `nw_conn:* -> TLS ctx -> fd` 映射
- 某个 preview 就等于完整业务消息
- 某个 callback 就等于完整业务响应
- HTTP/2 的 stream 级完整语义

## 与原始 Frida 脚本的主要差异

- Frida 的 `Thread.backtrace` / `DebugSymbol` 聚类被替换成原生 `backtrace()` + `dladdr()`
- 远程转发未实现，因为原始脚本本身只有 `console.log(JSON)`
- `Network.framework` payload 提取仍然是 best-effort
- 当前版本比旧版更强的一点是：`receive` callback 真正触发时也会记日志，而不只是记录 receive 注册
