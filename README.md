[![zread](https://img.shields.io/badge/Ask_Zread-_.svg?style=for-the-badge&color=00b0aa&labelColor=000000&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTQuOTYxNTYgMS42MDAxSDIuMjQxNTZDMS44ODgxIDEuNjAwMSAxLjYwMTU2IDEuODg2NjQgMS42MDE1NiAyLjI0MDFWNC45NjAxQzEuNjAxNTYgNS4zMTM1NiAxLjg4ODEgNS42MDAxIDIuMjQxNTYgNS42MDAxSDQuOTYxNTZDNS4zMTUwMiA1LjYwMDEgNS42MDE1NiA1LjMxMzU2IDUuNjAxNTYgNC45NjAxVjIuMjQwMUM1LjYwMTU2IDEuODg2NjQgNS4zMTUwMiAxLjYwMDEgNC45NjE1NiAxLjYwMDFaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00Ljk2MTU2IDEwLjM5OTlIMi4yNDE1NkMxLjg4ODEgMTAuMzk5OSAxLjYwMTU2IDEwLjY4NjQgMS42MDE1NiAxMS4wMzk5VjEzLjc1OTlDMS42MDE1NiAxNC4xMTM0IDEuODg4MSAxNC4zOTk5IDIuMjQxNTYgMTQuMzk5OUg0Ljk2MTU2QzUuMzE1MDIgMTQuMzk5OSA1LjYwMTU2IDE0LjExMzQgNS42MDE1NiAxMy43NTk5VjExLjAzOTlDNS42MDE1NiAxMC42ODY0IDUuMzE1MDIgMTAuMzk5OSA0Ljk2MTU2IDEwLjM5OTlaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik0xMy43NTg0IDEuNjAwMUgxMS4wMzg0QzEwLjY4NSAxLjYwMDEgMTAuMzk4NCAxLjg4NjY0IDEwLjM5ODQgMi4yNDAxVjQuOTYwMUMxMC4zOTg0IDUuMzEzNTYgMTAuNjg1IDUuNjAwMSAxMS4wMzg0IDUuNjAwMUgxMy43NTg0QzE0LjExMTkgNS42MDAxIDE0LjM5ODQgNS4zMTM1NiAxNC4zOTg0IDQuOTYwMVYyLjI0MDFDMTQuMzk4NCAxLjg4NjY0IDE0LjExMTkgMS42MDAxIDEzLjc1ODQgMS42MDAxWiIgZmlsbD0iI2ZmZiIvPgo8cGF0aCBkPSJNNCAxMkwxMiA0TDQgMTJaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00IDEyTDEyIDQiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxLjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPgo8L3N2Zz4K&logoColor=ffffff)](https://zread.ai/peiwithhao/GTCatcher)
# GTCatcher Tweak

This project converts `ultimate_network_Tracer.js` into a Theos MobileSubstrate tweak.
It is configured to hook traffic from broadly all UIKit-based iOS apps.

## What it hooks

- BSD socket layer: `connect`, `close`, `send`, `sendto`, `write`, `writev`, `sendmsg`, `recv`, `recvfrom`, `read`, `readv`, `recvmsg`
- SecureTransport: `SSLSetConnection`, `SSLWrite`, `SSLRead`
- BoringSSL/OpenSSL-like exports: `SSL_set_fd`, `SSL_set_bio`, `SSL_write`, `SSL_read`
- Network.framework: `nw_connection_start`, `nw_connection_send`, `nw_connection_receive`, `nw_connection_receive_message`

## Output

- Unified JSON lines are written to system log with prefix `[GTCatcher]`
- Per-app log files are written to `/var/jb/var/mobile/Library/Logs/GTCatcher/`
- Each process gets its own file name based on `bundle_id`
- Example: `com.tencent.mqq.log`, `com.meituan.imeituan.log`

## Before install

`[GTCatcher.plist](/Users/peiwithhao/pwhRe/Network/GTCatcher/GTCatcher.plist)` is already set for broad UIKit app injection:

- `com.apple.UIKit`

If you want to narrow the scope again, replace that bundle entry with a specific app bundle identifier.

## Build

```sh
CLANG_MODULE_CACHE_PATH=$PWD/.clang-module-cache make
```

## Current behavior differences from the Frida script

- Frida `Thread.backtrace`/`DebugSymbol` clustering was replaced with native `backtrace()` plus `dladdr()`
- Remote forwarding is not implemented because the source script only emitted `console.log(JSON)` and did not contain a transport implementation
- `Network.framework` payload extraction stays best-effort, matching the original script's intent
