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
