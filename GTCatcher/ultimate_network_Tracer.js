  // =========================================================================
  // Ultimate Network Tracer - Revised Prototype
  // 目标:
  // 1. BSD/CF/TLS 多层兜底
  // 2. 正确五元组解析
  // 3. 更稳的 FD 生命周期
  // 4. TLS ctx -> conn_id 关联骨架
  // =========================================================================

  console.log("\n[*] Starting revised network tracer...");
  console.log("[*] Layer1 transport hooks + Layer2 correlation + Layer3 clustering\n");

  var globalSessionMap = Object.create(null); // fd -> session
  var globalTlsMap = Object.create(null);     // ssl_ctx -> { conn_id, fd }

  // -------------------------------------------------------------------------
  // libc / system exports
  // -------------------------------------------------------------------------

  function mustFind(name, mod) {
      var p = Module.findExportByName(mod || null, name);
      if (!p) console.log("[!] export not found: " + (mod || "null") + "!" + name);
      return p;
  }

  var p_getsockname = mustFind("getsockname");
  var p_getpeername = mustFind("getpeername");
  var p_ntohs = mustFind("ntohs");
  var p_inet_ntop = mustFind("inet_ntop");
  var p_close = mustFind("close");
  var p_connect = mustFind("connect");
  var p_send = mustFind("send");
  var p_sendto = mustFind("sendto");
  var p_write = mustFind("write");
  var p_writev = mustFind("writev");
  var p_recv = mustFind("recv");
  var p_recvfrom = mustFind("recvfrom");
  var p_read = mustFind("read");
  var p_readv = mustFind("readv");

  var p_SSLWrite = mustFind("SSLWrite", "Security");
  var p_SSLRead = mustFind("SSLRead", "Security");
  var p_SSLSetConnection = mustFind("SSLSetConnection", "Security");

  var getsockname = p_getsockname ? new NativeFunction(p_getsockname, "int", ["int", "pointer", "pointer"]) : null;
  var getpeername = p_getpeername ? new NativeFunction(p_getpeername, "int", ["int", "pointer", "pointer"]) : null;
  var ntohs = p_ntohs ? new NativeFunction(p_ntohs, "uint16", ["uint16"]) : null;
  var inet_ntop = p_inet_ntop ? new NativeFunction(p_inet_ntop, "pointer", ["int", "pointer", "pointer", "int"]) : null;

  // -------------------------------------------------------------------------
  // helpers
  // -------------------------------------------------------------------------

  function nowMs() {
      return Date.now();
  }

  function ptrKey(p) {
      return p ? p.toString() : "0x0";
  }

  function readSizeT(v) {
      try {
          if (Process.pointerSize === 8) {
              return parseInt(v.toString(), 10);
          }
          return v.toUInt32();
      } catch (e) {
          try {
              return parseInt(v.toString(), 10);
          } catch (e2) {
              return 0;
          }
      }
  }

  function readSizeTFromMemory(p) {
      if (!p || p.isNull()) return 0;
      try {
          if (Process.pointerSize === 8) {
              return p.readU64().toNumber();
          }
          return p.readU32();
      } catch (e) {
          return 0;
      }
  }


  function djb2Hash(str) {
      var hash = 5381;
      for (var i = 0; i < str.length; i++) {
          hash = ((hash << 5) + hash) + str.charCodeAt(i);
      }
      return (hash >>> 0).toString(16);
  }

  function generateLightPreview(bufPtr, len, maxLen) {
      if (!bufPtr || bufPtr.isNull() || len <= 0) {
          return { hex: "", ascii: "" };
      }

      var readLen = Math.min(len, maxLen || 32);
      try {
          var raw = bufPtr.readByteArray(readLen);
          var bytes = new Uint8Array(raw);
          var hex = [];
          var ascii = [];

          for (var i = 0; i < bytes.length; i++) {
              var b = bytes[i];
              hex.push((b < 16 ? "0" : "") + b.toString(16));
              ascii.push((b >= 32 && b <= 126) ? String.fromCharCode(b) : ".");
          }

          return {
              hex: hex.join(""),
              ascii: ascii.join("")
          };
      } catch (e) {
          return { hex: "read_err", ascii: "read_err" };
      }
  }

  function extractClusterStack(context) {
      if (!context) return { hash: "no_ctx", frames: [] };

      try {
          var backtrace = Thread.backtrace(context, Backtracer.ACCURATE);
          var frames = [];
          var keyFrames = [];

          for (var i = 0; i < backtrace.length; i++) {
              var addr = backtrace[i];
              var sym = DebugSymbol.fromAddress(addr);
              var moduleName = sym.moduleName || "UnknownModule";
              var name = sym.name || addr.toString();

              var isNoise =
                  moduleName.indexOf("libsystem") !== -1 ||
                  moduleName.indexOf("libdyld") !== -1 ||
                  moduleName.indexOf("libdispatch") !== -1 ||
                  moduleName.indexOf("CoreFoundation") !== -1 ||
                  moduleName.indexOf("Foundation") !== -1 ||
                  moduleName.indexOf("CFNetwork") !== -1 ||
                  moduleName.indexOf("Security") !== -1 ||
                  moduleName.indexOf("Network") !== -1;

              if (!isNoise) {
                  var frame = moduleName + "!" + name;
                  frames.push(frame);
                  keyFrames.push(frame);
                  if (keyFrames.length >= 3) break;
              }
          }

          if (keyFrames.length === 0) {
              return { hash: "async_noise", frames: ["[System Managed Async Flow]"] };
          }

          return {
              hash: djb2Hash(keyFrames.join("|")),
              frames: frames
          };
      } catch (e) {
          return { hash: "unwind_err", frames: [] };
      }
  }

  // Darwin sockaddr
  function parseSockaddr(saPtr) {
      if (!saPtr || saPtr.isNull() || !ntohs || !inet_ntop) return null;

      var family = saPtr.add(1).readU8();
      var AF_INET = 2;
      var AF_INET6 = 30;
      var ipBuf = Memory.alloc(64);
      var port, ipStr;

      try {
          if (family === AF_INET) {
              port = ntohs(saPtr.add(2).readU16());
              inet_ntop(AF_INET, saPtr.add(4), ipBuf, 64);
              ipStr = ipBuf.readCString();
              return ipStr + ":" + port;
          }

          if (family === AF_INET6) {
              port = ntohs(saPtr.add(2).readU16());
              inet_ntop(AF_INET6, saPtr.add(8), ipBuf, 64);
              ipStr = ipBuf.readCString();
              return "[" + ipStr + "]:" + port;
          }

          if (family === 1) {
              return "unix";
          }

          return "af_" + family;
      } catch (e) {
          return "sockaddr_err";
      }
  }

  function allocSockaddr() {
      return {
          lenPtr: Memory.alloc(4),
          addrPtr: Memory.alloc(128)
      };
  }

  function getLocalAndPeer(fd) {
      if (!getsockname || !getpeername) return null;

      var local = allocSockaddr();
      var peer = allocSockaddr();

      local.lenPtr.writeU32(128);
      peer.lenPtr.writeU32(128);

      var localOk = getsockname(fd, local.addrPtr, local.lenPtr) === 0;
      var peerOk = getpeername(fd, peer.addrPtr, peer.lenPtr) === 0;

      return {
          localOk: localOk,
          peerOk: peerOk,
          local: localOk ? parseSockaddr(local.addrPtr) : null,
          peer: peerOk ? parseSockaddr(peer.addrPtr) : null
      };
  }

  function isNetworkLikeFd(fd) {
      if (fd <= 2) return false;
      return true;
  }

  function buildConnId(fd, info, seq) {
      var local = info && info.local ? info.local : "unknown_local";
      var peer = info && info.peer ? info.peer : "unknown_peer";
      return "pid:" + Process.id + "|fd:" + fd + "|seq:" + seq + "|" + local + "->" + peer;
  }

  function ensureFdSession(fd) {
      var key = fd.toString();
      var s = globalSessionMap[key];
      if (s) return s;

      s = {
          fd: fd,
          seq: 1,
          state: "pending",
          create_ts: nowMs(),
          conn_id: null,
          local: null,
          peer: null,
          bytes_in: 0,
          bytes_out: 0
      };
      globalSessionMap[key] = s;
      return s;
  }

  function refreshFdSession(fd) {
      var s = ensureFdSession(fd);
      var info = getLocalAndPeer(fd);

      if (!info) return s;

      if (info.localOk) s.local = info.local;
      if (info.peerOk) s.peer = info.peer;

      if (info.peerOk) {
          if (!s.conn_id) {
              s.conn_id = buildConnId(fd, info, s.seq);
          }
          s.state = "connected";
      }

      return s;
  }

  function markFdClosed(fd) {
      var key = fd.toString();
      if (globalSessionMap[key]) {
          delete globalSessionMap[key];
      }

      Object.keys(globalTlsMap).forEach(function (k) {
          if (globalTlsMap[k] && globalTlsMap[k].fd === fd) {
              delete globalTlsMap[k];
          }
      });
  }

  function getConnIdForFd(fd) {
      var s = refreshFdSession(fd);
      if (!s) return null;

      if (!s.conn_id) {
          return "pending_fd:" + fd;
      }
      return s.conn_id;
  }

  function getConnIdForTlsCtx(ctx) {
      var key = ptrKey(ctx);
      var t = globalTlsMap[key];
      if (t && t.conn_id) return t.conn_id;
      return "tls_ctx:" + key;
  }

  function linkTlsCtxToFd(ctx, fd) {
      var connId = getConnIdForFd(fd);
      globalTlsMap[ptrKey(ctx)] = {
          fd: fd,
          conn_id: connId,
          ts: nowMs()
      };
  }

  // -------------------------------------------------------------------------
  // logging
  // -------------------------------------------------------------------------

  function emitSmartLog(layer, event, connId, dataPtr, dataLen, context, extra) {
      var preview = generateLightPreview(dataPtr, dataLen, 32);

      var logObj = {
          ts: Date.now() / 1000.0,
          pid: Process.id,
          tid: Thread.id,
          layer: layer,
          event: event,
          conn_id: connId,
          len: dataLen || 0,
          preview_hex: preview.hex,
          preview_ascii: preview.ascii
      };

      if (extra) {
          Object.keys(extra).forEach(function (k) {
              logObj[k] = extra[k];
          });
      }

      if (context) {
          var stack = extractClusterStack(context);
          logObj.stack_hash = stack.hash;
          logObj.frames = stack.frames;
      }

      console.log(JSON.stringify(logObj));
  }

  // -------------------------------------------------------------------------
  // hooks
  // -------------------------------------------------------------------------

  if (p_close) {
      Interceptor.attach(p_close, {
          onEnter: function (args) {
              var fd = args[0].toInt32();
              markFdClosed(fd);
          }
      });
  }

  if (p_connect) {
      Interceptor.attach(p_connect, {
          onEnter: function (args) {
              this.fd = args[0].toInt32();
          },
          onLeave: function (retval) {
              if (this.fd > 2) {
                  refreshFdSession(this.fd);
              }
          }
      });
  }

  // Security.framework TLS ctx -> fd 关联骨架
  if (p_SSLSetConnection) {
      Interceptor.attach(p_SSLSetConnection, {
          onEnter: function (args) {
              var ctx = args[0];
              var connection = args[1];

              // 这里只能做“尝试关联”:
              // 某些实现里 connection 是 fd/int，某些是自定义对象/指针。
              // 若是小整数，按 fd 处理；否则保留原始 connection。
              try {
                  var maybeFd = connection.toInt32();
                  if (maybeFd > 2 && maybeFd < 0x100000) {
                      linkTlsCtxToFd(ctx, maybeFd);
                  } else {
                      globalTlsMap[ptrKey(ctx)] = {
                          fd: null,
                          conn_id: "tls_conn:" + ptrKey(connection),
                          ts: nowMs()
                      };
                  }
              } catch (e) {
                  globalTlsMap[ptrKey(ctx)] = {
                      fd: null,
                      conn_id: "tls_conn:" + ptrKey(connection),
                      ts: nowMs()
                  };
              }
          }
      });
  }

  [
      { name: "send", ptr: p_send, fdIndex: 0, bufIndex: 1, lenIndex: 2 },
      { name: "sendto", ptr: p_sendto, fdIndex: 0, bufIndex: 1, lenIndex: 2 },
      { name: "write", ptr: p_write, fdIndex: 0, bufIndex: 1, lenIndex: 2 }
  ].forEach(function (spec) {
      if (!spec.ptr) return;

      Interceptor.attach(spec.ptr, {
          onEnter: function (args) {
              var fd = args[spec.fdIndex].toInt32();
              if (!isNetworkLikeFd(fd)) return;

              var len = readSizeT(args[spec.lenIndex]);
              if (len <= 0) return;

              var connId = getConnIdForFd(fd);
              var s = ensureFdSession(fd);
              s.bytes_out += len;

              emitSmartLog("bsd", spec.name, connId, args[spec.bufIndex], len, this.context, {
                  fd: fd
              });
          }
      });
  });

  [
      { name: "recv", ptr: p_recv },
      { name: "recvfrom", ptr: p_recvfrom },
      { name: "read", ptr: p_read }
  ].forEach(function (spec) {
      if (!spec.ptr) return;

      Interceptor.attach(spec.ptr, {
          onEnter: function (args) {
              this.fd = args[0].toInt32();
              this.buf = args[1];
          },
          onLeave: function (retval) {
              if (!isNetworkLikeFd(this.fd)) return;

              var len = retval.toInt32();
              if (len <= 0) return;

              var connId = getConnIdForFd(this.fd);
              var s = ensureFdSession(this.fd);
              s.bytes_in += len;

              emitSmartLog("bsd", spec.name, connId, this.buf, len, null, {
                  fd: this.fd
              });
          }
      });
  });

  if (p_writev) {
      Interceptor.attach(p_writev, {
          onEnter: function (args) {
              var fd = args[0].toInt32();
              if (!isNetworkLikeFd(fd)) return;

              var iov = args[1];
              var iovcnt = args[2].toInt32();
              if (iovcnt <= 0) return;

              var base = iov.readPointer();
              var len = readSizeTFromMemory(iov.add(Process.pointerSize).readPointer());

              if (len <= 0) return;

              var connId = getConnIdForFd(fd);
              emitSmartLog("bsd", "writev", connId, base, len, this.context, {
                  fd: fd,
                  iovcnt: iovcnt
              });
          }
      });
  }

  if (p_readv) {
      Interceptor.attach(p_readv, {
          onEnter: function (args) {
              this.fd = args[0].toInt32();
              this.iov = args[1];
              this.iovcnt = args[2].toInt32();
          },
          onLeave: function (retval) {
              if (!isNetworkLikeFd(this.fd)) return;

              var total = retval.toInt32();
              if (total <= 0 || this.iovcnt <= 0) return;

              var base = this.iov.readPointer();
              var firstLen = readSizeTFromMemory(this.iov.add(Process.pointerSize).readPointer());

              emitSmartLog("bsd", "readv", getConnIdForFd(this.fd), base, Math.min(total, firstLen), null, {
                  fd: this.fd,
                  iovcnt: this.iovcnt,
                  total_len: total
              });
          }
      });
  }

  if (p_SSLWrite) {
      Interceptor.attach(p_SSLWrite, {
          onEnter: function (args) {
              var ctx = args[0];
              var len = readSizeT(args[2]);
              if (len <= 0) return;

              emitSmartLog("tls", "SSLWrite", getConnIdForTlsCtx(ctx), args[1], len, this.context, {
                  ssl_ctx: ptrKey(ctx)
              });
          }
      });
  }

  if (p_SSLRead) {
      Interceptor.attach(p_SSLRead, {
          onEnter: function (args) {
              this.ctx = args[0];
              this.buf = args[1];
              this.processedPtr = args[3];
          },
          onLeave: function (retval) {
              if (!this.processedPtr || this.processedPtr.isNull()) return;

              var actualLen;
              try {
                  actualLen = Process.pointerSize === 8
                      ? this.processedPtr.readU64().toNumber()
                      : this.processedPtr.readU32();
              } catch (e) {
                  return;
              }

              if (actualLen <= 0) return;

              emitSmartLog("tls", "SSLRead", getConnIdForTlsCtx(this.ctx), this.buf, actualLen, null, {
                  ssl_ctx: ptrKey(this.ctx)
              });
          }
      });
  }

  // =========================================================================
  // Extended Hooks: BoringSSL + sendmsg/recvmsg + nw_connection_*
  // =========================================================================

  var globalNwMap = Object.create(null);      // nw_connection ptr -> meta
  var globalBioMap = Object.create(null);     // BIO ptr -> { fd?, bio_ptr }
  var globalBoringSslMap = Object.create(null); // SSL ptr -> { fd?, conn_id?, bio? }

  // -------------------------------------------------------------------------
  // extra exports
  // -------------------------------------------------------------------------

  var p_sendmsg = Module.findExportByName(null, "sendmsg");
  var p_recvmsg = Module.findExportByName(null, "recvmsg");

  // BoringSSL / OpenSSL-like
  var p_SSL_write_boring = Module.findExportByName(null, "SSL_write");
  var p_SSL_read_boring = Module.findExportByName(null, "SSL_read");
  var p_SSL_set_fd_boring = Module.findExportByName(null, "SSL_set_fd");
  var p_SSL_set_bio_boring = Module.findExportByName(null, "SSL_set_bio");

  // Network.framework
  var p_nw_connection_send = Module.findExportByName("Network", "nw_connection_send");
  var p_nw_connection_receive = Module.findExportByName("Network", "nw_connection_receive");
  var p_nw_connection_receive_message = Module.findExportByName("Network", "nw_connection_receive_message");
  var p_nw_connection_start = Module.findExportByName("Network", "nw_connection_start");

  // dispatch_data helpers
  var p_dispatch_data_get_size = Module.findExportByName(null, "dispatch_data_get_size");
  var p_dispatch_data_create_map = Module.findExportByName(null, "dispatch_data_create_map");

  var dispatch_data_get_size = p_dispatch_data_get_size
      ? new NativeFunction(p_dispatch_data_get_size, "ulong", ["pointer"])
      : null;

  // const void *dispatch_data_create_map(dispatch_data_t data, const void **buffer_ptr, size_t *size_ptr);
  var dispatch_data_create_map = p_dispatch_data_create_map
      ? new NativeFunction(p_dispatch_data_create_map, "pointer", ["pointer", "pointer", "pointer"])
      : null;

  // -------------------------------------------------------------------------
  // robust size helpers
  // -------------------------------------------------------------------------

  function readArgSizeT(v) {
      try {
          return parseInt(v.toString(), 10);
      } catch (e) {
          return 0;
      }
  }

  function readSizeTFromMemory(p) {
      if (!p || p.isNull()) return 0;
      try {
          if (Process.pointerSize === 8) {
              return p.readU64().toNumber();
          }
          return p.readU32();
      } catch (e) {
          return 0;
      }
  }

  function readSocklenFromMemory(p) {
      if (!p || p.isNull()) return 0;
      try {
          return p.readU32();
      } catch (e) {
          return 0;
      }
  }

  // -------------------------------------------------------------------------
  // iovec / msghdr helpers
  // Darwin iovec:
  //   void *iov_base;
  //   size_t iov_len;
  // Darwin msghdr:
  //   void         *msg_name;
  //   socklen_t     msg_namelen;
  //   struct iovec *msg_iov;
  //   int           msg_iovlen;
  //   void         *msg_control;
  //   socklen_t     msg_controllen;
  //   int           msg_flags;
  // -------------------------------------------------------------------------

  function getIovecBase(iovPtr) {
      if (!iovPtr || iovPtr.isNull()) return ptr(0);
      try {
          return iovPtr.readPointer();
      } catch (e) {
          return ptr(0);
      }
  }

  function getIovecLen(iovPtr) {
      if (!iovPtr || iovPtr.isNull()) return 0;
      try {
          return readSizeTFromMemory(iovPtr.add(Process.pointerSize));
      } catch (e) {
          return 0;
      }
  }

  function parseMsghdr(msgPtr) {
      if (!msgPtr || msgPtr.isNull()) return null;

      try {
          var off = 0;
          var msg_name = msgPtr.add(off).readPointer();
          off += Process.pointerSize;

          var msg_namelen = msgPtr.add(off).readU32();
          off += 4;
          if (Process.pointerSize === 8) off += 4; // alignment on arm64

          var msg_iov = msgPtr.add(off).readPointer();
          off += Process.pointerSize;

          var msg_iovlen;
          if (Process.pointerSize === 8) {
              msg_iovlen = msgPtr.add(off).readS64().toNumber();
              off += 8;
          } else {
              msg_iovlen = msgPtr.add(off).readS32();
              off += 4;
          }

          var msg_control = msgPtr.add(off).readPointer();
          off += Process.pointerSize;

          var msg_controllen;
          if (Process.pointerSize === 8) {
              msg_controllen = msgPtr.add(off).readU64().toNumber();
              off += 8;
          } else {
              msg_controllen = msgPtr.add(off).readU32();
              off += 4;
          }

          var msg_flags = msgPtr.add(off).readS32();

          return {
              msg_name: msg_name,
              msg_namelen: msg_namelen,
              msg_iov: msg_iov,
              msg_iovlen: msg_iovlen,
              msg_control: msg_control,
              msg_controllen: msg_controllen,
              msg_flags: msg_flags
          };
      } catch (e) {
          return null;
      }
  }

  function previewFromMsghdr(msgPtr, totalLenHint) {
      var mh = parseMsghdr(msgPtr);
      if (!mh || !mh.msg_iov || mh.msg_iov.isNull() || mh.msg_iovlen <= 0) {
          return { ptr: ptr(0), len: 0, iovcnt: 0 };
      }

      var firstIov = mh.msg_iov;
      var base = getIovecBase(firstIov);
      var len = getIovecLen(firstIov);

      if (totalLenHint > 0 && len > totalLenHint) {
          len = totalLenHint;
      }

      return {
          ptr: base,
          len: len,
          iovcnt: mh.msg_iovlen
      };
  }

  // -------------------------------------------------------------------------
  // dispatch_data helper
  // -------------------------------------------------------------------------

  function previewFromDispatchData(dispatchData) {
      if (!dispatchData || dispatchData.isNull() || !dispatch_data_get_size || !dispatch_data_create_map) {
          return { ptr: ptr(0), len: 0 };
      }

      try {
          var size = dispatch_data_get_size(dispatchData);
          if (!size || size <= 0) return { ptr: ptr(0), len: 0 };

          var bufPtrPtr = Memory.alloc(Process.pointerSize);
          var sizePtr = Memory.alloc(Process.pointerSize);
          bufPtrPtr.writePointer(ptr(0));
          if (Process.pointerSize === 8) {
              sizePtr.writeU64(0);
          } else {
              sizePtr.writeU32(0);
          }

          var mappedObj = dispatch_data_create_map(dispatchData, bufPtrPtr, sizePtr);
          var mappedBuf = bufPtrPtr.readPointer();
          var mappedLen = readSizeTFromMemory(sizePtr);

          if (!mappedBuf || mappedBuf.isNull() || mappedLen <= 0) {
              return { ptr: ptr(0), len: 0 };
          }

          return {
              ptr: mappedBuf,
              len: mappedLen,
              mappedObj: mappedObj
          };
      } catch (e) {
          return { ptr: ptr(0), len: 0 };
      }
  }

  // -------------------------------------------------------------------------
  // boring ssl correlation helpers
  // -------------------------------------------------------------------------

  function boringSslKey(sslPtr) {
      return ptrKey(sslPtr);
  }

  function linkBoringSslToFd(sslPtr, fd) {
      var key = boringSslKey(sslPtr);
      globalBoringSslMap[key] = globalBoringSslMap[key] || {};
      globalBoringSslMap[key].fd = fd;
      globalBoringSslMap[key].conn_id = getConnIdForFd(fd);
      globalBoringSslMap[key].ts = nowMs();
  }

  function linkBoringSslToBio(sslPtr, bioPtr) {
      var key = boringSslKey(sslPtr);
      globalBoringSslMap[key] = globalBoringSslMap[key] || {};
      globalBoringSslMap[key].bio = ptrKey(bioPtr);
      globalBoringSslMap[key].ts = nowMs();

      var bioMeta = globalBioMap[ptrKey(bioPtr)];
      if (bioMeta && bioMeta.fd) {
          globalBoringSslMap[key].fd = bioMeta.fd;
          globalBoringSslMap[key].conn_id = getConnIdForFd(bioMeta.fd);
      }
  }

  function getConnIdForBoringSsl(sslPtr) {
      var meta = globalBoringSslMap[boringSslKey(sslPtr)];
      if (meta) {
          if (meta.conn_id) return meta.conn_id;
          if (meta.fd) return getConnIdForFd(meta.fd);
          if (meta.bio) return "boringssl_bio:" + meta.bio;
      }
      return "boringssl_ssl:" + ptrKey(sslPtr);
  }

  // -------------------------------------------------------------------------
  // nw helpers
  // -------------------------------------------------------------------------

  function nwKey(connPtr) {
      return ptrKey(connPtr);
  }

  function ensureNwConn(connPtr) {
      var key = nwKey(connPtr);
      if (!globalNwMap[key]) {
          globalNwMap[key] = {
              nw_ptr: key,
              ts: nowMs(),
              conn_id: "nw_conn:" + key
          };
      }
      return globalNwMap[key];
  }

  // -------------------------------------------------------------------------
  // sendmsg / recvmsg
  // -------------------------------------------------------------------------

  if (p_sendmsg) {
      Interceptor.attach(p_sendmsg, {
          onEnter: function (args) {
              var fd = args[0].toInt32();
              if (!isNetworkLikeFd(fd)) return;

              var msgPtr = args[1];
              var flags = args[2].toInt32();

              var info = previewFromMsghdr(msgPtr, 0);
              if (!info.ptr || info.ptr.isNull() || info.len <= 0) return;

              var connId = getConnIdForFd(fd);
              var s = ensureFdSession(fd);
              s.bytes_out += info.len;

              emitSmartLog("bsd", "sendmsg", connId, info.ptr, info.len, this.context, {
                  fd: fd,
                  iovcnt: info.iovcnt,
                  flags: flags
              });
          }
      });
  }

  if (p_recvmsg) {
      Interceptor.attach(p_recvmsg, {
          onEnter: function (args) {
              this.fd = args[0].toInt32();
              this.msgPtr = args[1];
              this.flags = args[2].toInt32();
          },
          onLeave: function (retval) {
              if (!isNetworkLikeFd(this.fd)) return;

              var total = retval.toInt32();
              if (total <= 0) return;

              var info = previewFromMsghdr(this.msgPtr, total);
              if (!info.ptr || info.ptr.isNull() || info.len <= 0) return;

              var connId = getConnIdForFd(this.fd);
              var s = ensureFdSession(this.fd);
              s.bytes_in += total;

              emitSmartLog("bsd", "recvmsg", connId, info.ptr, info.len, null, {
                  fd: this.fd,
                  iovcnt: info.iovcnt,
                  flags: this.flags,
                  total_len: total
              });
          }
      });
  }

  // -------------------------------------------------------------------------
  // writev/readv fix
  // -------------------------------------------------------------------------

  if (p_writev) {
      Interceptor.attach(p_writev, {
          onEnter: function (args) {
              var fd = args[0].toInt32();
              if (!isNetworkLikeFd(fd)) return;

              var iov = args[1];
              var iovcnt = args[2].toInt32();
              if (iovcnt <= 0) return;

              var base = getIovecBase(iov);
              var len = getIovecLen(iov);
              if (!base || base.isNull() || len <= 0) return;

              emitSmartLog("bsd", "writev", getConnIdForFd(fd), base, len, this.context, {
                  fd: fd,
                  iovcnt: iovcnt
              });
          }
      });
  }

  if (p_readv) {
      Interceptor.attach(p_readv, {
          onEnter: function (args) {
              this.fd = args[0].toInt32();
              this.iov = args[1];
              this.iovcnt = args[2].toInt32();
          },
          onLeave: function (retval) {
              if (!isNetworkLikeFd(this.fd)) return;

              var total = retval.toInt32();
              if (total <= 0 || this.iovcnt <= 0) return;

              var base = getIovecBase(this.iov);
              var firstLen = getIovecLen(this.iov);
              if (!base || base.isNull() || firstLen <= 0) return;

              emitSmartLog("bsd", "readv", getConnIdForFd(this.fd), base, Math.min(total, firstLen), null, {
                  fd: this.fd,
                  iovcnt: this.iovcnt,
                  total_len: total
              });
          }
      });
  }

  // -------------------------------------------------------------------------
  // BoringSSL hooks
  // -------------------------------------------------------------------------

  if (p_SSL_set_fd_boring) {
      Interceptor.attach(p_SSL_set_fd_boring, {
          onEnter: function (args) {
              var ssl = args[0];
              var fd = args[1].toInt32();
              if (fd > 2) {
                  linkBoringSslToFd(ssl, fd);
              }
          }
      });
  }

  if (p_SSL_set_bio_boring) {
      Interceptor.attach(p_SSL_set_bio_boring, {
          onEnter: function (args) {
              var ssl = args[0];
              var rbio = args[1];
              var wbio = args[2];

              if (rbio && !rbio.isNull()) {
                  globalBioMap[ptrKey(rbio)] = globalBioMap[ptrKey(rbio)] || { bio_ptr: ptrKey(rbio) };
                  linkBoringSslToBio(ssl, rbio);
              }

              if (wbio && !wbio.isNull()) {
                  globalBioMap[ptrKey(wbio)] = globalBioMap[ptrKey(wbio)] || { bio_ptr: ptrKey(wbio) };
                  linkBoringSslToBio(ssl, wbio);
              }
          }
      });
  }

  if (p_SSL_write_boring) {
      Interceptor.attach(p_SSL_write_boring, {
          onEnter: function (args) {
              var ssl = args[0];
              var buf = args[1];
              var len = args[2].toInt32();
              if (len <= 0) return;

              emitSmartLog("tls", "SSL_write", getConnIdForBoringSsl(ssl), buf, len, this.context, {
                  ssl_ctx: ptrKey(ssl),
                  tls_impl: "BoringSSL"
              });
          }
      });
  }

  if (p_SSL_read_boring) {
      Interceptor.attach(p_SSL_read_boring, {
          onEnter: function (args) {
              this.ssl = args[0];
              this.buf = args[1];
          },
          onLeave: function (retval) {
              var len = retval.toInt32();
              if (len <= 0) return;

              emitSmartLog("tls", "SSL_read", getConnIdForBoringSsl(this.ssl), this.buf, len, null, {
                  ssl_ctx: ptrKey(this.ssl),
                  tls_impl: "BoringSSL"
              });
          }
      });
  }

  // -------------------------------------------------------------------------
  // Network.framework hooks
  // signatures here are used in a "best effort" way for tracing/correlation
  // rather than ABI-perfect payload extraction across every iOS version.
  // -------------------------------------------------------------------------

  if (p_nw_connection_start) {
      Interceptor.attach(p_nw_connection_start, {
          onEnter: function (args) {
              var conn = args[0];
              ensureNwConn(conn);
          }
      });
  }

  if (p_nw_connection_send) {
      Interceptor.attach(p_nw_connection_send, {
          onEnter: function (args) {
              var conn = args[0];
              var content = args[1]; // often dispatch_data_t
              var contextObj = args[2];
              var isComplete = args[3];
              var completion = args[4];

              var meta = ensureNwConn(conn);
              var preview = previewFromDispatchData(content);

              emitSmartLog(
                  "network",
                  "nw_connection_send",
                  meta.conn_id,
                  preview.ptr,
                  preview.len,
                  this.context,
                  {
                      nw_ptr: ptrKey(conn),
                      has_content: !!(content && !content.isNull()),
                      is_complete: isComplete ? isComplete.toInt32() : 0,
                      content_context: ptrKey(contextObj),
                      completion: ptrKey(completion)
                  }
              );
          }
      });
  }

  if (p_nw_connection_receive) {
      Interceptor.attach(p_nw_connection_receive, {
          onEnter: function (args) {
              var conn = args[0];
              var minLen = args[1].toInt32();
              var maxLen = args[2].toInt32();
              var completion = args[3];

              var meta = ensureNwConn(conn);

              emitSmartLog(
                  "network",
                  "nw_connection_receive",
                  meta.conn_id,
                  ptr(0),
                  0,
                  this.context,
                  {
                      nw_ptr: ptrKey(conn),
                      min_incomplete_length: minLen,
                      max_length: maxLen,
                      completion: ptrKey(completion)
                  }
              );
          }
      });
  }

  if (p_nw_connection_receive_message) {
      Interceptor.attach(p_nw_connection_receive_message, {
          onEnter: function (args) {
              var conn = args[0];
              var completion = args[1];
              var meta = ensureNwConn(conn);

              emitSmartLog(
                  "network",
                  "nw_connection_receive_message",
                  meta.conn_id,
                  ptr(0),
                  0,
                  this.context,
                  {
                      nw_ptr: ptrKey(conn),
                      completion: ptrKey(completion)
                  }
              );
          }
      });
  }

