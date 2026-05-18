#import <Foundation/Foundation.h>
#import <Security/SecureTransport.h>
#import <substrate.h>
#import "fishhook.h"
#import "GTExtraContext.h"

#include <arpa/inet.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <objc/runtime.h>
#include <os/lock.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>

typedef int32_t OSStatus;
typedef unsigned int BOOL32;
typedef const void *dispatch_data_t_compat;

static NSString *const kGTCatcherLogDir = @"/var/jb/var/mobile/Library/Logs/GTCatcher";

static os_unfair_lock gStateLock = OS_UNFAIR_LOCK_INIT;
static NSMutableDictionary<NSString *, NSMutableDictionary *> *gSessionMap;
static NSMutableDictionary<NSString *, NSMutableDictionary *> *gTlsMap;
static NSMutableDictionary<NSString *, NSMutableDictionary *> *gBioMap;
static NSMutableDictionary<NSString *, NSMutableDictionary *> *gBoringSSLMap;
static NSMutableDictionary<NSString *, NSMutableDictionary *> *gNwMap;
static dispatch_queue_t gLogQueue;
static int gLogFd = -1;
static NSString *gProcessLogPath;
static NSString *gProcessBundleID;
static NSString *gProcessName;
static __thread BOOL gInEmitLog = NO;
static BOOL gEnableTlsHooks = YES;
static BOOL gEnableNwHooks = YES;
static BOOL gEnableWideBsdHooks = YES;
static BOOL gEnableUdpHooks = YES;
static BOOL gEnableStacks = YES;
static BOOL gEnablePayloadPreview = YES;
static BOOL gEnablePeerMetadata = YES;
static BOOL gEnableConnectHooks = YES;
static BOOL gEnableSendHooks = YES;
static BOOL gEnableRecvHooks = YES;
static BOOL gEnableSendtoHooks = YES;
static BOOL gEnableRecvfromHooks = YES;

// Toggle these flags directly, then rebuild and reinstall.
// Recommended debug order:
// 1. gEnableConnectHooks = YES
// 2. gEnableSendHooks = YES, then gEnableRecvHooks = YES
// 3. Then try gEnableSendtoHooks / gEnableRecvfromHooks
// 4. Then restore payload preview / peer metadata / stacks
// 5. Only after that restore TLS / Network.framework / wide BSD

static int (*orig_close)(int);
static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static ssize_t (*orig_send)(int, const void *, size_t, int);
static ssize_t (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*orig_write)(int, const void *, size_t);
static ssize_t (*orig_writev)(int, const struct iovec *, int);
static ssize_t (*orig_recv)(int, void *, size_t, int);
static ssize_t (*orig_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
static ssize_t (*orig_read)(int, void *, size_t);
static ssize_t (*orig_readv)(int, const struct iovec *, int);
static ssize_t (*orig_sendmsg)(int, const struct msghdr *, int);
static ssize_t (*orig_recvmsg)(int, struct msghdr *, int);

static OSStatus (*orig_SSLWrite)(SSLContextRef, const void *, size_t, size_t *);
static OSStatus (*orig_SSLRead)(SSLContextRef, void *, size_t, size_t *);
static OSStatus (*orig_SSLSetConnection)(SSLContextRef, SSLConnectionRef);

static int (*orig_SSL_write_boring)(void *, const void *, int);
static int (*orig_SSL_read_boring)(void *, void *, int);
static int (*orig_SSL_set_fd_boring)(void *, int);
static void (*orig_SSL_set_bio_boring)(void *, void *, void *);
static int (*orig_BIO_set_fd_boring)(void *, int, int);

static void (*orig_nw_connection_send)(void *, void *, void *, BOOL32, void *);
static void (*orig_nw_connection_receive)(void *, uint32_t, uint32_t, void *);
static void (*orig_nw_connection_receive_message)(void *, void *);
static void (*orig_nw_connection_start)(void *);

static size_t (*orig_dispatch_data_get_size)(dispatch_data_t);
static dispatch_data_t (*orig_dispatch_data_create_map)(dispatch_data_t, const void **, size_t *);

static ssize_t hook_send_fish(int fd, const void *buf, size_t len, int flags);
static ssize_t hook_recv_fish(int fd, void *buf, size_t len, int flags);
static ssize_t hook_sendto_fish(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen);
static ssize_t hook_recvfrom_fish(int fd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *addrlen);

static uint64_t gt_now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);
}

static uint64_t gt_tid(void) {
    uint64_t tid = 0;
    pthread_threadid_np(NULL, &tid);
    return tid;
}

static NSString *gt_ptr_string(const void *ptr) {
    return [NSString stringWithFormat:@"0x%llx", (unsigned long long)(uintptr_t)ptr];
}

static NSString *gt_sanitize_path_component(NSString *text) {
    if (text.length == 0) {
        return @"unknown";
    }

    NSMutableString *out = [NSMutableString stringWithCapacity:text.length];
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"];
    for (NSUInteger i = 0; i < text.length; i++) {
        unichar ch = [text characterAtIndex:i];
        if ([allowed characterIsMember:ch]) {
            [out appendFormat:@"%C", ch];
        } else {
            [out appendString:@"_"];
        }
    }
    return out.length > 0 ? out : @"unknown";
}

static void gt_init_process_identity(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSBundle *bundle = [NSBundle mainBundle];
        NSString *bundleID = bundle.bundleIdentifier;
        NSString *processName = NSProcessInfo.processInfo.processName ?: @"unknown";
        if (bundleID.length == 0) {
            bundleID = processName.length > 0 ? processName : [NSString stringWithFormat:@"pid_%d", getpid()];
        }

        gProcessBundleID = [bundleID copy];
        gProcessName = [processName copy];
        gProcessLogPath = [NSString stringWithFormat:@"%@/%@.log", kGTCatcherLogDir, gt_sanitize_path_component(gProcessBundleID)];
    });
}

static uint32_t gt_djb2_hash(NSString *text) {
    uint32_t hash = 5381;
    NSUInteger length = text.length;
    for (NSUInteger i = 0; i < length; i++) {
        hash = ((hash << 5) + hash) + [text characterAtIndex:i];
    }
    return hash;
}

static NSDictionary *gt_generate_preview(const void *buf, size_t len, size_t maxLen) {
    if (!buf || len == 0) {
        return @{@"hex": @"", @"ascii": @""};
    }

    size_t readLen = MIN(len, maxLen ?: 32);
    const uint8_t *bytes = (const uint8_t *)buf;
    NSMutableString *hex = [NSMutableString stringWithCapacity:readLen * 2];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:readLen];
    for (size_t i = 0; i < readLen; i++) {
        uint8_t b = bytes[i];
        [hex appendFormat:@"%02x", b];
        [ascii appendFormat:@"%c", (b >= 32 && b <= 126) ? b : '.'];
    }
    return @{@"hex": hex, @"ascii": ascii};
}

static BOOL gt_is_noise_frame(NSString *imageName) {
    static NSArray<NSString *> *noiseModules;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        noiseModules = @[
            @"libsystem", @"libdyld", @"libdispatch", @"CoreFoundation",
            @"Foundation", @"CFNetwork", @"Security", @"Network"
        ];
    });
    for (NSString *mod in noiseModules) {
        if ([imageName rangeOfString:mod options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return YES;
        }
    }
    return NO;
}

static NSDictionary *gt_extract_stack(void) {
    void *frames[32] = {0};
    int count = backtrace(frames, 32);
    NSMutableArray<NSString *> *visibleFrames = [NSMutableArray array];
    NSMutableArray<NSString *> *keyFrames = [NSMutableArray array];

    for (int i = 0; i < count; i++) {
        Dl_info info = {0};
        if (!dladdr(frames[i], &info)) {
            continue;
        }

        NSString *imageName = info.dli_fname ? [NSString stringWithUTF8String:info.dli_fname].lastPathComponent : @"UnknownModule";
        NSString *symbol = info.dli_sname ? [NSString stringWithUTF8String:info.dli_sname] : gt_ptr_string(frames[i]);
        if (gt_is_noise_frame(imageName)) {
            continue;
        }

        NSString *frame = [NSString stringWithFormat:@"%@!%@", imageName, symbol];
        [visibleFrames addObject:frame];
        [keyFrames addObject:frame];
        if (keyFrames.count >= 3) {
            break;
        }
    }

    if (keyFrames.count == 0) {
        return @{@"hash": @"async_noise", @"frames": @[@"[System Managed Async Flow]"]};
    }

    NSString *joined = [keyFrames componentsJoinedByString:@"|"];
    return @{
        @"hash": [NSString stringWithFormat:@"%x", gt_djb2_hash(joined)],
        @"frames": visibleFrames
    };
}

static NSString *gt_parse_sockaddr(const struct sockaddr *sa) {
    if (!sa) {
        return nil;
    }

    char ipbuf[INET6_ADDRSTRLEN] = {0};
    switch (sa->sa_family) {
        case AF_INET: {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
            inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf));
            return [NSString stringWithFormat:@"%s:%u", ipbuf, ntohs(sin->sin_port)];
        }
        case AF_INET6: {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
            inet_ntop(AF_INET6, &sin6->sin6_addr, ipbuf, sizeof(ipbuf));
            return [NSString stringWithFormat:@"[%s]:%u", ipbuf, ntohs(sin6->sin6_port)];
        }
        case AF_UNIX:
            return @"unix";
        default:
            return [NSString stringWithFormat:@"af_%d", sa->sa_family];
    }
}

static NSDictionary *gt_local_and_peer(int fd) {
    struct sockaddr_storage local = {0};
    struct sockaddr_storage peer = {0};
    socklen_t localLen = sizeof(local);
    socklen_t peerLen = sizeof(peer);

    BOOL localOk = getsockname(fd, (struct sockaddr *)&local, &localLen) == 0;
    BOOL peerOk = getpeername(fd, (struct sockaddr *)&peer, &peerLen) == 0;

    return @{
        @"localOk": @(localOk),
        @"peerOk": @(peerOk),
        @"local": localOk ? (gt_parse_sockaddr((struct sockaddr *)&local) ?: [NSNull null]) : [NSNull null],
        @"peer": peerOk ? (gt_parse_sockaddr((struct sockaddr *)&peer) ?: [NSNull null]) : [NSNull null]
    };
}

static BOOL gt_is_inet_sockaddr(const struct sockaddr *sa) {
    if (!sa) {
        return NO;
    }
    return sa->sa_family == AF_INET || sa->sa_family == AF_INET6;
}

static uint16_t gt_sockaddr_port(const struct sockaddr *sa) {
    if (!sa) {
        return 0;
    }
    if (sa->sa_family == AF_INET) {
        return ntohs(((const struct sockaddr_in *)sa)->sin_port);
    }
    if (sa->sa_family == AF_INET6) {
        return ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
    }
    return 0;
}

static BOOL gt_should_trace_sockaddr(const struct sockaddr *sa) {
    if (!gt_is_inet_sockaddr(sa)) {
        return NO;
    }
    uint16_t port = gt_sockaddr_port(sa);
    if (port == 123) {
        return NO;
    }
    return YES;
}

static BOOL gt_is_network_like_fd(int fd) {
    if (fd <= 2) {
        return NO;
    }

    int sockType = 0;
    socklen_t optLen = sizeof(sockType);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &sockType, &optLen) != 0) {
        return NO;
    }

    if (sockType == SOCK_STREAM) {
        // allowed
    } else if (gEnableUdpHooks && (sockType == SOCK_DGRAM || sockType == SOCK_SEQPACKET)) {
        // allowed only when explicitly enabled
    } else {
        return NO;
    }

    struct sockaddr_storage local = {0};
    struct sockaddr_storage peer = {0};
    socklen_t localLen = sizeof(local);
    socklen_t peerLen = sizeof(peer);

    BOOL localOk = getsockname(fd, (struct sockaddr *)&local, &localLen) == 0;
    BOOL peerOk = getpeername(fd, (struct sockaddr *)&peer, &peerLen) == 0;

    if (peerOk && gt_should_trace_sockaddr((const struct sockaddr *)&peer)) {
        return YES;
    }
    if (localOk && gt_should_trace_sockaddr((const struct sockaddr *)&local)) {
        return YES;
    }
    return NO;
}

static NSString *gt_build_conn_id(int fd, NSDictionary *info, NSNumber *seq) {
    id local = info[@"local"];
    id peer = info[@"peer"];
    NSString *localValue = [local isKindOfClass:[NSString class]] ? local : @"unknown_local";
    NSString *peerValue = [peer isKindOfClass:[NSString class]] ? peer : @"unknown_peer";
    return [NSString stringWithFormat:@"pid:%d|fd:%d|seq:%@|%@->%@", getpid(), fd, seq, localValue, peerValue];
}

static NSMutableDictionary *gt_ensure_fd_session_unlocked(int fd) {
    NSString *key = [NSString stringWithFormat:@"%d", fd];
    NSMutableDictionary *session = gSessionMap[key];
    if (session) {
        return session;
    }

    session = [@{
        @"fd": @(fd),
        @"seq": @1,
        @"state": @"pending",
        @"create_ts": @(gt_now_ms()),
        @"bytes_in": @0,
        @"bytes_out": @0
    } mutableCopy];
    gSessionMap[key] = session;
    return session;
}

static NSMutableDictionary *gt_refresh_fd_session_unlocked(int fd) {
    NSMutableDictionary *session = gt_ensure_fd_session_unlocked(fd);
    NSDictionary *info = gt_local_and_peer(fd);
    if (!info) {
        return session;
    }

    if ([info[@"localOk"] boolValue] && [info[@"local"] isKindOfClass:[NSString class]]) {
        session[@"local"] = info[@"local"];
    }
    if ([info[@"peerOk"] boolValue] && [info[@"peer"] isKindOfClass:[NSString class]]) {
        session[@"peer"] = info[@"peer"];
    }
    if ([info[@"peerOk"] boolValue]) {
        if (!session[@"conn_id"]) {
            session[@"conn_id"] = gt_build_conn_id(fd, info, session[@"seq"]);
        }
        session[@"state"] = @"connected";
    }
    return session;
}

static NSMutableDictionary *gt_refresh_fd_session(int fd) {
    os_unfair_lock_lock(&gStateLock);
    NSMutableDictionary *session = gt_refresh_fd_session_unlocked(fd);
    os_unfair_lock_unlock(&gStateLock);
    return session;
}

static NSString *gt_conn_id_for_fd_unlocked(int fd) {
    NSMutableDictionary *session = gt_refresh_fd_session_unlocked(fd);
    NSString *connID = session[@"conn_id"];
    if (connID.length > 0) {
        return connID;
    }
    return [NSString stringWithFormat:@"pending_fd:%d", fd];
}

static void gt_mark_fd_closed(int fd) {
    os_unfair_lock_lock(&gStateLock);
    [gSessionMap removeObjectForKey:[NSString stringWithFormat:@"%d", fd]];

    NSArray<NSString *> *tlsKeys = [gTlsMap allKeys];
    for (NSString *key in tlsKeys) {
        if ([gTlsMap[key][@"fd"] intValue] == fd) {
            [gTlsMap removeObjectForKey:key];
        }
    }

    NSArray<NSString *> *boringKeys = [gBoringSSLMap allKeys];
    for (NSString *key in boringKeys) {
        if ([gBoringSSLMap[key][@"fd"] intValue] == fd) {
            [gBoringSSLMap removeObjectForKey:key];
        }
    }
    os_unfair_lock_unlock(&gStateLock);
}

static NSString *gt_conn_id_for_fd(int fd) {
    os_unfair_lock_lock(&gStateLock);
    NSString *connID = gt_conn_id_for_fd_unlocked(fd);
    os_unfair_lock_unlock(&gStateLock);
    return connID;
}

static NSString *gt_conn_id_for_tls_ctx(void *ctx) {
    NSString *key = gt_ptr_string(ctx);
    os_unfair_lock_lock(&gStateLock);
    NSString *connID = gTlsMap[key][@"tls_conn_id"];
    os_unfair_lock_unlock(&gStateLock);
    return connID.length > 0 ? connID : [NSString stringWithFormat:@"tls_ctx:%@", key];
}

static void gt_link_tls_ctx_to_fd(void *ctx, int fd) {
    NSString *fdConnID = gt_conn_id_for_fd(fd);
    os_unfair_lock_lock(&gStateLock);
    gTlsMap[gt_ptr_string(ctx)] = [@{
        @"fd": @(fd),
        @"fd_conn_id": fdConnID,
        @"tls_conn_id": [NSString stringWithFormat:@"tls_ctx:%@", gt_ptr_string(ctx)],
        @"ts": @(gt_now_ms())
    } mutableCopy];
    os_unfair_lock_unlock(&gStateLock);
}

static void gt_link_boringssl_to_fd(void *ssl, int fd) {
    NSString *key = gt_ptr_string(ssl);
    os_unfair_lock_lock(&gStateLock);
    NSMutableDictionary *meta = gBoringSSLMap[key] ?: [NSMutableDictionary dictionary];
    meta[@"fd"] = @(fd);
    meta[@"fd_conn_id"] = gt_conn_id_for_fd_unlocked(fd);
    meta[@"tls_conn_id"] = [NSString stringWithFormat:@"boringssl_ssl:%@", key];
    meta[@"ts"] = @(gt_now_ms());
    gBoringSSLMap[key] = meta;
    os_unfair_lock_unlock(&gStateLock);
}

static void gt_link_boringssl_to_bio(void *ssl, void *bio) {
    NSString *sslKey = gt_ptr_string(ssl);
    NSString *bioKey = gt_ptr_string(bio);
    os_unfair_lock_lock(&gStateLock);
    NSMutableDictionary *meta = gBoringSSLMap[sslKey] ?: [NSMutableDictionary dictionary];
    meta[@"bio"] = bioKey;
    meta[@"ts"] = @(gt_now_ms());
    if (!meta[@"tls_conn_id"]) {
        meta[@"tls_conn_id"] = [NSString stringWithFormat:@"boringssl_bio:%@", bioKey];
    }
    NSDictionary *bioMeta = gBioMap[bioKey];
    NSNumber *fd = bioMeta[@"fd"];
    if (fd.intValue > 2) {
        meta[@"fd"] = fd;
        meta[@"fd_conn_id"] = gt_conn_id_for_fd_unlocked(fd.intValue);
    }
    gBoringSSLMap[sslKey] = meta;
    os_unfair_lock_unlock(&gStateLock);
}

static void gt_link_bio_to_fd(void *bio, int fd) {
    NSString *bioKey = gt_ptr_string(bio);
    os_unfair_lock_lock(&gStateLock);
    NSMutableDictionary *bioMeta = gBioMap[bioKey] ?: [NSMutableDictionary dictionary];
    bioMeta[@"bio_ptr"] = bioKey;
    bioMeta[@"fd"] = @(fd);
    bioMeta[@"fd_conn_id"] = gt_conn_id_for_fd_unlocked(fd);
    gBioMap[bioKey] = bioMeta;

    NSArray<NSString *> *sslKeys = [gBoringSSLMap allKeys];
    for (NSString *sslKey in sslKeys) {
        NSMutableDictionary *meta = gBoringSSLMap[sslKey];
        if ([meta[@"bio"] isEqualToString:bioKey]) {
            meta[@"fd"] = @(fd);
            meta[@"fd_conn_id"] = gt_conn_id_for_fd_unlocked(fd);
            if (!meta[@"tls_conn_id"]) {
                meta[@"tls_conn_id"] = [NSString stringWithFormat:@"boringssl_bio:%@", bioKey];
            }
        }
    }
    os_unfair_lock_unlock(&gStateLock);
}

static NSString *gt_conn_id_for_boringssl(void *ssl) {
    NSString *key = gt_ptr_string(ssl);
    os_unfair_lock_lock(&gStateLock);
    NSDictionary *meta = gBoringSSLMap[key];
    os_unfair_lock_unlock(&gStateLock);

    NSString *connID = meta[@"tls_conn_id"];
    if (connID.length > 0) {
        return connID;
    }
    NSNumber *fd = meta[@"fd"];
    if (fd.intValue > 2) {
        return [NSString stringWithFormat:@"boringssl_ssl:%@", key];
    }
    NSString *bio = meta[@"bio"];
    if (bio.length > 0) {
        return [NSString stringWithFormat:@"boringssl_bio:%@", bio];
    }
    return [NSString stringWithFormat:@"boringssl_ssl:%@", key];
}

static NSMutableDictionary *gt_ensure_nw_conn(void *conn) {
    NSString *key = gt_ptr_string(conn);
    os_unfair_lock_lock(&gStateLock);
    NSMutableDictionary *meta = gNwMap[key];
    if (!meta) {
        meta = [@{
            @"nw_ptr": key,
            @"ts": @(gt_now_ms()),
            @"conn_id": [NSString stringWithFormat:@"nw_conn:%@", key]
        } mutableCopy];
        gNwMap[key] = meta;
    }
    os_unfair_lock_unlock(&gStateLock);
    return meta;
}

static NSDictionary *gt_preview_from_dispatch_data(dispatch_data_t data) {
    if (!data || !orig_dispatch_data_get_size || !orig_dispatch_data_create_map) {
        return @{@"ptr": [NSValue valueWithPointer:NULL], @"len": @0};
    }

    size_t size = orig_dispatch_data_get_size(data);
    if (size == 0) {
        return @{@"ptr": [NSValue valueWithPointer:NULL], @"len": @0};
    }

    const void *mappedBuf = NULL;
    size_t mappedLen = 0;
    dispatch_data_t mapped = orig_dispatch_data_create_map(data, &mappedBuf, &mappedLen);
    (void)mapped;
    if (!mappedBuf || mappedLen == 0) {
        return @{@"ptr": [NSValue valueWithPointer:NULL], @"len": @0};
    }
    return @{@"ptr": [NSValue valueWithPointer:mappedBuf], @"len": @(mappedLen)};
}

static NSDictionary *gt_preview_from_msghdr(const struct msghdr *msg, ssize_t totalHint) {
    if (!msg || !msg->msg_iov || msg->msg_iovlen <= 0) {
        return @{@"ptr": [NSValue valueWithPointer:NULL], @"len": @0, @"iovcnt": @0};
    }

    const struct iovec *iov = msg->msg_iov;
    const void *base = iov[0].iov_base;
    size_t len = iov[0].iov_len;
    if (totalHint > 0 && (size_t)totalHint < len) {
        len = (size_t)totalHint;
    }
    return @{
        @"ptr": [NSValue valueWithPointer:base],
        @"len": @(len),
        @"iovcnt": @(msg->msg_iovlen)
    };
}

static void gt_init_dispatch_data_helpers(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        void *handle = dlopen("/usr/lib/system/libdispatch.dylib", RTLD_NOW);
        if (!handle) {
            handle = RTLD_DEFAULT;
        }
        orig_dispatch_data_get_size = (size_t (*)(dispatch_data_t))dlsym(handle, "dispatch_data_get_size");
        orig_dispatch_data_create_map = (dispatch_data_t (*)(dispatch_data_t, const void **, size_t *))dlsym(handle, "dispatch_data_create_map");
    });
}

static void gt_init_log_fd(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gt_init_process_identity();
        NSString *dir = kGTCatcherLogDir;
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        int fd = open([gProcessLogPath fileSystemRepresentation], O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            gLogFd = fd;
        }
    });
}

static void gt_raw_write_line(const void *text, size_t len) {
    if (!text || len == 0) {
        return;
    }

    if (gLogFd >= 0) {
        (void)orig_write(gLogFd, text, len);
        (void)orig_write(gLogFd, "\n", 1);
    }
}

static void gt_update_session_bytes(int fd, BOOL incoming, size_t amount) {
    os_unfair_lock_lock(&gStateLock);
    NSMutableDictionary *session = gt_ensure_fd_session_unlocked(fd);
    NSString *key = incoming ? @"bytes_in" : @"bytes_out";
    uint64_t value = [session[key] unsignedLongLongValue];
    session[key] = @(value + amount);
    os_unfair_lock_unlock(&gStateLock);
}

static void gt_emit_log(NSString *layer, NSString *event, NSString *connID, const void *data, size_t len, BOOL includeStack, NSDictionary *extra) {
    if (gInEmitLog) {
        return;
    }

    NSDictionary *preview = gEnablePayloadPreview
        ? gt_generate_preview(data, len, 32)
        : @{@"hex": @"", @"ascii": @""};

    NSMutableDictionary *payload = [@{
        @"ts": @((double)gt_now_ms() / 1000.0),
        @"pid": @(getpid()),
        @"tid": @(gt_tid()),
        @"bundle_id": gProcessBundleID ?: @"",
        @"process_name": gProcessName ?: @"",
        @"layer": layer ?: @"",
        @"event": event ?: @"",
        @"conn_id": connID ?: @"",
        @"len": @(len),
        @"preview_hex": preview[@"hex"] ?: @"",
        @"preview_ascii": preview[@"ascii"] ?: @""
    } mutableCopy];

    if (extra.count > 0) {
        [payload addEntriesFromDictionary:extra];
    }
    NSNumber *fdNumber = payload[@"fd"];
    if (fdNumber && [fdNumber isKindOfClass:[NSNumber class]]) {
        [payload addEntriesFromDictionary:GTSessionSnapshotForFD(gSessionMap, &gStateLock, fdNumber.intValue)];
    }
    if ([layer isEqualToString:@"tls"]) {
        [payload addEntriesFromDictionary:GTTLSAugmentPayload(payload, gTlsMap, gBoringSSLMap, gSessionMap, &gStateLock)];
    }
    if (!payload[@"flow_id"] && payload[@"conn_id"]) {
        payload[@"flow_id"] = payload[@"conn_id"];
    }
    if (includeStack && gEnableStacks) {
        NSDictionary *stack = gt_extract_stack();
        payload[@"stack_hash"] = stack[@"hash"] ?: @"";
        payload[@"frames"] = stack[@"frames"] ?: @[];
    }

    dispatch_async(gLogQueue, ^{
        gInEmitLog = YES;
        NSError *error = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&error];
        if (!json) {
            NSString *errLine = [NSString stringWithFormat:@"[GTCatcher][encode_error] %@", error];
            NSData *errData = [errLine dataUsingEncoding:NSUTF8StringEncoding];
            gt_raw_write_line(errData.bytes, errData.length);
            gInEmitLog = NO;
            return;
        }

        NSString *line = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
        NSString *prefixed = [NSString stringWithFormat:@"[GTCatcher] %@", line];
        NSData *lineData = [prefixed dataUsingEncoding:NSUTF8StringEncoding];
        gt_raw_write_line(lineData.bytes, lineData.length);
        gInEmitLog = NO;
    });
}

static int hook_close(int fd) {
    gt_mark_fd_closed(fd);
    return orig_close(fd);
}

static int hook_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    int rc = orig_connect(fd, addr, len);
    if (fd > 2) {
        gt_refresh_fd_session(fd);
    }
    return rc;
}

static ssize_t hook_send_fish(int fd, const void *buf, size_t len, int flags) {
    if (gInEmitLog) {
        return orig_send(fd, buf, len, flags);
    }
    if (gt_is_network_like_fd(fd) && len > 0) {
        gt_update_session_bytes(fd, NO, len);
        gt_emit_log(@"bsd", @"send", gt_conn_id_for_fd(fd), buf, len, NO, @{@"fd": @(fd), @"flags": @(flags)});
    }
    return orig_send(fd, buf, len, flags);
}

static ssize_t hook_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen) {
    if (gInEmitLog) {
        return orig_sendto(fd, buf, len, flags, addr, addrlen);
    }
    if (gt_is_network_like_fd(fd) && len > 0) {
        gt_update_session_bytes(fd, NO, len);
        NSMutableDictionary *extra = [@{@"fd": @(fd), @"flags": @(flags)} mutableCopy];
        if (gEnablePeerMetadata) {
            NSString *peer = gt_parse_sockaddr(addr);
            if (peer) {
                extra[@"sendto_peer"] = peer;
            }
        }
        gt_emit_log(@"bsd", @"sendto", gt_conn_id_for_fd(fd), buf, len, YES, extra);
    }
    return orig_sendto(fd, buf, len, flags, addr, addrlen);
}

static ssize_t hook_sendto_fish(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen) {
    return hook_sendto(fd, buf, len, flags, addr, addrlen);
}

static ssize_t hook_write(int fd, const void *buf, size_t len) {
    if (gInEmitLog) {
        return orig_write(fd, buf, len);
    }
    if (gt_is_network_like_fd(fd) && len > 0) {
        gt_update_session_bytes(fd, NO, len);
        gt_emit_log(@"bsd", @"write", gt_conn_id_for_fd(fd), buf, len, YES, @{@"fd": @(fd)});
    }
    return orig_write(fd, buf, len);
}

static ssize_t hook_writev(int fd, const struct iovec *iov, int iovcnt) {
    if (gInEmitLog) {
        return orig_writev(fd, iov, iovcnt);
    }
    if (gt_is_network_like_fd(fd) && iov && iovcnt > 0 && iov[0].iov_base && iov[0].iov_len > 0) {
        gt_update_session_bytes(fd, NO, iov[0].iov_len);
        gt_emit_log(@"bsd", @"writev", gt_conn_id_for_fd(fd), iov[0].iov_base, iov[0].iov_len, YES, @{@"fd": @(fd), @"iovcnt": @(iovcnt)});
    }
    return orig_writev(fd, iov, iovcnt);
}

static ssize_t hook_recv_fish(int fd, void *buf, size_t len, int flags) {
    ssize_t rc = orig_recv(fd, buf, len, flags);
    if (gInEmitLog) {
        return rc;
    }
    if (gt_is_network_like_fd(fd) && rc > 0) {
        gt_update_session_bytes(fd, YES, (size_t)rc);
        gt_emit_log(@"bsd", @"recv", gt_conn_id_for_fd(fd), buf, (size_t)rc, NO, @{@"fd": @(fd), @"flags": @(flags)});
    }
    return rc;
}

static ssize_t hook_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *addrlen) {
    ssize_t rc = orig_recvfrom(fd, buf, len, flags, addr, addrlen);
    if (gInEmitLog) {
        return rc;
    }
    if (gt_is_network_like_fd(fd) && rc > 0) {
        gt_update_session_bytes(fd, YES, (size_t)rc);
        NSMutableDictionary *extra = [@{@"fd": @(fd), @"flags": @(flags)} mutableCopy];
        if (gEnablePeerMetadata) {
            NSString *peer = gt_parse_sockaddr(addr);
            if (peer) {
                extra[@"recvfrom_peer"] = peer;
            }
        }
        gt_emit_log(@"bsd", @"recvfrom", gt_conn_id_for_fd(fd), buf, (size_t)rc, NO, extra);
    }
    return rc;
}

static ssize_t hook_recvfrom_fish(int fd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *addrlen) {
    return hook_recvfrom(fd, buf, len, flags, addr, addrlen);
}

static ssize_t hook_read(int fd, void *buf, size_t len) {
    ssize_t rc = orig_read(fd, buf, len);
    if (gInEmitLog) {
        return rc;
    }
    if (gt_is_network_like_fd(fd) && rc > 0) {
        gt_update_session_bytes(fd, YES, (size_t)rc);
        gt_emit_log(@"bsd", @"read", gt_conn_id_for_fd(fd), buf, (size_t)rc, NO, @{@"fd": @(fd)});
    }
    return rc;
}

static ssize_t hook_readv(int fd, const struct iovec *iov, int iovcnt) {
    ssize_t rc = orig_readv(fd, iov, iovcnt);
    if (gInEmitLog) {
        return rc;
    }
    if (gt_is_network_like_fd(fd) && rc > 0 && iov && iovcnt > 0 && iov[0].iov_base && iov[0].iov_len > 0) {
        size_t previewLen = MIN((size_t)rc, iov[0].iov_len);
        gt_update_session_bytes(fd, YES, (size_t)rc);
        gt_emit_log(@"bsd", @"readv", gt_conn_id_for_fd(fd), iov[0].iov_base, previewLen, NO, @{@"fd": @(fd), @"iovcnt": @(iovcnt), @"total_len": @(rc)});
    }
    return rc;
}

static ssize_t hook_sendmsg(int fd, const struct msghdr *msg, int flags) {
    if (gInEmitLog) {
        return orig_sendmsg(fd, msg, flags);
    }
    if (gt_is_network_like_fd(fd) && msg) {
        NSDictionary *preview = gt_preview_from_msghdr(msg, 0);
        const void *ptr = [preview[@"ptr"] pointerValue];
        size_t len = [preview[@"len"] unsignedLongLongValue];
        if (ptr && len > 0) {
            gt_update_session_bytes(fd, NO, len);
            gt_emit_log(@"bsd", @"sendmsg", gt_conn_id_for_fd(fd), ptr, len, YES, @{@"fd": @(fd), @"iovcnt": preview[@"iovcnt"] ?: @0, @"flags": @(flags)});
        }
    }
    return orig_sendmsg(fd, msg, flags);
}

static ssize_t hook_recvmsg(int fd, struct msghdr *msg, int flags) {
    ssize_t rc = orig_recvmsg(fd, msg, flags);
    if (gInEmitLog) {
        return rc;
    }
    if (gt_is_network_like_fd(fd) && rc > 0 && msg) {
        NSDictionary *preview = gt_preview_from_msghdr(msg, rc);
        const void *ptr = [preview[@"ptr"] pointerValue];
        size_t len = [preview[@"len"] unsignedLongLongValue];
        if (ptr && len > 0) {
            gt_update_session_bytes(fd, YES, (size_t)rc);
            gt_emit_log(@"bsd", @"recvmsg", gt_conn_id_for_fd(fd), ptr, len, NO, @{@"fd": @(fd), @"iovcnt": preview[@"iovcnt"] ?: @0, @"flags": @(flags), @"total_len": @(rc)});
        }
    }
    return rc;
}

static OSStatus hook_SSLSetConnection(SSLContextRef ctx, SSLConnectionRef connection) {
    intptr_t value = (intptr_t)connection;
    if (value > 2 && value < 0x100000) {
        gt_link_tls_ctx_to_fd(ctx, (int)value);
    } else {
        os_unfair_lock_lock(&gStateLock);
        gTlsMap[gt_ptr_string(ctx)] = [@{
            @"fd": [NSNull null],
            @"tls_conn_id": [NSString stringWithFormat:@"tls_conn:%@", gt_ptr_string(connection)],
            @"ts": @(gt_now_ms())
        } mutableCopy];
        os_unfair_lock_unlock(&gStateLock);
    }
    return orig_SSLSetConnection(ctx, connection);
}

static OSStatus hook_SSLWrite(SSLContextRef ctx, const void *data, size_t len, size_t *processed) {
    if (len > 0) {
        gt_emit_log(@"tls", @"SSLWrite", gt_conn_id_for_tls_ctx(ctx), data, len, YES, @{@"ssl_ctx": gt_ptr_string(ctx)});
    }
    return orig_SSLWrite(ctx, data, len, processed);
}

static OSStatus hook_SSLRead(SSLContextRef ctx, void *data, size_t len, size_t *processed) {
    OSStatus status = orig_SSLRead(ctx, data, len, processed);
    size_t actual = processed ? *processed : 0;
    if (actual > 0) {
        gt_emit_log(@"tls", @"SSLRead", gt_conn_id_for_tls_ctx(ctx), data, actual, NO, @{@"ssl_ctx": gt_ptr_string(ctx)});
    }
    return status;
}

static int hook_SSL_set_fd_boring(void *ssl, int fd) {
    if (fd > 2) {
        gt_link_boringssl_to_fd(ssl, fd);
    }
    return orig_SSL_set_fd_boring(ssl, fd);
}

static void hook_SSL_set_bio_boring(void *ssl, void *rbio, void *wbio) {
    os_unfair_lock_lock(&gStateLock);
    if (rbio) {
        gBioMap[gt_ptr_string(rbio)] = [@{@"bio_ptr": gt_ptr_string(rbio)} mutableCopy];
    }
    if (wbio) {
        gBioMap[gt_ptr_string(wbio)] = [@{@"bio_ptr": gt_ptr_string(wbio)} mutableCopy];
    }
    os_unfair_lock_unlock(&gStateLock);

    if (rbio) {
        gt_link_boringssl_to_bio(ssl, rbio);
    }
    if (wbio) {
        gt_link_boringssl_to_bio(ssl, wbio);
    }
    orig_SSL_set_bio_boring(ssl, rbio, wbio);
}

static int hook_BIO_set_fd_boring(void *bio, int fd, int flags) {
    if (fd > 2) {
        gt_link_bio_to_fd(bio, fd);
    }
    return orig_BIO_set_fd_boring(bio, fd, flags);
}

static int hook_SSL_write_boring(void *ssl, const void *buf, int len) {
    if (len > 0) {
        gt_emit_log(@"tls", @"SSL_write", gt_conn_id_for_boringssl(ssl), buf, (size_t)len, YES, @{@"ssl_ctx": gt_ptr_string(ssl), @"tls_impl": @"BoringSSL"});
    }
    return orig_SSL_write_boring(ssl, buf, len);
}

static int hook_SSL_read_boring(void *ssl, void *buf, int len) {
    int rc = orig_SSL_read_boring(ssl, buf, len);
    if (rc > 0) {
        gt_emit_log(@"tls", @"SSL_read", gt_conn_id_for_boringssl(ssl), buf, (size_t)rc, NO, @{@"ssl_ctx": gt_ptr_string(ssl), @"tls_impl": @"BoringSSL"});
    }
    return rc;
}

static void hook_nw_connection_start(void *conn) {
    gt_ensure_nw_conn(conn);
    orig_nw_connection_start(conn);
}

static void hook_nw_connection_send(void *conn, void *content, void *contextObj, BOOL32 isComplete, void *completion) {
    NSDictionary *meta = gt_ensure_nw_conn(conn);
    NSDictionary *preview = gt_preview_from_dispatch_data((__bridge dispatch_data_t)content);
    const void *ptr = [preview[@"ptr"] pointerValue];
    size_t len = [preview[@"len"] unsignedLongLongValue];
    gt_emit_log(@"network", @"nw_connection_send", meta[@"conn_id"], ptr, len, YES, @{
        @"nw_ptr": gt_ptr_string(conn),
        @"has_content": @((content != NULL)),
        @"is_complete": @(isComplete),
        @"content_context": gt_ptr_string(contextObj),
        @"completion": gt_ptr_string(completion)
    });
    orig_nw_connection_send(conn, content, contextObj, isComplete, completion);
}

static void hook_nw_connection_receive(void *conn, uint32_t minLen, uint32_t maxLen, void *completion) {
    NSDictionary *meta = gt_ensure_nw_conn(conn);
    gt_emit_log(@"network", @"nw_connection_receive", meta[@"conn_id"], NULL, 0, YES, @{
        @"nw_ptr": gt_ptr_string(conn),
        @"min_incomplete_length": @(minLen),
        @"max_length": @(maxLen),
        @"completion": gt_ptr_string(completion)
    });
    orig_nw_connection_receive(conn, minLen, maxLen, completion);
}

static void hook_nw_connection_receive_message(void *conn, void *completion) {
    NSDictionary *meta = gt_ensure_nw_conn(conn);
    gt_emit_log(@"network", @"nw_connection_receive_message", meta[@"conn_id"], NULL, 0, YES, @{
        @"nw_ptr": gt_ptr_string(conn),
        @"completion": gt_ptr_string(completion)
    });
    orig_nw_connection_receive_message(conn, completion);
}

static void gt_hook_symbol(const char *image, const char *symbol, void *replacement, void **original) {
    void *handle = image ? dlopen(image, RTLD_NOW) : NULL;
    void *searchHandle = handle ?: RTLD_DEFAULT;
    void *target = dlsym(searchHandle, symbol);
    if (!target) {
        char line[512] = {0};
        snprintf(line, sizeof(line), "[GTCatcher] export not found: %s!%s", image ?: "null", symbol);
        gt_raw_write_line(line, strlen(line));
        if (handle) {
            dlclose(handle);
        }
        return;
    }
    if (replacement) {
        MSHookFunction(target, replacement, original);
    } else if (original) {
        *original = target;
    }
    if (handle) {
        dlclose(handle);
    }
}

static void gt_install_fishhook(void) {
    struct rebinding rebindings[4];
    size_t count = 0;

    if (gEnableSendHooks) {
        rebindings[count++] = (struct rebinding){"send", (void *)hook_send_fish, (void **)&orig_send};
    }
    if (gEnableRecvHooks) {
        rebindings[count++] = (struct rebinding){"recv", (void *)hook_recv_fish, (void **)&orig_recv};
    }
    if (gEnableSendtoHooks) {
        rebindings[count++] = (struct rebinding){"sendto", (void *)hook_sendto_fish, (void **)&orig_sendto};
    }
    if (gEnableRecvfromHooks) {
        rebindings[count++] = (struct rebinding){"recvfrom", (void *)hook_recvfrom_fish, (void **)&orig_recvfrom};
    }

    if (count > 0) {
        rebind_symbols(rebindings, count);
    }
}

%ctor {
    @autoreleasepool {
        gSessionMap = [NSMutableDictionary dictionary];
        gTlsMap = [NSMutableDictionary dictionary];
        gBioMap = [NSMutableDictionary dictionary];
        gBoringSSLMap = [NSMutableDictionary dictionary];
        gNwMap = [NSMutableDictionary dictionary];
        gLogQueue = dispatch_queue_create("com.iie.gtcatcher.log", DISPATCH_QUEUE_SERIAL);
        gt_init_dispatch_data_helpers();
        gt_init_log_fd();

        gt_hook_symbol(NULL, "close", NULL, (void **)&orig_close);
        gt_hook_symbol(NULL, "connect", NULL, (void **)&orig_connect);
        gt_hook_symbol(NULL, "send", NULL, (void **)&orig_send);
        gt_hook_symbol(NULL, "sendto", NULL, (void **)&orig_sendto);
        gt_hook_symbol(NULL, "recv", NULL, (void **)&orig_recv);
        gt_hook_symbol(NULL, "recvfrom", NULL, (void **)&orig_recvfrom);
        gt_hook_symbol(NULL, "write", NULL, (void **)&orig_write);
        gt_hook_symbol(NULL, "writev", NULL, (void **)&orig_writev);
        gt_hook_symbol(NULL, "read", NULL, (void **)&orig_read);
        gt_hook_symbol(NULL, "readv", NULL, (void **)&orig_readv);
        gt_hook_symbol(NULL, "sendmsg", NULL, (void **)&orig_sendmsg);
        gt_hook_symbol(NULL, "recvmsg", NULL, (void **)&orig_recvmsg);

        if (gEnableConnectHooks) {
            gt_hook_symbol(NULL, "close", (void *)hook_close, (void **)&orig_close);
            gt_hook_symbol(NULL, "connect", (void *)hook_connect, (void **)&orig_connect);
        }

        if (gEnableSendHooks || gEnableRecvHooks || gEnableSendtoHooks || gEnableRecvfromHooks) {
            gt_install_fishhook();
        }

        if (gEnableWideBsdHooks) {
            gt_hook_symbol(NULL, "write", (void *)hook_write, (void **)&orig_write);
            gt_hook_symbol(NULL, "writev", (void *)hook_writev, (void **)&orig_writev);
            gt_hook_symbol(NULL, "read", (void *)hook_read, (void **)&orig_read);
            gt_hook_symbol(NULL, "readv", (void *)hook_readv, (void **)&orig_readv);
            gt_hook_symbol(NULL, "sendmsg", (void *)hook_sendmsg, (void **)&orig_sendmsg);
            gt_hook_symbol(NULL, "recvmsg", (void *)hook_recvmsg, (void **)&orig_recvmsg);
        }

        if (gEnableTlsHooks) {
            gt_hook_symbol("/System/Library/Frameworks/Security.framework/Security", "SSLWrite", (void *)hook_SSLWrite, (void **)&orig_SSLWrite);
            gt_hook_symbol("/System/Library/Frameworks/Security.framework/Security", "SSLRead", (void *)hook_SSLRead, (void **)&orig_SSLRead);
            gt_hook_symbol("/System/Library/Frameworks/Security.framework/Security", "SSLSetConnection", (void *)hook_SSLSetConnection, (void **)&orig_SSLSetConnection);

            gt_hook_symbol(NULL, "SSL_write", (void *)hook_SSL_write_boring, (void **)&orig_SSL_write_boring);
            gt_hook_symbol(NULL, "SSL_read", (void *)hook_SSL_read_boring, (void **)&orig_SSL_read_boring);
            gt_hook_symbol(NULL, "SSL_set_fd", (void *)hook_SSL_set_fd_boring, (void **)&orig_SSL_set_fd_boring);
            gt_hook_symbol(NULL, "SSL_set_bio", (void *)hook_SSL_set_bio_boring, (void **)&orig_SSL_set_bio_boring);
            gt_hook_symbol(NULL, "BIO_set_fd", (void *)hook_BIO_set_fd_boring, (void **)&orig_BIO_set_fd_boring);
        }

        if (gEnableNwHooks) {
            gt_hook_symbol("/System/Library/Frameworks/Network.framework/Network", "nw_connection_send", (void *)hook_nw_connection_send, (void **)&orig_nw_connection_send);
            gt_hook_symbol("/System/Library/Frameworks/Network.framework/Network", "nw_connection_receive", (void *)hook_nw_connection_receive, (void **)&orig_nw_connection_receive);
            gt_hook_symbol("/System/Library/Frameworks/Network.framework/Network", "nw_connection_receive_message", (void *)hook_nw_connection_receive_message, (void **)&orig_nw_connection_receive_message);
            gt_hook_symbol("/System/Library/Frameworks/Network.framework/Network", "nw_connection_start", (void *)hook_nw_connection_start, (void **)&orig_nw_connection_start);
        }

    }
}
