#import "GTExtraContext.h"

static NSMutableDictionary *GTMutableSessionSnapshot(NSMutableDictionary *session) {
    NSMutableDictionary *snapshot = [NSMutableDictionary dictionary];
    NSNumber *fdNumber = session[@"fd"];
    if (fdNumber) {
        snapshot[@"fd"] = fdNumber;
    }
    if (session[@"state"]) {
        snapshot[@"fd_state"] = session[@"state"];
    }
    if (session[@"local"]) {
        snapshot[@"local"] = session[@"local"];
    }
    if (session[@"peer"]) {
        snapshot[@"peer"] = session[@"peer"];
    }
    if (session[@"bytes_in"]) {
        snapshot[@"bytes_in"] = session[@"bytes_in"];
    }
    if (session[@"bytes_out"]) {
        snapshot[@"bytes_out"] = session[@"bytes_out"];
    }
    if (session[@"create_ts"]) {
        snapshot[@"fd_create_ts"] = session[@"create_ts"];
    }
    if (session[@"conn_id"]) {
        snapshot[@"fd_conn_id"] = session[@"conn_id"];
        snapshot[@"flow_id"] = session[@"conn_id"];
    }
    return snapshot;
}

NSDictionary *GTSessionSnapshotForFD(NSMutableDictionary *sessionMap, os_unfair_lock *lock, int fd) {
    os_unfair_lock_lock(lock);
    NSMutableDictionary *session = sessionMap[[NSString stringWithFormat:@"%d", fd]];
    NSDictionary *snapshot = session ? [GTMutableSessionSnapshot(session) copy] : @{};
    os_unfair_lock_unlock(lock);
    return snapshot;
}

NSDictionary *GTTLSAugmentPayload(NSMutableDictionary *payload,
                                  NSMutableDictionary *tlsMap,
                                  NSMutableDictionary *boringSSLMap,
                                  NSMutableDictionary *sessionMap,
                                  os_unfair_lock *lock) {
    NSMutableDictionary *extra = [NSMutableDictionary dictionary];

    os_unfair_lock_lock(lock);
    NSString *sslCtx = payload[@"ssl_ctx"];
    NSDictionary *tlsMeta = sslCtx ? (tlsMap[sslCtx] ?: boringSSLMap[sslCtx]) : nil;
    if (!tlsMeta && sslCtx) {
        NSString *normalized = nil;
        if ([sslCtx hasPrefix:@"boringssl_ssl:"]) {
            normalized = [sslCtx substringFromIndex:[@"boringssl_ssl:" length]];
        } else if ([sslCtx hasPrefix:@"boringssl_bio:"]) {
            normalized = [sslCtx substringFromIndex:[@"boringssl_bio:" length]];
        } else if ([sslCtx hasPrefix:@"tls_ctx:"]) {
            normalized = [sslCtx substringFromIndex:[@"tls_ctx:" length]];
        } else {
            normalized = sslCtx;
        }
        if (normalized) {
            tlsMeta = tlsMap[normalized] ?: boringSSLMap[normalized];
        }
    }

    NSNumber *fd = tlsMeta[@"fd"];
    NSString *fdConnID = tlsMeta[@"fd_conn_id"];
    NSString *tlsConnID = tlsMeta[@"tls_conn_id"];
    if (fd) {
        extra[@"fd"] = fd;
    }
    if (tlsConnID.length > 0) {
        extra[@"tls_conn_id"] = tlsConnID;
    }
    if (fdConnID.length > 0) {
        extra[@"fd_conn_id"] = fdConnID;
        extra[@"flow_id"] = fdConnID;
    }

    if (fd.intValue > 2) {
        NSMutableDictionary *session = sessionMap[[NSString stringWithFormat:@"%d", fd.intValue]];
        if (session) {
            [extra addEntriesFromDictionary:GTMutableSessionSnapshot(session)];
        }
    }
    os_unfair_lock_unlock(lock);

    return extra;
}
