#import <Foundation/Foundation.h>
#include <os/lock.h>

#ifdef __cplusplus
extern "C" {
#endif

NSDictionary *GTSessionSnapshotForFD(NSMutableDictionary *sessionMap, os_unfair_lock *lock, int fd);
NSDictionary *GTTLSAugmentPayload(NSMutableDictionary *payload,
                                  NSMutableDictionary *tlsMap,
                                  NSMutableDictionary *boringSSLMap,
                                  NSMutableDictionary *sessionMap,
                                  os_unfair_lock *lock);

#ifdef __cplusplus
}
#endif
