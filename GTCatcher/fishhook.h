#ifndef GTCATCHER_FISHHOOK_H
#define GTCATCHER_FISHHOOK_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);

#ifdef __cplusplus
}
#endif

#endif
