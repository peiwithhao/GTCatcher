#include "fishhook.h"

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct rebindings_entry {
    struct rebinding *rebindings;
    size_t rebindings_nel;
    struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;

static int prepend_rebindings(struct rebindings_entry **rebindings_head,
                              struct rebinding rebindings[],
                              size_t nel) {
    struct rebindings_entry *new_entry = (struct rebindings_entry *)calloc(1, sizeof(struct rebindings_entry));
    if (!new_entry) {
        return -1;
    }
    new_entry->rebindings = (struct rebinding *)calloc(nel, sizeof(struct rebinding));
    if (!new_entry->rebindings) {
        free(new_entry);
        return -1;
    }
    memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
    new_entry->rebindings_nel = nel;
    new_entry->next = *rebindings_head;
    *rebindings_head = new_entry;
    return 0;
}

static void perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                           const struct mach_header *header,
                                           intptr_t slide,
                                           struct segment_command_64 *seg_cmd,
                                           struct section_64 *sect,
                                           struct nlist_64 *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab) {
    if (!sect || !rebindings || !symtab || !strtab || !indirect_symtab) {
        return;
    }

    uint32_t *indirect_symbol_indices = indirect_symtab + sect->reserved1;
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + sect->addr);
    size_t count = sect->size / sizeof(void *);

    for (size_t i = 0; i < count; i++) {
        uint32_t symtab_index = indirect_symbol_indices[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS ||
            symtab_index == INDIRECT_SYMBOL_LOCAL ||
            (symtab_index & INDIRECT_SYMBOL_ABS) != 0) {
            continue;
        }

        char *symbol_name = strtab + symtab[symtab_index].n_un.n_strx;
        if (!symbol_name || symbol_name[0] == '\0') {
            continue;
        }

        struct rebindings_entry *cur = rebindings;
        while (cur) {
            for (size_t j = 0; j < cur->rebindings_nel; j++) {
                struct rebinding *rebinding = &cur->rebindings[j];
                if (strcmp(symbol_name + 1, rebinding->name) != 0) {
                    continue;
                }

                if (rebinding->replaced && *rebinding->replaced == NULL) {
                    *rebinding->replaced = indirect_symbol_bindings[i];
                }

                uintptr_t page = ((uintptr_t)&indirect_symbol_bindings[i]) & ~(uintptr_t)(getpagesize() - 1);
                mprotect((void *)page, (size_t)getpagesize(), PROT_READ | PROT_WRITE);
                indirect_symbol_bindings[i] = rebinding->replacement;
                break;
            }
            cur = cur->next;
        }
    }
}

static void rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide) {
    if (!header) {
        return;
    }

    const struct mach_header_64 *header64 = (const struct mach_header_64 *)header;
    uintptr_t cursor = (uintptr_t)header + sizeof(struct mach_header_64);
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;
    struct segment_command_64 *linkedit_segment = NULL;

    for (uint32_t i = 0; i < header64->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cursor;
        if (lc->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)lc;
        } else if (lc->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)lc;
        } else if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, SEG_LINKEDIT) == 0) {
                linkedit_segment = seg;
            }
        }
        cursor += lc->cmdsize;
    }

    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment) {
        return;
    }

    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    struct nlist_64 *symtab = (struct nlist_64 *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    cursor = (uintptr_t)header + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < header64->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cursor;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, SEG_DATA) == 0 || strcmp(seg->segname, "__DATA_CONST") == 0) {
                struct section_64 *sect = (struct section_64 *)((uintptr_t)seg + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if ((sect[j].flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
                        (sect[j].flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                        perform_rebinding_with_section(rebindings, header, slide, seg, &sect[j], symtab, strtab, indirect_symtab);
                    }
                }
            }
        }
        cursor += lc->cmdsize;
    }
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
    if (prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel) < 0) {
        return -1;
    }

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        rebind_symbols_for_image(_rebindings_head, _dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
    return 0;
}
