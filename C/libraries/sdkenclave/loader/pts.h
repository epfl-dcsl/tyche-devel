#ifndef __LOADER_PTS_H__
#define __LOADER_PTS_H__

#include "enclave_loader.h"

/// Default name for the environment variable setting up the nb pages for bump.
#define NB_PAGES_ENVVAR "NB_PAGES"

/// These are default values, use the variable defined at the top of pts.c
/// which reflect variables set through the environment.
#define DEFAULT_NB_PAGES ((uint64_t)100)

#define DEFAULT_BUMP_SIZE (DEFAULT_NB_PAGES * PAGE_SIZE)

/// Create the page tables for the provided ELF.
/// The physical mappings are constructed as an offset from the overall size
/// of the segments.
/// |--------- segment 1 ---------]
/// |--------- segment 2 ---------]
///            .........
/// |---------  pages[0] ---------] <- phys_offset
/// |---------  pages[1] ---------]
int create_page_tables(
    uint64_t phys_offset,
    page_tables_t* bump,
    Elf64_Ehdr* header,
    Elf64_Phdr* segments);
/// Adds offset to all the page tables entries.
int fix_page_tables(usize offset, page_tables_t* tables);

#endif /*__LOADER_PTS_H__*/
