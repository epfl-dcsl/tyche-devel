#ifndef __LOADER2_PTS_H__
#define __LOADER2_PTS_H__

#include "pts_api.h"
#include <stdint.h>

/// Default name for the environment variable setting up the nb pages for bump.
#define NB_PAGES_ENVVAR "NB_PAGES"

#define PAGE_SIZE ((uint64_t)(0x1000))

/// These are default values, use the variable defined at the top of pts.c
/// which reflect variables set through the environment.
#define DEFAULT_NB_PAGES ((uint64_t)100)

#define DEFAULT_BUMP_SIZE (DEFAULT_NB_PAGES * PAGE_SIZE)

typedef struct __attribute__((__packed__)) __attribute__((aligned(4096))) {
  uint64_t data[512];
} page_t;

/// The page tables rely on a bump allocator.
/// The allocator itself is just a large region that we mmap.
/// The layout in physical memory is expected to be as follows:
/// |--------- segment 1 ---------]
/// |--------- segment 2 ---------]
///            .........
/// |---------  pages[0] ---------] <- phys_offset
/// |---------  pages[1] ---------]
///            .........
typedef struct {
  /// Index of the next free page.
  int idx;

  /// Buffer of pages;
  page_t* pages;

  /// Physical memory offset for the allocator.
  uint64_t phys_offset;

} page_tables_t;

/// Extra information we carry in the mapper.
typedef struct {
  /// A reference to the bump allocator.
  page_tables_t* bump;
  /// Intermediary flags used when mapping pages.
  uint64_t intermed_flags;
  /// More information.
  void* extras;
} info_t;

addr_t align_up(addr_t addr);

#endif /*__LOADER2_PTS_H__*/
