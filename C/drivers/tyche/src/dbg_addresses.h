#ifndef __DBG_ADDRESSES_H__
#define __DBG_ADDRESSES_H__

#include "tyche_capabilities_types.h"

// ————————————————————— Information Passed via Walker —————————————————————— //

struct walker_info_t {
  usize virt_addr;
  usize phys_addr;
  usize size;
  int success;
};

int init_page_walker(void);
int walk_and_collect_region(usize virt, usize size, usize* phys);

#endif
