#include "riscv48_pt.h"
#include "common.h"
#include "common_log.h"

/// Default profile for riscv48.
const pt_profile_t riscv64_sv48_profile = {
  .nb_levels = RISCV48_LEVELS,
  .nb_entries = PT_NB_ENTRIES,
  .masks = {PT_LVL0_PAGE_MASK, PT_LVL1_PAGE_MASK, PT_LVL2_PAGE_MASK, PT_LVL3_PAGE_MASK},
  .shifts = {PT_LVL0_SHIFT, PT_LVL1_SHIFT, PT_LVL2_SHIFT, PT_LVL3_SHIFT},
  .how = riscv_how_visit_leaves,
  .next = riscv_next,
};

const pt_profile_t riscv64_sv39_profile = {
    .nb_levels = RISCV39_LEVELS,
    .nb_entries = PT_NB_ENTRIES,
    .masks = {PT_LVL0_PAGE_MASK, PT_LVL1_PAGE_MASK, PT_LVL2_PAGE_MASK},
    .shifts = {PT_LVL0_SHIFT, PT_LVL1_SHIFT, PT_LVL2_SHIFT},
    .how = riscv_how_visit_leaves,
    .next = riscv_next,
}; 

/// Example how function that asks to visit present leaves.
callback_action_t riscv_how_visit_leaves(entry_t* entry, level_t level, pt_profile_t* profile)
{
  // Not an entry.
  if ((*entry & PT_V) != PT_V){
    return SKIP; 
  }
  // Invalid entry.
  if ((*entry & PT_R) == 0 && (*entry & PT_W) != 0) {
    return ERROR;
  }
  // Not a leaf
  if ((*entry & (PT_R | PT_W | PT_X)) == 0) {
    return WALK;
  }

  return VISIT;
}

/// Function visiting all the present nodes.
callback_action_t riscv_how_visit_present(entry_t* entry, level_t level, pt_profile_t* profile)
{
  if ((*entry & PT_V) != PT_V) {
    return SKIP; 
  }
  // Invalid entry.
  if ((*entry & PT_R) == 0 && (*entry & PT_W) != 0) {
    return ERROR;
  }
  return VISIT;
}

/// Example how function that asks to map missing entries.
callback_action_t riscv_how_map(entry_t* entry, level_t level, pt_profile_t* profile)
{
  if ((*entry & PT_V) != PT_V) {
    return MAP; 
  }
  // Invalid entry.
  if ((*entry & PT_R) == 0 && (*entry & PT_W) != 0) {
    return ERROR;
  }
  return WALK;
}

index_t riscv_get_index(addr_t addr, level_t level, pt_profile_t* profile)
{
  // Clear the address
  addr = addr & PT_VIRT_PAGE_MASK;
  return ((addr & profile->masks[level]) >> profile->shifts[level]);
}

entry_t riscv_next(entry_t entry, level_t curr_level) 
{
    return (entry >> PT_FLAGS_RESERVED) << PT_PAGE_WIDTH; 
}
