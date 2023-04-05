#include "pts_api.h"
#include "x86_64_pt.h"
#include "common.h"
/// Default profile for x86_64.
/// @warn It is incomplete.
const pt_profile_t x86_64_profile = {
  .nb_levels = x86_64_LEVELS,
  .nb_entries = PT_NB_ENTRIES,
  .masks = {PT_PTE_PAGE_MASK, PT_PMD_PAGE_MASK, PT_PGD_PAGE_MASK, PT_PML4_PAGE_MASK},
  .shifts = {PT_PTE_SHIFT, PT_PMD_SHIFT, PT_PGD_SHIFT, PT_PML4_SHIFT},
  .how = x86_64_how_visit_leaves,
  .next = x86_64_next,
};

/// Example how function that asks to visit present leaves.
callback_action_t x86_64_how_visit_leaves(entry_t* entry, level_t level, pt_profile_t* profile)
{
  if ((*entry & PT_PP) != PT_PP) {
    return SKIP; 
  }
  // We have a Giant or Huge mapping, visit the node.
  // -> TODO there is something wrong here.
  if (level == PT_PTE || ((level == PT_PGD || level == PT_PMD) &&
      ((*entry & PT_PAGE_PSE) == PT_PAGE_PSE))) {
    return VISIT;
  }
  return WALK;
}

/// Function visiting all the present nodes.
callback_action_t x86_64_how_visit_present(entry_t* entry, level_t level, pt_profile_t* profile)
{
  if ((*entry & PT_PP) != PT_PP) {
    return SKIP; 
  }
  return VISIT;
}

/// Example how function that asks to map missing entries.
callback_action_t x86_64_how_map(entry_t* entry, level_t level, pt_profile_t* profile)
{
  if ((*entry & PT_PP) != PT_PP) {
    return MAP; 
  }
  return WALK;
}

index_t x86_64_get_index(addr_t addr, level_t level, pt_profile_t* profile)
{
  // Clear the address
  addr = addr & PT_VIRT_PAGE_MASK;
  TEST(level <= x86_64_LEVELS);
  return ((addr & profile->masks[level]) >> profile->shifts[level]);
}

entry_t x86_64_next(entry_t entry, level_t curr_level) 
{
  return (entry & PT_PHYS_PAGE_MASK);
}
