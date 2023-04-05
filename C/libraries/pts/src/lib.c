#include "pts_api.h"

#include "common.h"

/// From a VA addr and a level, get the current index.
index_t get_index(addr_t addr, level_t level, pt_profile_t* profile)
{
  return ((addr & profile->masks[level]) >> profile->shifts[level]);
}

int pt_walk_page_range(entry_t root, level_t level, addr_t start, addr_t end, pt_profile_t* profile)
{
  entry_t next = 0;
  addr_t curr_va = 0;
  index_t s = 0;
  entry_t* va_root = 0;
  index_t i = 0;
  TEST(start < end); 
  TEST(profile != 0);
  TEST(level < profile->nb_levels); 
  TEST(profile->how != 0);
  TEST(profile->pa_to_va != 0);
  next = 0;
  curr_va = start;
  s = get_index(start, level, profile);
  va_root = (entry_t*) profile->pa_to_va(root, profile);
  for (i = s; i < profile->nb_entries; i++) {
    // Compute the current virtual address.
    curr_va = (start & ~(profile->masks[level])) 
        | (((addr_t)i) << profile->shifts[level]);

    // Clear the lower bits if we are not at the start anymore.
    if (i != s) {
      curr_va = (curr_va >> profile->shifts[level]) << profile->shifts[level]; 
    }

    // If the current address is greater or equal to the end, stop.
    if (curr_va >= end) {
      break;
    }

    // Drop the address into the profile in case it is needed.
    // This avoids passing it around.
    profile->curr_va = curr_va;

    // Decide what to do first.
    // We can either MAP -> WALK -> VISIT
    switch(profile->how(&(va_root[i]), level, profile)) {
      // Skip this entry.
      case SKIP:
        continue;
        break;
      // Visit this entry.
      case VISIT:
        goto visit;
        break;
      // Map this entry.
      case MAP:
        goto map;
        break;
      // Keep walking.
      case WALK:
        goto walk;
        break;
      case ERROR:
        return -1;
      default:
        TEST(0);
        break;
    } 
map:
    // Add a mapping.
    if (profile->mappers[level] != 0) {
      switch(profile->mappers[level](&va_root[i], level, profile)) {
        // That means we should not walk.
        case WALK:
          goto walk;
          break;
        case VISIT:
          goto visit;
          break;
        case SKIP:
          continue;
          break;
        case ERROR:
          return -1;
        // Should never happen.
        case MAP:
        default:
          TEST(0);
          break;
      }
    }
visit:
    // Walk the mapping.
    if (profile->visitors[level] != 0) {
      switch(profile->visitors[level](&va_root[i], level, profile)) {
        // The only acceptable return values.
        case WALK:
          // Recursive walk to the next level.
          goto walk;
          break;
        // Skip that entry.
        case SKIP:
          continue;
          break;
        case ERROR:
          return -1;
        default:
          TEST(0);
          break;
      }
    }
walk:
    // No more to do.
    if (level == 0) {
      continue;
    } 
    // Next level page table (PA) to visit.
    next = profile->next(va_root[i], level);
    if (pt_walk_page_range(next, level-1, curr_va, end, profile) == -1) {
      TEST(0);
      return -1; 
    }
  }
  // Reset the profile curr_va
  profile->curr_va = 0;
  return 0;
}
