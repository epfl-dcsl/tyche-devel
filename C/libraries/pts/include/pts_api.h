#ifndef __INCLUDE_PTS_API_H__
#define __INCLUDE_PTS_API_H__

// —————————————————————————————————— API ——————————————————————————————————— //

#define MAX_LEVEL 5

/// Cover the address with a typedef in case we need to change that.
typedef unsigned long long addr_t;

/// Cover the level with a typedef in case we need to change that.
typedef unsigned char level_t;

/// Cover the index with a typedef in case we need to change that.
typedef unsigned int index_t;

/// How we abstract an entry.
typedef addr_t entry_t;

/// Possible result for a callback.
typedef enum {
  // The invocation requires to keep walking the subtree.
  WALK = 0,
  // The invocation requires a walk of the subtree.
  VISIT = 1,
  // The invocation requires a map.
  MAP = 2,
  // The invocation wants to skip walking the subtree.
  SKIP = 3,
  // Report Error
  ERROR = 4,
} callback_action_t;

/// Forward declaration
struct pt_profile_t;

/// Callback type per entry.
/// TODO: figure out what we want in there.
typedef callback_action_t (*callback_t)(entry_t*, level_t, struct pt_profile_t*);

typedef index_t (*get_index_t)(addr_t, level_t);

/// Function type to visit the next level in the page table.
typedef entry_t (*next_level_t)(entry_t, level_t curr_lvl);

/// Allocator for new entries.
typedef entry_t* (*allocator_t)(void*);

/// Translates an addr_t (i.e., PA -> VA, VA -> PA).
typedef addr_t (*translator_t)(addr_t, struct pt_profile_t* extra);

/// A profile for a page table.
typedef struct pt_profile_t {
  // Number of levels in the page table.
  level_t nb_levels;

  // Number of entries per level.
  index_t nb_entries;

  // CallBacks for each level when entry is present.
  callback_t visitors[MAX_LEVEL];

  // Callbacks for each level when entry is absent.
  callback_t mappers[MAX_LEVEL];

  // Mask for each level.
  addr_t masks[MAX_LEVEL];

  // Shift for each level.
  addr_t shifts[MAX_LEVEL];

  // Determines whether the node should be visited by a mapper or a walker.
  callback_t how;

  // From one level entry to the lower level.
  next_level_t next;

  // Allocator to spawn new entries.
  allocator_t allocate;

  // Translate from PA to VA.
  translator_t pa_to_va;

  // Translate from VA to PA.
  translator_t va_to_pa;

  // Whatever the user wants.
  void* extras;

  // The current va set before making a call.
  // This is written by the library but never read.
  addr_t curr_va;

} pt_profile_t;

/// Goes through a range of VAs using the profile.
/// Returns -1 in case of an error, 0 if success.
int pt_walk_page_range(entry_t root, level_t level, addr_t start, addr_t end, pt_profile_t* profile);
index_t get_index(addr_t addr, level_t level, pt_profile_t* profile);

#endif
