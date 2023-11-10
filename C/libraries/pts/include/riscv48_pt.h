#ifndef __INCLUDE_RISCV48_PT_H__
#define __INCLUDE_RISCV48_PT_H__

#include "pts_api.h"

#define RISCV64_SV39
//#define RISCV64_SV48

#define RISCV39_LEVELS 3
#define RISCV48_LEVELS 4

// ——————————————————————————— Page Configuration ——————————————————————————— //

#ifdef RISCV64_SV39
#define PT_VIRT_WIDTH 39ULL
#endif

#ifdef RISCV64_SV48
#define PT_VIRT_WIDTH 48ULL
#endif

#define PT_PHYS_WIDTH 44ULL

/// Valid virtual addresses are 48 bits, valid physical ones 56.
#define PT_VIRT_MASK ((1ULL << PT_VIRT_WIDTH) - 1ULL)
#define PT_PHYS_MASK ((1ULL << PT_PHYS_WIDTH) - 1ULL)

/// Define the 4-level page tables.
#define LVL0 0
#define LVL1 1
#define LVL2 2
#define LVL3 3

/// The smallest granule of memory is a page.
#define PT_PAGE_WIDTH 12ULL
#define PT_PAGE_SIZE (1ULL << PT_PAGE_WIDTH)
#define PT_PAGE_ALIGN (PT_PAGE_SIZE - 1ULL)

/// RISCV48 has 512 entries per level table, i.e., 9 bits (511) to index.
#define PT_NB_ENTRIES 512ULL
#define PT_VPN_MASK 511ULL
#define PT_VPN_BIT_WIDTH 9ULL

/// RISCV shifts for page table level masks.
#define PT_LVL0_SHIFT 12ULL
#define PT_LVL1_SHIFT (PT_LVL0_SHIFT + PT_VPN_BIT_WIDTH)
#define PT_LVL2_SHIFT (PT_LVL1_SHIFT + PT_VPN_BIT_WIDTH)
#define PT_LVL3_SHIFT (PT_LVL2_SHIFT + PT_VPN_BIT_WIDTH)

/// A mask is nine 1's shifted to the left by the level's shift.
#define PT_LVL0_PAGE_MASK (PT_VPN_MASK << PT_LVL0_SHIFT)
#define PT_LVL1_PAGE_MASK (PT_VPN_MASK << PT_LVL1_SHIFT)
#define PT_LVL2_PAGE_MASK (PT_VPN_MASK << PT_LVL2_SHIFT)
#define PT_LVL3_PAGE_MASK (PT_VPN_MASK << PT_LVL3_SHIFT)

/// Page table masks
#define PT_FLAGS_RESERVED 10ULL
#define PT_VIRT_PAGE_MASK (PT_VIRT_MASK - PT_PAGE_ALIGN)
#define PT_PHYS_PAGE_MASK (PT_PHYS_MASK << (PT_FLAGS_RESERVED))

// ———————————————————— TODO Other granules? Giant etc. ————————————————————— //

// ———————————————————————————— PTE Flag Indices ———————————————————————————— //

#define PT_BIT_V (0ULL)
#define PT_BIT_R (1ULL)
#define PT_BIT_W (2ULL)
#define PT_BIT_X (3ULL)
#define PT_BIT_U (4ULL)
#define PT_BIT_G (5ULL)
#define PT_BIT_A (6ULL)
#define PT_BIT_D (7ULL)

#define PT_BITS_RESERVED (54ULL)

// ——————————————————————————————— PTE Flags ———————————————————————————————— //

#define PT_V (1ULL << PT_BIT_V)
#define PT_R (1ULL << PT_BIT_R)
#define PT_W (1ULL << PT_BIT_W)
#define PT_X (1ULL << PT_BIT_X)
#define PT_U (1ULL << PT_BIT_U)
#define PT_G (1ULL << PT_BIT_G)
#define PT_A (1ULL << PT_BIT_A)
#define PT_D (1ULL << PT_BIT_D)

#define PT_PAGE_PIPE (3ULL << PT_BITS_RESERVED)

// ———————————————————————————— Default profile ————————————————————————————— //
extern const pt_profile_t riscv64_sv48_profile;
// ———————————————————————————— Additional profile ————————————————————————————— //
extern const pt_profile_t riscv64_sv39_profile;

// ——————————————————————————————— Functions ———————————————————————————————— //

callback_action_t riscv_how_visit_leaves(entry_t* entry, level_t level, pt_profile_t* profile);

callback_action_t riscv_how_visit_present(entry_t* entry, level_t level, pt_profile_t* profile);

callback_action_t riscv_how_map(entry_t* entry, level_t level, pt_profile_t* profile);

entry_t riscv_next(entry_t entry, level_t curr_level);

#endif /*__INCLUDE_RISCV48_PT_H__*/
