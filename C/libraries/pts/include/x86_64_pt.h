#ifndef __INCLUDE_X86_64_H__
#define __INCLUDE_X86_64_H__

#include "pts_api.h"

#define x86_64_LEVELS 4

// ——————————————————————————— Page Configuration ——————————————————————————— //
/* PT_PAGE_SHIFT determines the page size */

/// Hardware sizes define virtual addresses as being (last index is 47),
/// and physical address spaces as 52.
#define PT_VIRT_WIDTH 48ULL
#define PT_PHYS_WIDTH 52ULL

/// Valid virtual addresses are 48 bits, valid physical ones 52.
#define PT_VIRT_MASK ((1ULL << PT_VIRT_WIDTH) - 1ULL)
#define PT_PHYS_MASK ((1ULL << PT_PHYS_WIDTH) - 1ULL)

/// The smallest granule of memory is a page.
#define PT_PAGE_WIDTH 12ULL
#define PT_PAGE_SIZE (1ULL << PT_PAGE_WIDTH)
#define PT_PAGE_ALIGN (PT_PAGE_SIZE - 1ULL)

/// x86 64 has a 4-level page table.
#define PT_PML4 3
#define PT_PGD 2
#define PT_PMD 1
#define PT_PTE 0

/// x86 64 has 512 entries per level table, i.e., 9 bits (511) to index.
#define PT_NB_ENTRIES 512ULL
#define PT_ENTRY_MASK 511ULL
#define PT_ENTRY_BIT_SIZE 9ULL

/// x86 shifts for page table level masks.
#define PT_PTE_SHIFT 12ULL
#define PT_PMD_SHIFT (PT_PTE_SHIFT + PT_ENTRY_BIT_SIZE)
#define PT_PGD_SHIFT (PT_PMD_SHIFT + PT_ENTRY_BIT_SIZE)
#define PT_PML4_SHIFT (PT_PGD_SHIFT + PT_ENTRY_BIT_SIZE)

/// A mask is nine 1's shifted to the left by the level's shift.
#define PT_PTE_PAGE_MASK (PT_ENTRY_MASK << PT_PTE_SHIFT)
#define PT_PMD_PAGE_MASK (PT_ENTRY_MASK << PT_PMD_SHIFT)
#define PT_PGD_PAGE_MASK (PT_ENTRY_MASK << PT_PGD_SHIFT)
#define PT_PML4_PAGE_MASK (PT_ENTRY_MASK << PT_PML4_SHIFT)

/// Other granules for pages.
#define PT_PMD_PAGE_SIZE (1ULL << PT_PMD_SHIFT)
#define PT_PGD_PAGE_SIZE (1ULL << PT_PGD_SHIFT)

/// Page table masks
#define PT_VIRT_PAGE_MASK (PT_VIRT_MASK - PT_PAGE_ALIGN)
#define PT_PHYS_PAGE_MASK (PT_PHYS_MASK - PT_PAGE_ALIGN)

// ——————————————————————————— Page bits for flags —————————————————————————— //

#define PT_PAGE_BIT_PRESENT 0    /* is present */
#define PT_PAGE_BIT_RW 1         /* writeable */
#define PT_PAGE_BIT_USER 2       /* userspace addressable */
#define PT_PAGE_BIT_PWT 3        /* page write through */
#define PT_PAGE_BIT_PCD 4        /* page cache disabled */
#define PT_PAGE_BIT_ACCESSED 5   /* was accessed (raised by CPU) */
#define PT_PAGE_BIT_DIRTY 6      /* was written to (raised by CPU) */
#define PT_PAGE_BIT_PSE 7        /* 4 MB (or 2MB) page */
#define PT_PAGE_BIT_PAT 7        /* on 4KB pages */
#define PT_PAGE_BIT_GLOBAL 8     /* Global TLB entry PPro+ */
#define PT_PAGE_BIT_SOFTW1 9     /* available for programmer */
#define PT_PAGE_BIT_SOFTW2 10    /* " */
#define PT_PAGE_BIT_SOFTW3 11    /* " */
#define PT_PAGE_BIT_PAT_LARGE 12 /* On 2MB or 1GB pages */
#define PT_PAGE_BIT_SOFTW4 58    /* available for programmer */
#define PT_PAGE_BIT_PKEY_BIT0 59 /* Protection Keys, bit 1/4 */
#define PT_PAGE_BIT_PKEY_BIT1 60 /* Protection Keys, bit 2/4 */
#define PT_PAGE_BIT_PKEY_BIT2 61 /* Protection Keys, bit 3/4 */
#define PT_PAGE_BIT_PKEY_BIT3 62 /* Protection Keys, bit 4/4 */
#define PT_PAGE_BIT_NX 63        /* No execute: only valid after cpuid check */
#define PT_PAGE_BIT_SPECIAL _PAGE_BIT_SOFTW1
#define PT_PAGE_BIT_CPA_TEST _PAGE_BIT_SOFTW1
#define PT_PAGE_BIT_UFFD_WP _PAGE_BIT_SOFTW2    /* userfaultfd wrprotected */
#define PT_PAGE_BIT_SOFT_DIRTY _PAGE_BIT_SOFTW3 /* software dirty tracking */
#define PT_PAGE_BIT_DEVMAP _PAGE_BIT_SOFTW4

/* If _PAGE_BIT_PRESENT is clear, we use these: */
/* - if the user mapped it with PROT_NONE; pte_present gives true */
#define _PAGE_BIT_PROTNONE _PAGE_BIT_GLOBAL

// —————————————————————————————— Actual Flags —————————————————————————————— //

#define PT_PAGE_PRESENT (PT_AT(entry_t, 1) << PT_PAGE_BIT_PRESENT)
#define PT_PAGE_RW (PT_AT(entry_t, 1) << PT_PAGE_BIT_RW)
#define PT_PAGE_USER (PT_AT(entry_t, 1) << PT_PAGE_BIT_USER)
#define PT_PAGE_PWT (PT_AT(entry_t, 1) << PT_PAGE_BIT_PWT)
#define PT_PAGE_PCD (PT_AT(entry_t, 1) << PT_PAGE_BIT_PCD)
#define PT_PAGE_ACCESSED (PT_AT(entry_t, 1) << PT_PAGE_BIT_ACCESSED)
#define PT_PAGE_DIRTY (PT_AT(entry_t, 1) << PT_PAGE_BIT_DIRTY)
#define PT_PAGE_PSE (PT_AT(entry_t, 1) << PT_PAGE_BIT_PSE)
#define PT_PAGE_GLOBAL (PT_AT(entry_t, 1) << PT_PAGE_BIT_GLOBAL)
#define PT_PAGE_SOFTW1 (PT_AT(entry_t, 1) << PT_PAGE_BIT_SOFTW1)
#define PT_PAGE_SOFTW2 (PT_AT(entry_t, 1) << PT_PAGE_BIT_SOFTW2)
#define PT_PAGE_SOFTW3 (PT_AT(entry_t, 1) << PT_PAGE_BIT_SOFTW3)
#define PT_PAGE_PAT (PT_AT(entry_t, 1) << PT_PAGE_BIT_PAT)
#define PT_PAGE_PAT_LARGE (PT_AT(entry_t, 1) << PT_PAGE_BIT_PAT_LARGE)
#define PT_PAGE_SPECIAL (PT_AT(entry_t, 1) << PT_PAGE_BIT_SPECIAL)
#define PT_PAGE_CPA_TEST (PT_AT(entry_t, 1) << PT_PAGE_BIT_CPA_TEST)
#define PT_PAGE_PKEY_BIT0 (PT_AT(entry_t, 1) << PT_PAGE_BIT_PKEY_BIT0)
#define PT_PAGE_PKEY_BIT1 (PT_AT(entry_t, 1) << PT_PAGE_BIT_PKEY_BIT1)
#define PT_PAGE_PKEY_BIT2 (PT_AT(entry_t, 1) << PT_PAGE_BIT_PKEY_BIT2)
#define PT_PAGE_PKEY_BIT3 (PT_AT(entry_t, 1) << PT_PAGE_BIT_PKEY_BIT3)
#define PT_PAGE_NX (PT_AT(entry_t, 1) << PT_PAGE_BIT_NX)
#define PT_PAGE_PIPE (PT_AT(entry_t, 3) << PT_PAGE_BIT_SOFTW1)

// ————————————————————————————— Short Versions ————————————————————————————— //
#define PT_PP PT_PAGE_PRESENT
#define PT_RW PT_PAGE_RW
#define PT_USR PT_PAGE_USER
#define PT_ACC PT_PAGE_ACCESSED
#define PT_DIRT PT_PAGE_DIRTY
#define PT_GLOB PT_PAGE_GLOBAL
#define PT_NX PT_PAGE_NX

// ———————————————————————————— Default profile ————————————————————————————— //
extern const pt_profile_t x86_64_profile;
// ——————————————————————————————— Functions ———————————————————————————————— //

callback_action_t x86_64_how_visit_leaves(entry_t* entry, level_t level, pt_profile_t* profile);

callback_action_t x86_64_how_visit_present(entry_t* entry, level_t level, pt_profile_t* profile);

callback_action_t x86_64_how_map(entry_t* entry, level_t level, pt_profile_t* profile);

entry_t x86_64_next(entry_t entry, level_t curr_level);

callback_action_t x86_64_generic_visitor(entry_t, level_t, pt_profile_t* profile);

callback_action_t x86_64_generic_mapper(entry_t, level_t, pt_profile_t* profile);

#endif
