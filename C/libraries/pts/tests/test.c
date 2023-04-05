#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "pts_api.h"
#include "x86_64_pt.h"
#include "common.h"


// ————————————————————————— Page Table Simulation —————————————————————————— //
#define PTE_NB_ENTRIES 512
typedef struct pte_t {
  entry_t entries[PTE_NB_ENTRIES];
} pte_t;

#define ALLOC_NB_ENTRIES 2000
#define ALLOC_RAW_SIZE  (ALLOC_NB_ENTRIES * PT_PAGE_SIZE)

/// Allocator of ptes that uses the pool above.
typedef struct pte_allocator_t {
  char* start;
  char* next_free;
  char* end; 
} pte_allocator_t;

/// Let's keep things easy, use a global allocator.
pte_allocator_t allocator = {0};

/// We just simualte segmentation from the allocator region.
addr_t pa_to_va(addr_t addr, pt_profile_t* profile) {
  return  ((addr_t)allocator.start) + addr;
}

/// Again, we have segmentation.
/// Remove the base from the virtual address.
addr_t va_to_pa(addr_t addr, pt_profile_t* profile) {
  TEST(addr >= ((addr_t)allocator.start));
  return addr - ((addr_t)allocator.start);
}

/// Stupid bump allocator.
entry_t* alloc(void* ptr) {
  TEST(allocator.next_free < allocator.end);
  entry_t* allocation = (entry_t*) allocator.next_free;
  allocator.next_free += PT_PAGE_SIZE; 
  return (entry_t*) va_to_pa((addr_t)allocation, ptr);
}

/// Easy way to specify a virtual address.
typedef struct virt_addr_t {
  size_t pml4_idx;
  size_t pgd_idx;
  size_t pmd_idx;
  size_t pte_idx;
} virt_addr_t;

typedef struct extras_t {
  entry_t root;
  entry_t flags;
  size_t invoc_count;
} extras_t;

addr_t create_virt_addr(virt_addr_t virt)
{
  return (PT_AT(addr_t, virt.pml4_idx) << PT_PML4_SHIFT) |
         (PT_AT(addr_t, virt.pgd_idx) << PT_PGD_SHIFT) |
         (PT_AT(addr_t, virt.pmd_idx) << PT_PMD_SHIFT) |
         (PT_AT(addr_t, virt.pte_idx) << PT_PTE_SHIFT);
}

static void init_allocator()
{
  allocator.start = (char*) mmap(NULL, ALLOC_RAW_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  TEST(allocator.start != MAP_FAILED);
  allocator.next_free = allocator.start;
  allocator.end = allocator.start + ALLOC_RAW_SIZE;
  LOG("Done init allocator");
}

callback_action_t pte_page_mapper(entry_t* curr, level_t level, pt_profile_t* profile)
{
  TEST(curr != NULL);
  TEST(profile != NULL);
  TEST((*curr & PT_PP) == 0);
  TEST(profile->extras !=NULL);
  extras_t* extra = (extras_t*)(profile->extras);
  entry_t* new_page = profile->allocate(NULL);
  TEST((((entry_t)new_page) % PT_PAGE_SIZE) == 0); 
  *curr = (((entry_t)new_page) & PT_PHYS_PAGE_MASK) | extra->flags;
  if (level == PT_PTE) {
    extra->invoc_count++;
  }
  return WALK; 
}

callback_action_t pte_page_visit(entry_t* curr, level_t level, pt_profile_t* profile)
{
  TEST(curr != NULL);
  TEST(profile != NULL);
  TEST((*curr & PT_PP) == 1);
  TEST(profile->extras !=NULL);
  if (level == PT_PTE) {
    extras_t* extras = (extras_t*) profile->extras;
    extras->invoc_count++;
  }
  return WALK; 
}

void test_simple_map(pt_profile_t* profile)
{
  // Configure the mappers.
  profile->how = x86_64_how_map;
  profile->mappers[PT_PTE] = pte_page_mapper;
  profile->mappers[PT_PMD] = pte_page_mapper;
  profile->mappers[PT_PGD] = pte_page_mapper;
  profile->mappers[PT_PML4] = pte_page_mapper;
  profile->allocate = alloc; 
  profile->pa_to_va = pa_to_va;
  profile->va_to_pa = va_to_pa;
  // Let's just map 3 ptes as a start.
  virt_addr_t start = {0, 0, 0, 0};
  virt_addr_t end = {0, 0, 0, 3};
  addr_t s = create_virt_addr(start);
  addr_t e = create_virt_addr(end);
  extras_t* extra = (extras_t*)(profile->extras);
  TEST(extra!=NULL);
  entry_t* root = profile->allocate(NULL); 
  extra->root = (entry_t) root;
  TEST(pt_walk_page_range((entry_t) root, PT_PML4, s, e, profile) == 0);
  // Check that we mapped 3 ptes
  TEST(extra->invoc_count == 3);
  LOG("Done mapping.");

  // Now let's check they are mapped.
  extra->invoc_count = 0;
  profile->how = x86_64_how_visit_leaves; 
  profile->visitors[PT_PTE] = pte_page_visit;
  TEST(pt_walk_page_range((entry_t) root, PT_PML4, s, e, profile) == 0);
  TEST(extra->invoc_count == 3);
  LOG("Done walking.");
}

void test_boundary_map(pt_profile_t* profile)
{
  extras_t* extra = (extras_t*)(profile->extras);
  TEST(extra!=NULL);
  extra->invoc_count = 0;
  profile->how = x86_64_how_map;
  // Virtual addresses with boundary crossing on pmd.
  virt_addr_t start = {1, 0, 0, 510};
  virt_addr_t end = {1, 0, 1, 2};
  addr_t s = create_virt_addr(start);
  addr_t e = create_virt_addr(end);
  TEST(get_index(s, PT_PML4, profile) == 1);
  TEST(get_index(s, PT_PGD, profile) == 0);
  TEST(get_index(s, PT_PMD, profile) == 0);
  TEST(get_index(s, PT_PTE, profile) == 510);
  TEST(pt_walk_page_range(extra->root, PT_PML4, s, e, profile) == 0); 
  TEST(extra->invoc_count == 4);
  LOG("Done mapping over a boundary");

  // Now read them.
  extra->invoc_count = 0;
  profile->how = x86_64_how_visit_leaves;
  TEST(pt_walk_page_range(extra->root, PT_PML4, s, e, profile) == 0);
  TEST(extra->invoc_count == 4);
  LOG("Done walking over a boundary");
}

void test_constants(pt_profile_t* profile)
{
  TEST(profile != NULL);
  TEST(profile->shifts[0] == 12);
  TEST(profile->shifts[1] == (12 + 9));
  TEST(profile->shifts[2] == (12 + 9 + 9));
  TEST(profile->shifts[3] == (12 + 9 + 9 + 9));

  TEST(profile->masks[0] == (511ULL << 12));
  TEST(profile->masks[1] == (511ULL << (12+9)));
  TEST(profile->masks[2] == (511ULL << (12+9+9)));
  TEST(profile->masks[3] == (511ULL << (12 + 9 + 9 + 9)));

  TEST(PT_PP == 1);
  TEST(PT_RW == 2);
  TEST(PT_USR == 4);
  TEST(PT_NX == (1ULL << 63));
}

int main(void) {
  LOG("TESTING X86_64 PTs");
  init_allocator();
  pt_profile_t my_profile = x86_64_profile;
  extras_t extra = {0, PT_PP | PT_USR | PT_RW | PT_NX, 0};
  my_profile.extras = (void*) &extra;
  test_constants(&my_profile);
  test_simple_map(&my_profile);
  test_boundary_map(&my_profile);
  return 0;
}
