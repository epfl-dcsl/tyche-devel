#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "pts_api.h"
#include "riscv48_pt.h"
#include "common.h"
#include "common_log.h"

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
  size_t lvl3_idx;
  size_t lvl2_idx;
  size_t lvl1_idx;
  size_t lvl0_idx;
} virt_addr_t;

typedef struct extras_t {
  entry_t root;
  entry_t flags;
  size_t invoc_count;
} extras_t;

addr_t create_virt_addr(virt_addr_t virt)
{
  return (PT_AT(addr_t, virt.lvl3_idx) << PT_LVL3_SHIFT) |
         (PT_AT(addr_t, virt.lvl2_idx) << PT_LVL2_SHIFT) |
         (PT_AT(addr_t, virt.lvl1_idx) << PT_LVL1_SHIFT) |
         (PT_AT(addr_t, virt.lvl0_idx) << PT_LVL0_SHIFT);
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
  TEST((*curr & PT_V) == 0);
  TEST(profile->extras !=NULL);
  extras_t* extra = (extras_t*)(profile->extras);
  entry_t flags = (level == LVL0)? extra->flags: PT_V;
  entry_t* new_page = profile->allocate(NULL);
  TEST((((entry_t)new_page) % PT_PAGE_SIZE) == 0); 
  *curr = (
      ((((entry_t)new_page) >> PT_PAGE_WIDTH) << PT_FLAGS_RESERVED) & 
      PT_PHYS_PAGE_MASK) |flags;
  if (level == LVL0) {
    extra->invoc_count++;
  }
  return WALK; 
}

callback_action_t pte_page_visit(entry_t* curr, level_t level, pt_profile_t* profile)
{
  TEST(curr != NULL);
  TEST(profile != NULL);
  TEST((*curr & PT_V) == 1);
  TEST(profile->extras !=NULL);
  if (level == LVL0) {
    extras_t* extras = (extras_t*) profile->extras;
    extras->invoc_count++;
  }
  return WALK; 
}

void test_simple_map(pt_profile_t* profile)
{
  // Configure the mappers.
  profile->how = riscv48_how_map;
  profile->mappers[LVL0] = pte_page_mapper;
  profile->mappers[LVL1] = pte_page_mapper;
  profile->mappers[LVL2] = pte_page_mapper;
  profile->mappers[LVL3] = pte_page_mapper;
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
  TEST(pt_walk_page_range((entry_t) root, LVL3, s, e, profile) == 0);
  // Check that we mapped 3 ptes
  TEST(extra->invoc_count == 3);
  LOG("Done mapping.");

  // Now let's check they are mapped.
  extra->invoc_count = 0;
  profile->how = riscv48_how_visit_leaves; 
  profile->visitors[LVL0] = pte_page_visit;
  int ret = pt_walk_page_range((entry_t) root, LVL3, s, e, profile);
  TEST(ret == 0);
  TEST(extra->invoc_count == 3);
  LOG("Done walking.");
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

  TEST(PT_V == 1);
  TEST(PT_R == 2);
  TEST(PT_W == 4);
  TEST(PT_X == 8);
  TEST(PT_U == 1 << 4);
}

int main(void) {
  LOG("TESTING RISCV48 PTs");
  init_allocator();
  pt_profile_t my_profile = riscv64_sv48_profile;
  extras_t extra = {0, PT_V | PT_U | PT_R | PT_W, 0};
  my_profile.extras = (void*) &extra;
  test_constants(&my_profile);
  test_simple_map(&my_profile);
  return 0;
}
