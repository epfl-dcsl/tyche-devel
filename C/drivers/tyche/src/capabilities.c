#include <linux/kernel.h>
#include <linux/slab.h>

#include "common.h"
#include "domains.h"
#include "tyche_capabilities.h"
// ———————————————————————————————— Helpers ————————————————————————————————— //
static unsigned long long counter_alloc = 0;
static void* local_allocator(unsigned long size)
{
  counter_alloc++;
  return kmalloc(size, GFP_KERNEL);
}

static void local_free(void* ptr)
{
  counter_alloc--;
  kfree(ptr);
}
/*
static void local_print(const char *msg)
{
  LOG("[CAPA | %lld]: %s\n", counter_alloc, msg);
}
*/

// ——————————————————————————————— Public API ——————————————————————————————— //

int driver_init_capabilities(void)
{
  return init(local_allocator, local_free); 
} 
