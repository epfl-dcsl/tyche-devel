#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "tyche_capabilities.h"
// —————————————————————————————— Module Info ——————————————————————————————— //

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tyche team");
MODULE_DESCRIPTION("Tyche Capability driver LKM");
MODULE_VERSION("0.01");

// ———————————————————————————————— Helpers ————————————————————————————————— //

// TODO for debugging, remove later.
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
  printk(KERN_NOTICE "[CAPA | %lld]: %s\n",counter_alloc, msg);
}
*/
// —————————————————————— Loading/Unloading  functions —————————————————————— //
static int __init tyche_capabilities_init(void) {
  return init(local_allocator, local_free);
}
static void __exit tyche_capabilities_exit(void)
{
  printk(KERN_INFO "Removing Tyche Capability LKM driver.");
}

// ————————————————————————————— API forwarders ————————————————————————————— //

int tc_create_domain(domain_id_t* handle, usize spawn, usize comm)
{
  return create_domain(handle, spawn, comm);
}

int tc_seal_domain(domain_id_t dom, usize core_map, paddr_t cr3, paddr_t rip, paddr_t rsp)
{
  return seal_domain(dom, core_map, cr3, rip, rsp);
}

int tc_grant_region(domain_id_t dom, paddr_t start, paddr_t end, memory_access_right_t access)
{
  return grant_region(dom, start, end, access); 
}

int tc_share_region(domain_id_t dom, paddr_t start, paddr_t end, memory_access_right_t access)
{
  return share_region(dom, start, end, access); 
}

int tc_revoke_region(domain_id_t dom, paddr_t start, paddr_t end)
{
  return revoke_region(dom, start, end);
}

int tc_switch_domain(domain_id_t id, void* args)
{
  return switch_domain(id, args);
}

int tc_revoke_domain(domain_id_t id)
{
  return revoke_domain(id);
}

// ————————————————————————— Module's Registration —————————————————————————— //

module_init(tyche_capabilities_init);
module_exit(tyche_capabilities_exit);
EXPORT_SYMBOL(tc_create_domain);
EXPORT_SYMBOL(tc_seal_domain);
EXPORT_SYMBOL(tc_grant_region);
EXPORT_SYMBOL(tc_share_region);
EXPORT_SYMBOL(tc_revoke_region);
EXPORT_SYMBOL(tc_switch_domain);
EXPORT_SYMBOL(tc_revoke_domain);
