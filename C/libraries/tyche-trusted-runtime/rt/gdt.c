#include "gdt.h"
#include <stddef.h>

static
__attribute__((aligned(0x1000)))
gdt_desc_t gdt[GDT_MAX_DESCRIPTORS];

static gdtr_t gdtr;

static uint16_t gindex = 0;

static uint64_t mbase = 0x400000;

void save_gdt(gdtr_t* to_save)
{
    __asm__ __volatile__("sgdt %0" : "=m" (*to_save));
}

void restore_gdt(gdtr_t* to_restore)
{
  __asm__ __volatile__("lgdt %0" : : "m" (*to_restore));
}