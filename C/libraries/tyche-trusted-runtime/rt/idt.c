#include "idt.h"
#include <stdint.h>
#include "sdk_tyche_rt.h"
#include "bricks.h"

// ———————————————————————————————— Globals ————————————————————————————————— //
__attribute__((aligned(0x10))) 
idt_desc_t idt[IDT_MAX_DESCRIPTORS];

static idtr_t idtr;

extern uint64_t isr_stub_table[];

frame_t* ret_handle = NULL;
// ——————————————————————————————— Functions ———————————————————————————————— //

void save_idt(idtr_t* to_save)
{
    __asm__ __volatile__("sidt %0" : "=m" (*to_save));
}

void restore_idt(idtr_t* to_restore)
{
    __asm__ __volatile__("lidt %0" : : "m" (*to_restore));
}

