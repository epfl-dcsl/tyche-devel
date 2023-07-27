#ifndef __TRT_INCLUDE_IDT_H__
#define __TRT_INCLUDE_IDT_H__

#include "sdk_tyche_rt.h"
#include <stdint.h>

// ————————————————————————————— IDT constants —————————————————————————————— //
#define IDT_MAX_DESCRIPTORS 256

#define MASK_ISR_LOW ((uint64_t)0xFFFF)
#define MASK_ISR_HIGH ((uint64_t)0xFFFFFFFF)
#define SHIFT_ISR_MID (16)
#define SHIFT_ISR_HIGH (32)

// ————————————————————————— Structures for x86_64 —————————————————————————— //

typedef struct idt_desc_t {
  uint16_t isr_low;   // The lower 16 bits of the ISR's address
  uint16_t kernel_cs; // The GDT segment selector that the CPU will load into CS before calling the ISR
  uint8_t ist;        // The IST in the TSS that the CPU will load into RSP; set to zero for now
  uint8_t attributes; // Type and attributes; see the IDT page
  uint16_t isr_mid;   // The higher 16 bits of the lower 32 bits of the ISR's address
  uint32_t isr_high;  // The higher 32 bits of the ISR's address
  uint32_t reserved;  // Set to zero
} __attribute__((packed)) idt_desc_t;

typedef struct idtr_t {
  uint16_t limit;
  uint64_t base;
} __attribute__((packed)) idtr_t;

// ——————————————————————————————— Functions ———————————————————————————————— //
void idt_init(frame_t* frame);
void save_idt(idtr_t* to_save);
void restore_idt(idtr_t* to_restore);
void exception_handler(void);
void divide_zero_handler(void);
#endif
