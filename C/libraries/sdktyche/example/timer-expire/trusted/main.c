#include "sdk_tyche_rt.h"
#include "common.h"
#include "enclave_app.h"
#include "tyche_api.h"
#include <stdint.h>
#include <stddef.h>
// ———————————————————————————————— Globals ————————————————————————————————— //
config_t* shared = NULL;

// ————————————————————————————— Creating Idts —————————————————————————————— //


#define NUM_INTERRUPTS 256
#define KERNEL_CS 0x08 // Kernel code segment selector
#define KERNEL_DS 0x10 // Kernel data segment selector
#define TSS_SELECTOR 0x18 // TSS selector in GDT (GDT index 3, shifted left by 3)

// GDT Structures
struct gdt_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t  base_middle;
    uint8_t  access;
    uint8_t  granularity;
    uint8_t  base_high;
} __attribute__((packed));

struct gdt_tss_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t  base_middle;
    uint8_t  access;
    uint8_t  granularity;
    uint8_t  base_high;
    uint32_t base_upper;
    uint32_t reserved;
} __attribute__((packed));

struct gdt_ptr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

// TSS Structure
struct tss_entry {
    uint32_t reserved1;
    uint64_t rsp0; // Stack pointer for ring 0
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved2;
    uint64_t ist[7]; // Interrupt Stack Table (7 entries)
    uint64_t reserved3;
    uint16_t reserved4;
    uint16_t iomap_base;
} __attribute__((packed));

// IDT Structures
struct idt_entry {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t  ist;          // Interrupt Stack Table index
    uint8_t  type_attr;    // Type and attributes
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t zero;
} __attribute__((packed));

struct idt_ptr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

// Global Variables
struct gdt_entry gdt[6];
struct gdt_tss_entry tss_gdt_entry;
struct tss_entry tss;
struct idt_entry idt[NUM_INTERRUPTS];
struct gdt_ptr gdt_descriptor;
struct idt_ptr idt_descriptor;

// Example stacks for IST
static uint8_t ist1_stack[4096] __attribute__((aligned(16)));
static uint8_t ist2_stack[4096] __attribute__((aligned(16)));

// Function Declarations
void load_gdt(struct gdt_ptr *gdt_desc);
void load_tss(uint16_t selector);
void load_idt(struct idt_ptr *idt_desc);
void set_idt_entry(int vector, void (*handler)(), uint8_t ist_index);
void interrupt_handler_stub(void) {
  // For the moment never return.
  while(1) {}
}

// Function Implementations
void load_gdt(struct gdt_ptr *gdt_desc) {
    asm volatile ("lgdt %0" : : "m"(*gdt_desc));
}

void load_tss(uint16_t selector) {
    asm volatile ("ltr %0" : : "r"(selector));
}

void load_idt(struct idt_ptr *idt_desc) {
    asm volatile ("lidt %0" : : "m"(*idt_desc));
}

void set_idt_entry(int vector, void (*handler)(), uint8_t ist_index) {
    uint64_t handler_address = (uint64_t)handler;

    idt[vector].offset_low  = handler_address & 0xFFFF;
    idt[vector].selector    = KERNEL_CS;
    idt[vector].ist         = ist_index & 0x7; // IST index (0-7)
    idt[vector].type_attr   = 0x8E;            // Present, interrupt gate
    idt[vector].offset_mid  = (handler_address >> 16) & 0xFFFF;
    idt[vector].offset_high = (handler_address >> 32) & 0xFFFFFFFF;
    idt[vector].zero        = 0;
}

void init_gdt_and_tss() {
    // Null descriptor
    gdt[0] = (struct gdt_entry){0};

    // Kernel code segment
    gdt[1] = (struct gdt_entry){
        .limit_low = 0xFFFF,
        .base_low = 0x0000,
        .base_middle = 0x00,
        .access = 0x9A, // Code segment, ring 0
        .granularity = 0xA0,
        .base_high = 0x00,
    };

    // Kernel data segment
    gdt[2] = (struct gdt_entry){
        .limit_low = 0xFFFF,
        .base_low = 0x0000,
        .base_middle = 0x00,
        .access = 0x92, // Data segment, ring 0
        .granularity = 0xA0,
        .base_high = 0x00,
    };

    // TSS descriptor
    uint64_t tss_base = (uint64_t)&tss;
    tss_gdt_entry = (struct gdt_tss_entry){
        .limit_low = sizeof(tss) - 1,
        .base_low = tss_base & 0xFFFF,
        .base_middle = (tss_base >> 16) & 0xFF,
        .access = 0x89, // Present, ring 0, TSS type
        .granularity = 0x00,
        .base_high = (tss_base >> 24) & 0xFF,
        .base_upper = (tss_base >> 32) & 0xFFFFFFFF,
        .reserved = 0,
    };

    // Copy TSS descriptor into GDT
    *(struct gdt_tss_entry *)&gdt[3] = tss_gdt_entry;

    // Initialize TSS
    tss.rsp0 = 0; // Kernel stack for ring 0
    tss.ist[0] = (uint64_t)&ist1_stack[4096]; // IST1
    tss.iomap_base = 0xFFFF; // Disable I/O map

    // Load GDT
    gdt_descriptor.limit = sizeof(gdt) - 1;
    gdt_descriptor.base = (uint64_t)&gdt;
    load_gdt(&gdt_descriptor);

    // Load TSS
    load_tss(TSS_SELECTOR);
}

void init_idt() {
    for (int i = 0; i < NUM_INTERRUPTS; i++) {
        set_idt_entry(i, interrupt_handler_stub, 1); // Use IST1 for all interrupts
    }

    // Load IDT
    idt_descriptor.limit = sizeof(idt) - 1;
    idt_descriptor.base = (uint64_t)idt;
    load_idt(&idt_descriptor);
}

// Kernel entry point
void kernel_init() {
    init_gdt_and_tss(); // Initialize GDT and TSS
    init_idt();         // Initialize IDT

    // Enable interrupts
    asm volatile("sti");
}
// —————————————————————————————— MSR helpers ——————————————————————————————— //
static inline uint64_t read_msr(uint32_t msr) {
    uint32_t low, high;
    asm volatile ("rdmsr"
                  : "=a"(low), "=d"(high)  // Output: low -> EAX, high -> EDX
                  : "c"(msr)              // Input: msr -> ECX
                  );
    return ((uint64_t)high << 32) | low;
}

static inline void write_msr(uint32_t msr, uint64_t value) {
    uint32_t low = (uint32_t)(value & 0xFFFFFFFF);    // Extract lower 32 bits
    uint32_t high = (uint32_t)(value >> 32);         // Extract upper 32 bits
    asm volatile ("wrmsr"
                  :
                  : "c"(msr), "a"(low), "d"(high)    // Inputs: msr -> ECX, low -> EAX, high -> EDX
                  );
}
// ———————————————————————————— Hogger Functions ———————————————————————————— //

// This function simple hogs the cpu.
void hogs(void)
{
  int i = 0;
  kernel_init();

  // Cancel the deadline all the time just for fun.
  while(1) {
    //write_msr(0x6e0, 0);
  }
}

// ————————————————————————————— Entry Function ————————————————————————————— //

void trusted_entry(void)
{
  shared = (config_t*) get_default_shared_buffer();
  hogs();
}
