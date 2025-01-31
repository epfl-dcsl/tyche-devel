#include "common.h"
#include "enclave_app.h"
#include "sdk_tyche_rt.h"
#include "tyche_api.h"
#include <stddef.h>
#include <stdint.h>
// ———————————————————————————————— Globals ————————————————————————————————— //
config_t *shared = NULL;

// ————————————————————————————— Creating Idts —————————————————————————————— //

#include "interrupts.h"

#define NUM_INTERRUPTS 256
#define KERNEL_CS 0x08 // Kernel code segment selector
#define KERNEL_DS 0x10 // Kernel data segment selector
#define TSS_SELECTOR                                                           \
  0x18 // TSS selector in GDT (GDT index 3, shifted left by 3)

// GDT Structures
struct gdt_entry {
  uint16_t limit_low;
  uint16_t base_low;
  uint8_t base_middle;
  uint8_t access;
  uint8_t granularity;
  uint8_t base_high;
} __attribute__((packed));

struct gdt_tss_entry {
  uint16_t limit_low;
  uint16_t base_low;
  uint8_t base_middle;
  uint8_t access;
  uint8_t granularity;
  uint8_t base_high;
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
  uint8_t ist;       // Interrupt Stack Table index
  uint8_t type_attr; // Type and attributes
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
//void interrupt_handler_stub(void);

// The vector array.
void (*vector_table[256])(void) = {
    vector_0,   vector_1,   vector_2,   vector_3,   vector_4,   vector_5,
    vector_6,   vector_7,   vector_8,   vector_9,   vector_10,  vector_11,
    vector_12,  vector_13,  vector_14,  vector_15,  vector_16,  vector_17,
    vector_18,  vector_19,  vector_20,  vector_21,  vector_22,  vector_23,
    vector_24,  vector_25,  vector_26,  vector_27,  vector_28,  vector_29,
    vector_30,  vector_31,  vector_32,  vector_33,  vector_34,  vector_35,
    vector_36,  vector_37,  vector_38,  vector_39,  vector_40,  vector_41,
    vector_42,  vector_43,  vector_44,  vector_45,  vector_46,  vector_47,
    vector_48,  vector_49,  vector_50,  vector_51,  vector_52,  vector_53,
    vector_54,  vector_55,  vector_56,  vector_57,  vector_58,  vector_59,
    vector_60,  vector_61,  vector_62,  vector_63,  vector_64,  vector_65,
    vector_66,  vector_67,  vector_68,  vector_69,  vector_70,  vector_71,
    vector_72,  vector_73,  vector_74,  vector_75,  vector_76,  vector_77,
    vector_78,  vector_79,  vector_80,  vector_81,  vector_82,  vector_83,
    vector_84,  vector_85,  vector_86,  vector_87,  vector_88,  vector_89,
    vector_90,  vector_91,  vector_92,  vector_93,  vector_94,  vector_95,
    vector_96,  vector_97,  vector_98,  vector_99,  vector_100, vector_101,
    vector_102, vector_103, vector_104, vector_105, vector_106, vector_107,
    vector_108, vector_109, vector_110, vector_111, vector_112, vector_113,
    vector_114, vector_115, vector_116, vector_117, vector_118, vector_119,
    vector_120, vector_121, vector_122, vector_123, vector_124, vector_125,
    vector_126, vector_127, vector_128, vector_129, vector_130, vector_131,
    vector_132, vector_133, vector_134, vector_135, vector_136, vector_137,
    vector_138, vector_139, vector_140, vector_141, vector_142, vector_143,
    vector_144, vector_145, vector_146, vector_147, vector_148, vector_149,
    vector_150, vector_151, vector_152, vector_153, vector_154, vector_155,
    vector_156, vector_157, vector_158, vector_159, vector_160, vector_161,
    vector_162, vector_163, vector_164, vector_165, vector_166, vector_167,
    vector_168, vector_169, vector_170, vector_171, vector_172, vector_173,
    vector_174, vector_175, vector_176, vector_177, vector_178, vector_179,
    vector_180, vector_181, vector_182, vector_183, vector_184, vector_185,
    vector_186, vector_187, vector_188, vector_189, vector_190, vector_191,
    vector_192, vector_193, vector_194, vector_195, vector_196, vector_197,
    vector_198, vector_199, vector_200, vector_201, vector_202, vector_203,
    vector_204, vector_205, vector_206, vector_207, vector_208, vector_209,
    vector_210, vector_211, vector_212, vector_213, vector_214, vector_215,
    vector_216, vector_217, vector_218, vector_219, vector_220, vector_221,
    vector_222, vector_223, vector_224, vector_225, vector_226, vector_227,
    vector_228, vector_229, vector_230, vector_231, vector_232, vector_233,
    vector_234, vector_235, vector_236, vector_237, vector_238, vector_239,
    vector_240, vector_241, vector_242, vector_243, vector_244, vector_245,
    vector_246, vector_247, vector_248, vector_249, vector_250, vector_251,
    vector_252, vector_253, vector_254, vector_255,
};

/*void interrupt_handler_c(int vect) {
  // For the moment never return.
  // TODO: just return from the interrupt handler.
  asm volatile("movq %0, %%rdi\n\t"
               "movq $10, %%rax\n\t"
               "vmcall\n\t"
               :
               : "rm"(vect)
               : "rax", "rdi");
  //TODO: clear the interrupt?
}*/

// Function Implementations
void load_gdt(struct gdt_ptr *gdt_desc) {
  asm volatile("lgdt %0" : : "m"(*gdt_desc));
}

void load_tss(uint16_t selector) { asm volatile("ltr %0" : : "r"(selector)); }

void load_idt(struct idt_ptr *idt_desc) {
  asm volatile("lidt %0" : : "m"(*idt_desc));
}

void set_idt_entry(int vector, void (*handler)(), uint8_t ist_index) {
  uint64_t handler_address = (uint64_t)handler;

  idt[vector].offset_low = handler_address & 0xFFFF;
  idt[vector].selector = KERNEL_CS;
  idt[vector].ist = ist_index & 0x7; // IST index (0-7)
  idt[vector].type_attr = 0x8E;      // Present, interrupt gate
  idt[vector].offset_mid = (handler_address >> 16) & 0xFFFF;
  idt[vector].offset_high = (handler_address >> 32) & 0xFFFFFFFF;
  idt[vector].zero = 0;
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
  tss.rsp0 = 0;                             // Kernel stack for ring 0
  tss.ist[0] = (uint64_t)&ist1_stack[4096]; // IST1
  tss.iomap_base = 0xFFFF;                  // Disable I/O map

  // Load GDT
  gdt_descriptor.limit = sizeof(gdt) - 1;
  gdt_descriptor.base = (uint64_t)&gdt;
  load_gdt(&gdt_descriptor);

  // Load TSS
  load_tss(TSS_SELECTOR);
}

void init_idt() {
  for (int i = 0; i < NUM_INTERRUPTS; i++) {
    set_idt_entry(i, vector_table[i], 1); // Use IST1 for all interrupts
  }

  // Load IDT
  idt_descriptor.limit = sizeof(idt) - 1;
  idt_descriptor.base = (uint64_t)idt;
  load_idt(&idt_descriptor);



  // **Explicitly load the correct CS and SS values**
  __asm__ volatile (
  "pushq $0x08\n\t"
  "leaq .reload_CS(%%rip), %%rax\n\t"
  "pushq %%rax\n\t"
   "retfq\n\t"
   ".reload_CS:\n\t"
    "mov $0x10, %%ax\n"  // Load KERNEL_SS (stack segment) into AX
    "mov %%ax, %%ss\n"   // Set SS to KERNEL_SS

    : // No input operands
    : // No output operands
    : "ax"               // "ax" is clobbered as it's being used to load values
  );
}

// Kernel entry point
void kernel_init() {
  init_gdt_and_tss(); // Initialize GDT and TSS
  init_idt();         // Initialize IDT

  // Enable interrupts
  // TODO: cancel the timer.
  asm volatile("sti");
}
// —————————————————————————————— MSR helpers ——————————————————————————————— //
static inline uint64_t read_msr(uint32_t msr) {
  uint32_t low, high;
  asm volatile("rdmsr"
               : "=a"(low), "=d"(high) // Output: low -> EAX, high -> EDX
               : "c"(msr)              // Input: msr -> ECX
  );
  return ((uint64_t)high << 32) | low;
}

static inline void write_msr(uint32_t msr, uint64_t value) {
  uint32_t low = (uint32_t)(value & 0xFFFFFFFF); // Extract lower 32 bits
  uint32_t high = (uint32_t)(value >> 32);       // Extract upper 32 bits
  asm volatile("wrmsr"
               :
               : "c"(msr), "a"(low),
                 "d"(high) // Inputs: msr -> ECX, low -> EAX, high -> EDX
  );
}
// ———————————————————————————— Hogger Functions ———————————————————————————— //

// This function simple hogs the cpu.
void hogs(void) {
  int i = 0;
  kernel_init();

  // Cancel the deadline all the time just for fun.
  for (i = 0; i < 10; i++) {
    asm volatile(
      "int $0x70\n\t"
      :
      : "rm"((uint64_t)i)
      : "%rax"); 
  }
  // Now we can exit.
}

// ————————————————————————————— Entry Function ————————————————————————————— //

void trusted_entry(void) {
  shared = (config_t *)get_default_shared_buffer();
  hogs();
  // Mark that we finished.
  shared->marker = 777;
}
