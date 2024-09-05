# Upon receiving a SIPI from BSP, the AP starts in real mode with CS:IP set to XY00:0000.
# The assembly here tries to enter long mode directly from real mode (skipping protected mode)
#
# Useful links:
# - https://wiki.osdev.org/Symmetric_Multiprocessing#AP_Initialization_Code
# - https://wiki.osdev.org/Entering_Long_Mode_Directly
# - https://stackoverflow.com/questions/36968829/how-to-switch-from-real-mode-to-protected-mode-after-bootloader
# Special thanks to: https://github.com/rcore-os/x86-smpboot

.equ start_addr, 0x7000
.equ ap_trampoline64_start_paddr, start_addr + ap_trampoline64_start - ap_trampoline_start
.equ gdt_64_paddr, start_addr + gdt_64 - ap_trampoline_start
.equ gdt_64_ptr_paddr, start_addr + gdt_64_ptr - ap_trampoline_start

.equ CR0_PE,  (1 << 0)
.equ CR0_PG,  (1 << 31)
.equ CR4_PAE, (1 << 5)
.equ CR4_PGE, (1 << 7)
.equ EFER_LME, (1 << 8)
.equ EFER_NXE, (1 << 11)
.equ EFER_SCE, (1 << 0)

.global ap_trampoline_start
.global ap_trampoline_end

.equ cr3_ptr, start_addr + 0x0ff8
.equ entry_ptr, start_addr + 0x0ff0
.equ stack_ptr, start_addr + 0x0fe8
.equ temp_stack_ptr, start_addr + 0x0fe0

.text
.code16 # 16-bit mode
ap_trampoline_start:
    # disable BIOS enabled interrupts
    cli
    # write back and invalidate cache
    wbinvd

    # zero out data segment registers DS, ES, and SS
    xor     ax, ax     # ax
    mov     ds, ax     # data segment
    mov     es, ax     # extra segment
    mov     ss, ax     # stack segment

    # load idt with 0, 0 so that any NMI will cause a triple fault
    # mov     eax, idt_zero
    # lidt    [eax]

    # cr4: enable PAE and PGE (0xa0)
    mov     eax, cr4
    or      eax, 0xa0
    mov     cr4, eax

    # load cr3
    mov     eax, cr3_ptr
    mov     eax, [eax]
    mov     cr3, eax

    # EFER: enable LME and NXE
    mov     ecx, 0xC0000080
    rdmsr
    or      eax, EFER_LME | EFER_NXE | EFER_SCE
    wrmsr

    # cr0: enable PE and PG (CR0_PE | CR0_PG)
    mov     eax, 1
    shl     eax, 31
    or      eax, 1
    mov     ebx, cr0
    or      ebx, eax
    mov     cr0, ebx

    # lgdt: load 64-bit GDT
    lgdt    [gdt_64_ptr_paddr]

    # esp: point to temporary stack
    mov     esp, temp_stack_ptr

    # jump to long mode directly
    push    0x8
    lea     eax, [ap_trampoline64_start_paddr]
    push    eax
    retf

.code64
ap_trampoline64_start:
    # zero out data segment registers DS, ES, SS, FS, GS, SS
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax

    # enter the entry function
    mov     rsp, [stack_ptr]
    mov     rax, [entry_ptr]
    call    rax

spin_hlt:
    hlt
    jmp     spin_hlt

gdt_64:
    .quad 0x0000000000000000           # NULL-segment descriptor (mandatory)
    .quad 0x00209A0000000000           # Code segment descriptor (required to switch to protected mode)
    .quad 0x0000920000000000           # Data segment descriptor (access data in memory after switching to protected mode)
.align 4
    .word 0                            # Padding to make the address of the GDT aligned on a 4-byte boundary

gdt_64_ptr:
    .word gdt_64_ptr - gdt_64 - 1      # 16-bit Size (Limit) of GDT.
    .long gdt_64_paddr                 # 32-bit Base Address of GDT. (CPU will zero extend to 64-bit)

ap_trampoline_end:
