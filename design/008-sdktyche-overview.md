# 008 - SDKTyche overview

## What

This is an overview of how `sdktyche` binaries are created and run.

## Why

This can be useful for onboarding new people faster.

## How

To run domains (enclaves and sandboxes) on top of tyche from the default linux domain, we created the `sdktyche`.
The SDK allows an `application` running in linux to load a `domain` instrumented binary inside a seperate domain.
The `domain` binary is instrumented using `tychools` to replace every loadable segment type with a tyche-specific segment type that determines whether the memory ressources are shared between the `application` and the `domain`.
The `domain` binary is included inside the `application`'s sections.
This is visible below in section 36.

```
readelf -S application
There are 37 section headers, starting at offset 0xfa98:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         00000000000002a8  000002a8
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.gnu.bu[...] NOTE             00000000000002c4  000002c4
       0000000000000024  0000000000000000   A       0     0     4
  [ 3] .note.ABI-tag     NOTE             00000000000002e8  000002e8
       0000000000000020  0000000000000000   A       0     0     4
  [ 4] .gnu.hash         GNU_HASH         0000000000000308  00000308
       0000000000000028  0000000000000000   A       5     0     8
  [ 5] .dynsym           DYNSYM           0000000000000330  00000330
       0000000000000300  0000000000000018   A       6     1     8
  [ 6] .dynstr           STRTAB           0000000000000630  00000630
       000000000000012c  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           000000000000075c  0000075c
       0000000000000040  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          00000000000007a0  000007a0
       0000000000000030  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             00000000000007d0  000007d0
       0000000000000138  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             0000000000000908  00000908
       0000000000000258  0000000000000018  AI       5    24     8
  [11] .init             PROGBITS         0000000000001000  00001000
       0000000000000017  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         0000000000001020  00001020
       00000000000001a0  0000000000000010  AX       0     0     16
  [13] .plt.got          PROGBITS         00000000000011c0  000011c0
       0000000000000008  0000000000000008  AX       0     0     8
  [14] .text             PROGBITS         00000000000011d0  000011d0
       0000000000003cc1  0000000000000000  AX       0     0     16
  [15] .fini             PROGBITS         0000000000004e94  00004e94
       0000000000000009  0000000000000000  AX       0     0     4
  [16] .rodata           PROGBITS         0000000000005000  00005000
       0000000000000e09  0000000000000000   A       0     0     16
  [17] .eh_frame_hdr     PROGBITS         0000000000005e0c  00005e0c
       00000000000001ac  0000000000000000   A       0     0     4
  [18] .eh_frame         PROGBITS         0000000000005fb8  00005fb8
       00000000000006d0  0000000000000000   A       0     0     8
  [19] .init_array       INIT_ARRAY       0000000000007c10  00006c10
       0000000000000008  0000000000000008  WA       0     0     8
  [20] .fini_array       FINI_ARRAY       0000000000007c18  00006c18
       0000000000000008  0000000000000008  WA       0     0     8
  [21] .data.rel.ro      PROGBITS         0000000000007c20  00006c20
       00000000000001c0  0000000000000000  WA       0     0     32
  [22] .dynamic          DYNAMIC          0000000000007de0  00006de0
       00000000000001e0  0000000000000010  WA       6     0     8
  [23] .got              PROGBITS         0000000000007fc0  00006fc0
       0000000000000028  0000000000000008  WA       0     0     8
  [24] .got.plt          PROGBITS         0000000000008000  00007000
       00000000000000e0  0000000000000008  WA       0     0     8
  [25] .data             PROGBITS         00000000000080e0  000070e0
       0000000000000018  0000000000000000  WA       0     0     8
  [26] .bss              NOBITS           0000000000008100  000070f8
       0000000000000020  0000000000000000  WA       0     0     32
  [27] .comment          PROGBITS         0000000000000000  000070f8
       0000000000000027  0000000000000001  MS       0     0     1
  [28] .debug_aranges    PROGBITS         0000000000000000  0000711f
       0000000000000150  0000000000000000           0     0     1
  [29] .debug_info       PROGBITS         0000000000000000  0000726f
       0000000000003e85  0000000000000000           0     0     1
  [30] .debug_abbrev     PROGBITS         0000000000000000  0000b0f4
       0000000000000b97  0000000000000000           0     0     1
  [31] .debug_line       PROGBITS         0000000000000000  0000bc8b
       00000000000016e8  0000000000000000           0     0     1
  [32] .debug_str        PROGBITS         0000000000000000  0000d373
       0000000000000d18  0000000000000001  MS       0     0     1
  [33] .symtab           SYMTAB           0000000000000000  0000e090
       0000000000001128  0000000000000018          34    96     8
  [34] .strtab           STRTAB           0000000000000000  0000f1b8
       0000000000000789  0000000000000000           0     0     1
  [35] .shstrtab         STRTAB           0000000000000000  0000f941
       0000000000000154  0000000000000000           0     0     1
  [36]                   NOTE             0000000000000000  000103d8
       0000000000009500  0000000000009500   o       0     0     0
```

Section 36 above contains the full `domain` binary.
The domain binary segment look like this:

```
 readelf -l dump                                                                                         [15:21]

Elf file type is EXEC (Executable file)
Entry point 0x4010be
There are 9 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOOS+0xa       0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x00000000000001b4 0x00000000000001b4  R      0x1000
  LOOS+0xa       0x00000000000010a8 0x0000000000401000 0x0000000000401000
                 0x00000000000001e1 0x00000000000001e1  R E    0x1000
  LOOS+0xa       0x00000000000020a8 0x0000000000402000 0x0000000000402000
                 0x0000000000000118 0x0000000000000118  R      0x1000
  LOOS+0xa       0x00000000000030a8 0x0000000000404000 0x0000000000404000
                 0x0000000000000018 0x0000000000000020  RW     0x1000
  NOTE           0x0000000000000238 0x0000000000400190 0x0000000000400190
                 0x0000000000000024 0x0000000000000024  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RWE    0x10
  LOOS+0x8       0x0000000000000000 0x0000000000405000 0x0000000000000000
                 0x0000000000000000 0x0000000000002000  RW     0x1000
  LOOS+0x9       0x0000000000000000 0x0000000000300000 0x0000000000000000
                 0x0000000000000000 0x0000000000002000  RW     0x1000
  LOOS+0x6       0x0000000000004100 0x0000000000008000 0x0000000000000000
                 0x0000000000005000 0x0000000000005000  RW     0x1000

```

Where the `LOOS` is the OS-specific marker for segment types.
What each value corresponds to can be determined by looking at `tychools` or the `sdktyche/include/sdk_tyche_types.h`.


The application uses the `loader` part of the SDK to extract section 36 (`domain`) from itself and parses and loads the `domain` binary.
The loader performs calls to the `tyche` driver to perform the monitor calls necessary to create and initialize a new domain for this binary.


Here is a schema of the binaries: 

```

| application |
| ----------- |
|             |
| loader      |
| domain      | --->  | domain    |
                      | LOOS+0xa  |

```

Here is a schema of how the execution works:

```
                Default Domain (Linux)  | The Created Domain
                                        |
                (application)           |
[user space]          |                 |
----------------------|-----------------|-------------------
[kernel space]        |                 |
                      v                 |
                (tyche driver)          |     (domain)
                      |                 |         ^
                      |                 |         |
 ---------------------|-----------------|---------|---------
                      V                           |
                    tyche--------------------------

```
