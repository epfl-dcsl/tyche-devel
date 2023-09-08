ENTRY(_start);

SECTIONS
{
  /* Start address */
  . = 0x0;

  /* Output a text section */
  .text : ALIGN(0x1000) {
    *(.text .text.*);
  }

  /* Output the rodata */
  .rodata : ALIGN(0x1000) {
    KEEP(*(__*))
    *(.rodata)
    *(.rodata.*)
  }

  .data : ALIGN(0x1000) {
    KEEP(*(__*))
    *(.data)
    *(.data.*)
  }
  .bss : ALIGN(0x1000) {
    *(.bss)
    *(.bss.*)
  }

  .unmapped : ALIGN(0x1000) {
    *(.*);
  }
}
