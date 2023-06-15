SECTIONS
{
  . = 0x80000000;  /* Set the desired starting address */
  .text : { *(.text) }
  .data : { *(.data) }
  .bss : { *(.bss) }
}
