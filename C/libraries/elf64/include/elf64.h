#ifndef __INCLUDE_ELF64_H__
#define __INCLUDE_ELF64_H__

#include <elf.h>
#include <stddef.h>
/// Parse an ELF file header and store the result in eh.
/// eh is freeable.
void read_elf64_header(int fd, Elf64_Ehdr* eh);

/// Parse an ELF file sections and store the result as an array in sections.
/// Returns the size of the sections array.
/// sections is freeable.
size_t read_elf64_sections(int fd, Elf64_Ehdr eh, Elf64_Shdr** sections);

/// Parse an ELF file segments and store the result as an array in segments.
/// Returns the size of the segments array.
/// segments is freeable.
size_t read_elf64_segments(int fd, Elf64_Ehdr eh, Elf64_Phdr** segments);

/// Read a section from and ELF file.
/// Result is freeable.
void* read_section64(int fd, Elf64_Shdr sh);

/// Find a symbol within a section pointed by idx.
/// Returns NULL if symbol not found.
/// Result is freeable.
Elf64_Sym* find_symbol_in_section(int fd, char* symbol, Elf64_Ehdr eh, Elf64_Shdr sections[], int idx);

/// Find a symbol within and ELF file.
/// Calls find_symbol_in_section.
/// Returns NULL if symbol not found.
/// Result is freeable.
Elf64_Sym* find_symbol(int fd, char* symbol, Elf64_Ehdr eh, Elf64_Shdr sections[]);

/// Prints all the sections.
void print_elf64_sheaders(int fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]);

/// Prints a single section.
void print_elf64_section(int fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[], int i, int header);
#endif
