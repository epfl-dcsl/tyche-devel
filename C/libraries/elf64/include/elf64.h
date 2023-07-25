#ifndef __INCLUDE_ELF64_H__
#define __INCLUDE_ELF64_H__

#include <elf.h>
#include <stddef.h>

/// Encodes the type of parser.
typedef enum {
  FILE_ELF = 0,
  MEM_ELF = 1,
} elf_parser_type_t;

/// A memory-based elf parser state.
typedef struct {
  char* start;
  size_t size;
  size_t offset;
} elf_mem_parser_t;

/// Structure for an elf source.
/// This library allows to parse an elf binary from either a file descriptor
/// or a memory mapped one.
typedef struct {
  elf_parser_type_t type;
  int fd;
  // Only used if we have type MEM_ELF
  elf_mem_parser_t memory;
} elf_parser_t;

/// Parse an ELF file header and store the result in eh.
/// eh is freeable.
void read_elf64_header(elf_parser_t* parser, Elf64_Ehdr* eh);

/// Parse an ELF file sections and store the result as an array in sections.
/// Returns the size of the sections array.
/// sections is freeable.
size_t read_elf64_sections(
    elf_parser_t* parser,
    Elf64_Ehdr eh,
    Elf64_Shdr** sections);

/// Parse an ELF file segments and store the result as an array in segments.
/// Returns the size of the segments array.
/// segments is freeable.
size_t read_elf64_segments(
    elf_parser_t* parser,
    Elf64_Ehdr eh,
    Elf64_Phdr** segments);

/// Loads the segment and reads it into dest.
void load_elf64_segment(elf_parser_t* parser, void* dest, Elf64_Phdr segment);

/// Read a section from and ELF file.
/// Result is freeable.
void* read_section64(elf_parser_t* parser, Elf64_Shdr sh);

/// Find a symbol within a section pointed by idx.
/// Returns NULL if symbol not found.
/// Result is freeable.
Elf64_Sym* find_symbol_in_section(
    elf_parser_t* parser,
    char* symbol,
    Elf64_Ehdr eh,
    Elf64_Shdr sections[],
    int idx);

/// Find a symbol within and ELF file.
/// Calls find_symbol_in_section.
/// Returns NULL if symbol not found.
/// Result is freeable.
Elf64_Sym* find_symbol(
    elf_parser_t* parser,
    char* symbol,
    Elf64_Ehdr eh,
    Elf64_Shdr sections[]);

/// Prints all the sections.
void print_elf64_sheaders(
    elf_parser_t* parser,
    Elf64_Ehdr eh,
    Elf64_Shdr sh_table[]);

/// Prints a single section.
void print_elf64_section(
    elf_parser_t* parser,
    Elf64_Ehdr eh,
    Elf64_Shdr sh_table[],
    int i,
    int header);
#endif
