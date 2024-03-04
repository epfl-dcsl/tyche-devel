#include <elf.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>

#include "common.h"
#include "common_log.h"
#include "elf64.h"

/// Let the test read itself for the test.
const char* file = "test_elf64";

void test_read_open_file(elf_parser_t* parser)
{
  parser->type = FILE_ELF;
  parser->fd = open(file, O_RDONLY|O_SYNC);
  TEST(parser->fd > 0);
  LOG("SUCCCESS");
}

void test_mmap_file(elf_parser_t* parser)
{
  parser->type = MEM_ELF;
  parser->fd = open(file, O_RDONLY|O_SYNC);
  TEST(parser->fd > 0);
  struct stat file_info;
  TEST(fstat(parser->fd, &file_info) != -1);
  parser->memory.size = file_info.st_size;
  parser->memory.offset = 0;
  parser->memory.start = (char*) mmap(
      NULL, file_info.st_size, PROT_READ, MAP_SHARED, parser->fd, 0); 
  TEST(parser->memory.start != MAP_FAILED);
}

Elf64_Ehdr test_read_header(elf_parser_t* parser)
{
  Elf64_Ehdr result;
  read_elf64_header(parser, &result);
  LOG("SUCCESS");
  return result;
}

Elf64_Shdr* test_read_sections(elf_parser_t* parser, Elf64_Ehdr eh)
{
  Elf64_Shdr* sections = NULL; 
  TEST(eh.e_shentsize == sizeof(Elf64_Shdr));
  TEST(read_elf64_sections(parser, eh, &sections) == eh.e_shnum); 
  TEST(sections != NULL);
  LOG("SUCCCESS %d", eh.e_shnum);
  return sections;
}

Elf64_Phdr* test_read_segments(elf_parser_t* parser, Elf64_Ehdr eh)
{
  Elf64_Phdr* segments = NULL;
  TEST(eh.e_phentsize == sizeof(Elf64_Phdr));
  TEST(read_elf64_segments(parser, eh, &segments) == eh.e_phnum);
  TEST(segments != NULL);
  LOG("SUCCESS");
  return segments;
}

Elf64_Sym* test_read_symbol(
    elf_parser_t* parser,
    char* symbol,
    Elf64_Ehdr eh,
    Elf64_Shdr* sections)
{
  Elf64_Sym* sym = NULL;
  sym = find_symbol(parser, symbol, eh, sections);
  TEST(sym != NULL);
  LOG("SUCCESS %s [0x%08lx]", symbol, sym->st_value);
  return sym;
}

int run_test(elf_parser_t* parser)
{
  Elf64_Ehdr eh = test_read_header(parser);
  Elf64_Shdr* sections = test_read_sections(parser, eh);
  print_elf64_sheaders(parser, eh,sections);
  Elf64_Phdr* segments = test_read_segments(parser, eh);
  char * symbols[] = {"test_read_open_file", "test_read_header", "test_read_sections"};
  for (int i = 0; i < 3; i++) {
    Elf64_Sym* sym = test_read_symbol(parser, symbols[i], eh, sections); 
    free(sym);
  }
}

int main(void)
{
  LOG("TESTING elf64 library: File based");
  elf_parser_t parser;
  test_read_open_file(&parser); 
  run_test(&parser);
  close(parser.fd);
  test_mmap_file(&parser);
  run_test(&parser);
  return 0;
}


