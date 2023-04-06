#include "common.h"
#include "elf64.h"
#include <elf.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>


void read_elf64_header(int fd, Elf64_Ehdr *eh)
{
  TEST(eh != NULL); 
  TEST(lseek(fd, (off_t)0, SEEK_SET) == (off_t)0);
  TEST(read(fd, (void*)eh, sizeof(Elf64_Ehdr)) == sizeof(Elf64_Ehdr)); 
  TEST(strncmp((char*)eh->e_ident, ELFMAG, SELFMAG) == 0);
}

size_t read_elf64_sections(int fd, Elf64_Ehdr eh, Elf64_Shdr** sections)
{
  TEST(sections!=NULL);
  TEST(eh.e_shnum > 0);
  *sections = calloc(sizeof(Elf64_Shdr), eh.e_shnum);
  TEST(*sections != NULL);
  TEST(lseek(fd, eh.e_shoff, SEEK_SET) == eh.e_shoff);
  for (int i = 0; i < eh.e_shnum; i++) {
    size_t val = read(fd, (void*)(&((*sections)[i])), sizeof(Elf64_Shdr));
    if (val != sizeof(Elf64_Shdr)) {
      LOG("%d  instead of %d [%s]", val, sizeof(Elf64_Shdr), strerror(errno));
    }
  TEST(val == sizeof(Elf64_Shdr));
  }
  return eh.e_shnum;
}

size_t read_elf64_segments(int fd, Elf64_Ehdr eh, Elf64_Phdr** segments)
{
  TEST(segments != NULL);
  TEST(eh.e_phnum > 0);
  *segments = calloc(sizeof(Elf64_Phdr), eh.e_phnum);
  TEST(*segments != NULL);
  TEST(lseek(fd, eh.e_phoff, SEEK_SET) == eh.e_phoff);
  TEST(sizeof(Elf64_Phdr) == eh.e_phentsize);
  for (int i = 0; i < eh.e_phnum; i++) {
    int val = read(fd, (void*)(&((*segments)[i])), sizeof(Elf64_Phdr)); 
    if (val != sizeof(Elf64_Phdr)) {
      LOG("%d  instead of %d [%s]", val, sizeof(Elf64_Shdr), strerror(errno));
    }
    TEST(val == sizeof(Elf64_Phdr)); 
  }
  return eh.e_phnum;
}

void load_elf64_segment(int fd, void* dest, Elf64_Phdr segment)
{
  TEST(dest != NULL);
  TEST(lseek(fd, segment.p_offset, SEEK_SET) == segment.p_offset);
  TEST(read(fd, dest, segment.p_filesz));
}

void* read_section64(int fd, Elf64_Shdr sh)
{
  void* result = malloc(sh.sh_size);
  TEST(result != NULL);
  TEST(lseek(fd, sh.sh_offset, SEEK_SET) == sh.sh_offset);
  TEST(read(fd, result, sh.sh_size) == sh.sh_size);
  return result;
}

Elf64_Sym* find_symbol_in_section(int fd, char* symbol, Elf64_Ehdr eh, Elf64_Shdr sections[], int idx)
{
  Elf64_Sym* result = NULL;
  Elf64_Sym* sym_tbl = (Elf64_Sym*)read_section64(fd, sections[idx]); 
  TEST(sym_tbl != NULL);
 
  Elf64_Word str_tbl_ndx = sections[idx].sh_link;
  TEST(str_tbl_ndx < eh.e_shnum);
  char* str_tbl = (char*)read_section64(fd, sections[str_tbl_ndx]);
  if ((sections[idx].sh_size % sizeof(Elf64_Sym)) != 0) {
    print_elf64_section(fd, eh, sections, idx, 1);
  } 
  TEST((sections[idx].sh_size % sizeof(Elf64_Sym)) == 0);
  size_t symbol_count = (sections[idx].sh_size / sizeof(Elf64_Sym));
  for (int i = 0; i < symbol_count; i++) {
    char* entry = str_tbl + sym_tbl[i].st_name;
    if (strcmp(symbol, entry) == 0) {
      result = malloc(sizeof(Elf64_Sym));
      TEST(result != NULL);
      memcpy(result, &(sym_tbl[i]), sizeof(Elf64_Sym));
      break;
    }
  }
  // Cleanup
  free(sym_tbl);
  free(str_tbl);
  return result;
}

Elf64_Sym* find_symbol(int fd, char* symbol, Elf64_Ehdr eh, Elf64_Shdr sections[])
{
  Elf64_Sym* result = NULL;
  TEST(symbol != NULL);
  for (int i = 0; i < eh.e_shnum; i++) {
    if ((sections[i].sh_type == SHT_DYNSYM) || (sections[i].sh_type == SHT_SYMTAB)) {
      result = find_symbol_in_section(fd, symbol, eh, sections, i);
      if (result != NULL) {
        return result;
      }
    }
  }
  TEST(result = NULL);
  return NULL;
}

// ———————————————————————————— Print Functions ————————————————————————————— //
void print_elf64_sheaders(int fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[])
{
	uint32_t i;

	printf("========================================");
	printf("========================================\n");
	printf(" idx offset     load-addr  size       algn"
			" flags      type       section\n");
	printf("========================================");
	printf("========================================\n");

	for(i=0; i<eh.e_shnum; i++) {
    print_elf64_section(fd, eh, sh_table, i, 0);
	}
	printf("========================================");
	printf("========================================\n");
	printf("\n");	/* end of section header table */
}

void print_elf64_section(int fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[], int i, int header)
{
	char* sh_str;	/* section-header string-table is also a section. */

	/* read section-header string-table */
	sh_str = read_section64(fd, sh_table[eh.e_shstrndx]);
  if (header) {
	  printf("========================================");
	  printf("========================================\n");
	  printf(" idx offset     load-addr  size       algn"
			  " flags      type       section\n");
	  printf("========================================");
	  printf("========================================\n");
  }
	printf(" %03d ", i);
	printf("0x%08lx ", sh_table[i].sh_offset);
	printf("0x%08lx ", sh_table[i].sh_addr);
	printf("0x%08lx ", sh_table[i].sh_size);
	printf("%4ld ", sh_table[i].sh_addralign);
	printf("0x%08lx ", sh_table[i].sh_flags);
	printf("0x%08x ", sh_table[i].sh_type);
	printf("%s\t", (sh_str + sh_table[i].sh_name));
	printf("\n");
  free(sh_str);
}
