all: encl_loader.so encl.so test-enclave test

# The folders we depend on.
ELF_LIB=../elf64
ENCL_DRIVER=../../drivers/enclave
CAPA_LIB=../capabilities
DLL_LIB= ../dll

# The includes we depend on.
INCLUDES=-I$(ELF_LIB)/include -I$(ENCL_DRIVER)/include -I$(DLL_LIB)/include -I$(CAPA_LIB)/include

# Configs for dyn libs.
ELF_CONFIG= -Wl,-R $(ELF_LIB) -L$(ELF_LIB)

encl_loader.so: loader/lib.c
	gcc -g $(INCLUDES) -Iinclude/ $(ELF_CONFIG) -shared -o $@ -fPIC $^ -lelf64

encl.so: runtime/lib.c runtime/asm.S
	gcc -g -I$(INCLUDES) -Iinclude/ -shared -o $@ -fPIC $^

test-enclave: tests/enclave.c encl_loader.so encl.so
	gcc -g -nostdlib -fPIC -o $@ $<

test: tests/test.c
	gcc -g $(INCLUDES) -Iinclude -Wl,-R . -L./  $(ELF_CONFIG) -o $@ $< -lelf64 -l:encl_loader.so 

.PHONY: clean

clean:
	rm -rf encl_loader.so encl.so test test-enclave
