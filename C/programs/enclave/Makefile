all: enclave a.out 

# All the library dependencies.
ELF64=../../libraries/elf64
LOADER=../../libraries/enclave
DRIVER=../../drivers/enclave
CAPA=../../libraries/capabilities
ENCL=../../libraries/enclave
DLL=../../libraries/dll

# All the includes
INCLUDES= -Iinclude/ -I$(DLL)/include -I$(ELF64)/include -I$(LOADER)/include -I$(DRIVER)/include -I$(CAPA)/include -I$(ENCL)/include

# Enclave includes
TRUSTED_INCLUDES=-I$(CAPA)/include
TRUSTED_RT=../../libraries/enclave/runtime/
TRUSTED_RT_SRC=$(TRUSTED_RT)/asm.S $(TRUSTED_RT)/lib.c
CAPA_LIB=$(CAPA)/libcapabilities.a

# Dynamic libraries
DYN_LIBS= -l:encl_loader.so -lelf64

# Destination for installation.
DISK_PATH = /tmp/mount/tyche/programs
INSTALL_PATH = /tyche

a.out: src/main.c enclave 
	mkdir -p libs
	make -C $(ELF64)
	make -C $(LOADER)
	cp $(ELF64)/libelf64.so libs/
	cp $(LOADER)/encl_loader.so libs/
	cp $(LOADER)/encl.so libs/
	gcc -g $(INCLUDES) -Wl,-R ./libs/ -L./libs/ -o $@ $< $(DYN_LIBS)

enclave: trusted/main.c $(TRUSTED_RT_SRC) $(CAPA_LIB)
	gcc -g $(INCLUDES) -nostdlib -static -o $@ $^

install: a.out enclave
	mkdir -p $(INSTALL_PATH)/enclaves
	cp -r libs $(INSTALL_PATH)/enclaves
	cp -t $(INSTALL_PATH)/enclaves $^

install_disk: a.out enclave
	mkdir -p $(DISK_PATH)
	cp -r libs $(DISK_PATH)
	cp -t $(DISK_PATH) $^


.PHONY: clean

clean:
	rm enclave

