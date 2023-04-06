all: enclave_loader.so

# Dependencies for the build.
LIB_PT=../pts
DLL_LIB= ../dll
ELF_LIB=../elf64
CAPA_LIB=../capabilities
COMMON_LIB=../common
ENCL_DRIVER=../../drivers/tyche

# Configuration for loader version 2.
CODE_LOADER = $(wildcard loader/*.c)
HDRS_LOADER = $(wildcard loader/*.h) $(wildcard include/*.h)

# Configure the includes.
COMMON_INCLUDES = -Iinclude -I$(ELF_LIB)/include -I$(ENCL_DRIVER)/include -I$(DLL_LIB)/include -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include
WITH_PTS_INCLUDES = $(COMMON_INCLUDES) -I$(LIB_PT)/include

# Configs for dynamic library.
ELF_CONFIG= -Wl,-R $(ELF_LIB) -L$(ELF_LIB)

enclave_loader.so: $(CODE_LOADER) $(HDRS_LOADER)
	gcc -DTYCHE_USER_SPACE=1 -g $(WITH_PTS_INCLUDES) $(ELF_CONFIG) -shared -o $@ -fPIC $(CODE_LOADER) -lelf64

.PHONY: clean

clean:
	rm -rf enclave_loader.so
