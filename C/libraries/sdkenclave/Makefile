all: enclave_loader.so enclave_runtime.so

# Dependencies for the build.
LIB_PT=../pts
DLL_LIB= ../dll
ELF_LIB=../elf64
CAPA_LIB=../capabilities
COMMON_LIB=../common
ENCL_DRIVER=../../drivers/tyche

# Configuration for loader.
CODE_LOADER = $(wildcard loader/*.c)
HDRS_LOADER = $(wildcard loader/*.h) $(wildcard include/*.h)

# Configuration for runtime.
CODE_RUNTIME = $(wildcard runtime/*.c) $(wildcard runtime/*.S)
HDRS_RUNTIME = $(wildcard runmtime/*.h) $(wildcard include/*.h)

# Configure the includes.
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include 
LOADER_INCLUDES = -Iinclude -I$(ELF_LIB)/include -I$(ENCL_DRIVER)/include $(COMMON_INCLUDES)
WITH_PTS_INCLUDES = $(LOADER_INCLUDES) -I$(LIB_PT)/include

# Configs for dynamic library.
ELF_CONFIG= -Wl,-R $(ELF_LIB) -L$(ELF_LIB)

enclave_loader.so: $(CODE_LOADER) $(HDRS_LOADER)
	gcc -DTYCHE_USER_SPACE=1 -g $(WITH_PTS_INCLUDES) $(ELF_CONFIG) -shared -o $@ -fPIC $(CODE_LOADER) -lelf64

# This is mostly to make sure the code compiles.
# When used by an enclave, include the code directly as shown below.
enclave_runtime.so: $(CODE_RUNTIME) $(HDRS_RUNTIME)
	gcc -DTYCHE_USER_SPACE=1 -g $(COMMON_INCLUDES) -shared -o $@ -fPIC $(CODE_RUNTIME)

.PHONY: clean

clean:
	rm -rf enclave_loader.so
