all: encl_loader.so encl.so test-enclave test

# Dependencies for the build.
LIB_PT=../pts
DLL_LIB= ../dll
ELF_LIB=../elf64
CAPA_LIB=../capabilities
COMMON_LIB=../common
ENCL_DRIVER=../../drivers/enclave

# Configuration for loader version 1.
CODE_LOADER = $(wildcard loader/*.c)
HDRS_LOADER = $(wildcard loader/*.h) $(wildcard include/*.h)

# Configuration for the runtime.
CODE_RT = $(wildcard runtime/*.c) $(wildcard runtime/*.S)
HDRS_RT = $(wildcard runtime/*.h) $(wildcard include/*.h)

# Configuration for test.
CODE_TEST = tests/test.c
HDRS_TEST = $(wildcard include/*.h)

# Configuration for test-enclave
CODE_TEST_ENCLAVE = tests/enclave.c
HDRS_TEST_ENCLAVE = $(wildcard include/*.h)

# Configure the includes.
COMMON_INCLUDES = -Iinclude -I$(ELF_LIB)/include -I$(ENCL_DRIVER)/include -I$(DLL_LIB)/include -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include
WITH_PTS_INCLUDES = $(COMMON_INCLUDES) -I$(LIB_PT)/include

# Configs for dynamic library.
ELF_CONFIG= -Wl,-R $(ELF_LIB) -L$(ELF_LIB)

encl_loader.so: $(CODE_LOADER) $(HDRS_LOADER)
	gcc -DTYCHE_USER_SPACE=1 -g $(COMMON_INCLUDES) $(ELF_CONFIG) -shared -o $@ -fPIC $(CODE_LOADER) -lelf64

# The following targets won't be needed anymore.
encl.so: $(CODE_RT) $(HDRS_RT)
	gcc -g $(COMMON_INCLUDES) -shared -o $@ -fPIC $(CODE_RT)

test: $(CODE_TEST) $(HDRS_TEST)
	gcc -g $(COMMON_INCLUDES) -Wl,-R . -L./  $(ELF_CONFIG) -o $@ $(CODE_TEST) -lelf64 -l:encl_loader.so 

test-enclave: $(CODE_TEST_ENCLAVE) $(HDRS_TEST_ENCLAVE) encl_loader.so encl.so
	gcc -g -nostdlib -fPIC -o $@ $(CODE_TEST_ENCLAVE)

.PHONY: clean

clean:
	rm -rf encl_loader.so encl.so test test-enclave
