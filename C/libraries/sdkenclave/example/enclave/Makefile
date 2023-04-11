all: app enclave

# Libraries
SDK=../../
DLL_LIB= ../../../dll
CAPA_LIB=../../../capabilities
COMMON_LIB=../../../common

ELF64=../../../elf64
PTS=../../../pts
DRIVER=../../../../drivers/tyche

# App Code and headers
CODE_APP=$(wildcard untrusted/*.c)
HDRS_APP=$(wildcard include/*.h)

# Enclave Code and headers
CODE_ENCLAVE=$(wildcard trusted/*.c)
HDRS_ENCLAVE=$(wildcard include/*.h)

CODE_RUNTIME=$(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/*.S)
HDRS_RUNTIME= $(wildcard $(SDK)/include/*.h)

# Includes
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(ELF64)/include -I$(PTS)/include -I$(DRIVER)/include

# Dynamic libraries
DYNS= -l:enclave_loader.so -lelf64 -lpts

app: $(CODE_APP) $(HDRS_APP) 
	mkdir -p libs
	make -C $(SDK)
	make -C $(ELF64)
	make -C $(PTS)
	cp $(ELF64)/libelf64.so libs/
	cp $(SDK)/enclave_loader.so libs/
	cp $(PTS)/libpts.a libs/
	gcc -DTYCHE_USER_SPACE=1 -g $(APP_INCLUDES) -Wl,-R ./libs  -L./libs/ -o $@ $(CODE_APP) $(DYNS)



enclave: $(CODE_ENCLAVE) $(CODE_RUNTIME) $(HDRS_ENCLAVE) $(HDRS_RUNTIME)
	gcc -DTYCHE_USER_SPACE=1 -DDEFAULT_SHARED_BUFFER=1 -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_ENCLAVE) $(CODE_RUNTIME)

.PHONY: clean

clean:
	rm app enclave
