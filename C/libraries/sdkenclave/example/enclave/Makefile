all: enclave

# Libraries
SDK=../../
DLL_LIB= ../../../dll
CAPA_LIB=../../../capabilities
COMMON_LIB=../../../common

# Code and headers
CODE_ENCLAVE=$(wildcard src/*.c)
HDRS_ENCLAVE=$(wildcard include/*.h)

CODE_RUNTIME=$(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/*.S)
HDRS_RUNTIME= $(wildcard $(SDK)/include/*.h)

# Includes
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 

enclave: $(CODE_ENCLAVE) $(CODE_RUNTIME) $(HDRS_ENCLAVE) $(HDRS_RUNTIME)
	gcc -DTYCHE_USER_SPACE=1 -DDEFAULT_SHARED_BUFFER=1 -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_ENCLAVE) $(CODE_RUNTIME)

.PHONY: clean

clean:
	rm enclave
