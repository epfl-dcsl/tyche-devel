all: malicious 

# Libraries
LIB_PATH=../../../
DRIVERS_PATH=../../../../drivers/

SDK=$(LIB_PATH)/sdkenclave
DLL_LIB= $(LIB_PATH)/dll
CAPA_LIB=$(LIB_PATH)/capabilities
COMMON_LIB=$(LIB_PATH)/common

ELF64=$(LIB_PATH)/elf64
PTS=$(LIB_PATH)/pts
DRIVER=$(DRIVERS_PATH)/tyche

# App Code and headers
CODE_APP=$(wildcard untrusted/*.c)
HDRS_APP=$(wildcard include/*.h)

# Includes
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(ELF64)/include -I$(PTS)/include -I$(DRIVER)/include

# Dynamic libraries
DYNS= -Wl,-R ./libs  -L./libs/ -l:enclave_loader.so -lpts

# Installation configuration.
DISK_PATH ?= /tmp/mount/tyche/programs 

# Rules

malicious: $(CODE_APP) $(HDRS_APP) 
	mkdir -p libs
	make -C $(SDK)
	make -C $(ELF64)
	make -C $(PTS)
	cp $(SDK)/enclave_loader.so libs/
	cp $(PTS)/libpts.a libs/
	gcc -DTYCHE_USER_SPACE=1 -g $(APP_INCLUDES) -o $@ $(CODE_APP) $(DYNS)

install_disk: all
	mkdir -p $(DISK_PATH)
	cp -r libs $(DISK_PATH)
	cp -t $(DISK_PATH) malicious 


.PHONY: clean

clean:
	rm malicious 
