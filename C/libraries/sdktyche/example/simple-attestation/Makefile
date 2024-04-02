all: simple_attestation

ARCH ?=x86
GCC ?=gcc
KVM ?=1

ifeq ($(ARCH), x86)
        GCC = gcc
else ifeq ($(ARCH), riscv)
        GCC = riscv64-unknown-linux-gnu-gcc
endif

ifeq ($(KVM), 1)
	LOADER_BACKEND = -DRUN_WITH_KVM=1
endif


## ————————————————————————————————— Paths —————————————————————————————————— ##

LIB_PATH=../../../
LIB_DRIVER=../../../../../linux/drivers/tyche/libraries/
DRIVERS_PATH=../../../../../linux/drivers/
LINKER_SCRIPT=../../../../../configs/riscv-linker-script-domain.x

## ——————————————————————————————— Libraries ———————————————————————————————— ##

SDK=$(LIB_PATH)/sdktyche
DLL_LIB= $(LIB_DRIVER)/dll
CAPA_LIB=$(LIB_DRIVER)/capabilities
COMMON_LIB=$(LIB_DRIVER)/common
ELF64=$(LIB_PATH)/elf64
PTS=$(LIB_PATH)/pts
DRIVER=$(DRIVERS_PATH)/tyche
CONTALLOC=$(DRIVERS_PATH)/contalloc

## ————————————————————— Application code and headers ——————————————————————— ##

CODE_APP=$(wildcard src/*.c)

## —————————————————————— Sandboxed code and headers ———————————————————————— ##

CODE_SANDBOXED=$(wildcard sandboxed/*.c)
HDRS_SANDBOXED=$(wildcard include/*.h)

# ———————————————————————— Code capabilities library ————————————————————————— #

CODE_CAPAS=$(wildcard $(CAPA_LIB)/src/*.c)

## ———————————————————————————————— Includes ———————————————————————————————— ##

COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(DRIVER)/include -I$(SDK)/loader -I$(LIB_PATH)/elf64/include -I$(DRIVER)/include

ifeq ($(KVM), 1)
	APP_INCLUDES += -I$(CONTALLOC)/include
endif

## ————————————————————— Configuration for the install —————————————————————— ##

DISK_PATH ?= /tmp/mount/tyche/programs 

TYCHOOLS_PATH ?= ../../../../../crates/tychools/ 

## ———————————————————————————————— Targets ————————————————————————————————— ##

simple_attestation: $(CODE_APP) $(HDRS_APP) 
	gcc -DTYCHE_USER_SPACE=1 $(LOADER_BACKEND) -g $(APP_INCLUDES) -o $@ $(CODE_APP)

install_disk: simple_attestation
	mkdir -p $(DISK_PATH)
	cp -t $(DISK_PATH) simple_attestation

.PHONY: clean

clean:
	rm -rf simple_attestation
