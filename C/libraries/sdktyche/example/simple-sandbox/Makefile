all: app sandbox instrument

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
CODE_APPLICATION=$(wildcard application/*.c)
HDRS_APPLICATION=$(wildcard include/*.h)

## —————————————————————— Sandboxed code and headers ———————————————————————— ##
CODE_SANDBOXED=$(wildcard sandboxed/*.c)
HDRS_SANDBOXED=$(wildcard include/*.h)

## ———————————————————————— Runtime code and headers ———————————————————————— ##
CODE_RUNTIME=$(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/*.S)
HDRS_RUNTIME= $(wildcard $(SDK)/include/*.h)
# ———————————————————————— Code capabilities library ————————————————————————— #
CODE_CAPAS=$(wildcard $(CAPA_LIB)/src/*.c)
## ———————————————————————— Loader code and headers ————————————————————————— ##
CODE_LOADER=$(wildcard $(SDK)/loader/*.c) $(wildcard $(SDK)/loader/*.S)
HDRS_LOADER=$(wildcard $(SDK)/include/*.h)

ifeq ($(KVM), 1)
	CODE_LOADER+=$(SDK)/loader/backends/back_kvm.c
else
	CODE_LOADER+=$(SDK)/loader/backends/back_tyche.c
endif

## ————————————————————————— ELF64 code and headers ————————————————————————— ##
CODE_ELF64=$(wildcard $(ELF64)/src/*.c)
HDRS_ELF64=$(wildcard $(ELF64)/include/*.h)

## —————————————————————— Page table code and headers ——————————————————————— ##
CODE_PTS=$(wildcard $(PTS)/src/*.c)
HDRS_PTS=$(wildcard $(PTS)/include/*.h)

## —————————————————————— Application code and headers —————————————————————— ##
CODE_APP=$(CODE_ELF64) $(CODE_PTS) $(CODE_LOADER) $(CODE_APPLICATION)
HDRS_APP=$(HDRS_ELF64) $(HDRS_PTS) $(HDRS_LOADER) $(HDRS_APPLICATION)

## ———————————————————————— Sandbox code and headers ———————————————————————— ##
CODE_SANDBOX=$(CODE_RUNTIME) $(CODE_SANDBOXED) $(CODE_CAPAS)
HDRS_SANDBOX=$(HDRS_RUNTIME) $(HDRS_SANDBOXED)

## ———————————————————————————————— Includes ———————————————————————————————— ##
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(ELF64)/include -I$(PTS)/include -I$(DRIVER)/include

ifeq ($(KVM), 1)
	APP_INCLUDES += -I$(CONTALLOC)/include
endif

## ————————————————————— Configuration for the install —————————————————————— ##
DISK_PATH ?= /tmp/mount/tyche/programs 

TYCHOOLS_PATH ?= ../../../../../crates/tychools/ 

## ———————————————————————————————— Targets ————————————————————————————————— ##

app: $(CODE_APP) $(HDRS_APP) 
	gcc -DTYCHE_USER_SPACE=1 $(LOADER_BACKEND) -g $(APP_INCLUDES) -o $@ $(CODE_APP)

sandbox: $(CODE_SANDBOX) $(HDRS_SANDBOX)
	gcc -DTYCHE_USER_SPACE=2 -DTYCHOOLS=1 -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_SANDBOX)

instrument: app sandbox 
	cargo -Z unstable-options -C $(TYCHOOLS_PATH) install --path . --locked
	tychools instrument -s manifests/default.json 
	chmod +x application_with_sandbox
	rm app sandbox

install_disk: all 
	mkdir -p $(DISK_PATH)
	cp -t $(DISK_PATH) application_with_sandbox 


.PHONY: clean

clean:
	rm -rf app sandbox application_with_sandbox
