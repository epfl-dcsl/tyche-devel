all: ping_pong ping pong ping_pong_enclave 

ARCH ?=x86
GCC ?=gcc
KVM ?=1

ifeq ($(ARCH), x86)
        GCC = gcc
else ifeq ($(ARCH), riscv)
        GCC = riscv64-unknown-linux-gnu-gcc
		KVM = 0
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
RINGBUF=$(LIB_PATH)/ringbuf

## ——————————————————————— Untrusted code and headers ——————————————————————— ##
CODE_UNTRUSTED=$(wildcard untrusted/*.c)
HDRS_UNTRUSTED=$(wildcard include/*.h)

CODE_MOCK=mock/main.c

# ————————————————————————————— Ping & Pong Code ————————————————————————————— #
# Configuration for runtime.
ifeq ($(ARCH), x86)
	CODE_RUNTIME = $(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/asm.S)
	HDRS_RUNTIME = $(wildcard $(SDK)/include/*.h) 
else ifeq ($(ARCH), riscv)
	CODE_RUNTIME = $(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/riscv_asm.S)
	HDRS_RUNTIME = $(wildcard $(SDK)/include/*.h)
endif

CODE_PING = trusted/ping.c $(CODE_RUNTIME) $(CODE_CAPAS)
HDRS_PING = include/ping_pong.h $(HDRS_RUNTIME)

CODE_PONG = trusted/pong.c $(CODE_RUNTIME) $(CODE_CAPAS)
HDRS_PONG = include/ping_pong.h $(HDRS_RUNTIME)

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
CODE_APP=$(CODE_ELF64) $(CODE_PTS) $(CODE_LOADER) $(CODE_UNTRUSTED)
HDRS_APP=$(HDRS_ELF64) $(HDRS_PTS) $(HDRS_LOADER) $(HDRS_UNTRUSTED)

## ———————————————————————————————— Includes ———————————————————————————————— ##
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include -I$(RINGBUF)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(ELF64)/include -I$(PTS)/include -I$(DRIVER)/include

ifeq ($(KVM), 1)
	APP_INCLUDES+=-I$(CONTALLOC)/include 
endif

## ————————————————————— Configuration for the install —————————————————————— ##
ifeq ($(ARCH), x86)
DISK_PATH ?= /tmp/mount/tyche/programs 
else ifeq ($(ARCH), riscv)
DISK_PATH ?= /tmp/ubuntu_riscv_mount/tyche/programs
endif

TYCHOOLS_PATH ?= ../../../../../crates/tychools/

# TODO: make that clean
REDIS_SERVER_PATH ?= ../../../../../../tyche-experiment-redis/tyche-redis/src/redis-server

## ———————————————————————————————— Targets ————————————————————————————————— ##

ping_pong: $(CODE_APP) $(HDRS_APP) 
	$(GCC) -DTYCHE_USER_SPACE=1 $(LOADER_BACKEND) -g $(APP_INCLUDES) -o $@ $(CODE_APP)

mock_app: $(CODE_MOCK)
	$(GCC) -g -static -o $@ $(CODE_MOCK)

ping: $(CODE_PING) $(HDRS_PING)
	$(GCC) -DTYCHE_USER_SPACE=2 -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_PING)

pong: $(CODE_PONG) $(HDRS_PING)
	$(GCC) -DTYCHE_USER_SPACE=2 -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_PONG)

ping_pong_enclave: mock_app ping pong
	cargo -Z unstable-options -C $(TYCHOOLS_PATH) install --path . --locked
	tychools instrument -s manifests/ping.json
	tychools instrument -s manifests/pong.json
	rm -f ping pong mock_app

install_disk: all 
	mkdir -p $(DISK_PATH)/ping-pong
	cp -t $(DISK_PATH)/ping-pong ping_pong ping_enclave pong_enclave 

.PHONY: clean

clean:
	rm -f ping pong ping_enclave pong_enclave mock_app 
