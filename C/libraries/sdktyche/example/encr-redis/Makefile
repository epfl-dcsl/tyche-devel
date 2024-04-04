all: encr_redis_enclave

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
RB=$(LIB_PATH)/ringbuf

## ——————————————————————— Untrusted code and headers ——————————————————————— ##
CODE_UNTRUSTED=$(wildcard untrusted/*.c)
HDRS_UNTRUSTED=$(wildcard include/*.h)

CODE_MOCK=$(wildcard mock/*.c)

# ————————————————————————————— Ping & Pong Code ————————————————————————————— #
# Configuration for runtime.
ifeq ($(ARCH), x86)
	CODE_RUNTIME = $(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/asm.S)
	HDRS_RUNTIME = $(wildcard $(SDK)/include/*.h) 
else ifeq ($(ARCH), riscv)
	CODE_RUNTIME = $(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/riscv_asm.S)
	HDRS_RUNTIME = $(wildcard $(SDK)/include/*.h)
endif

CODE_ENCR = encr/encr.c $(CODE_RUNTIME) $(CODE_CAPAS)
HDRS_ENCR = include/encr_redis_app.h $(HDRS_RUNTIME)

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
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include -I$(RB)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(ELF64)/include -I$(PTS)/include -I$(DRIVER)/include 

APP_INCLUDES+=-I$(CONTALLOC)/include 

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

encr_redis_app: $(CODE_APP) $(HDRS_APP)
	$(GCC) -D_GNU_SOURCE -DTYCHE_USER_SPACE=1 $(LOADER_BACKEND) -g $(APP_INCLUDES) -o $@ $(CODE_APP)

mock_app: $(CODE_MOCK)
	$(GCC) -g -static -o $@ $(CODE_MOCK)

redis-server:
	test -s $(REDIS_SERVER_PATH) && cp $(REDIS_SERVER_PATH) $@

encr-server: $(CODE_ENCR) $(HDRS_ENCR)
	$(GCC) -DTYCHE_USER_SPACE=2 -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_ENCR)

encr_redis_enclave: encr_redis_app mock_app redis-server encr-server
	cargo -Z unstable-options -C $(TYCHOOLS_PATH) install --path . --locked
	tychools instrument -s manifests/redis.json
	tychools instrument -s manifests/encr.json
	rm mock_app redis-server encr-server

install_disk: all
	mkdir -p $(DISK_PATH)/encr-redis
	cp -t $(DISK_PATH)/encr-redis encr_redis_app encr_enclave redis_enclave

.PHONY: clean

clean:
	rm -f redis_enclave encr_redis_app encr_enclave redis-server encr-server mock_app
