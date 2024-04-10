all: runbench 

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
LIB_PATH=../libraries/
LIB_DRIVER=../../linux/drivers/tyche/libraries/
DRIVERS_PATH=../../linux/drivers/
#LINKER_SCRIPT=../../../../../configs/riscv-linker-script-domain.x

## ——————————————————————————————— Libraries ———————————————————————————————— ##
SDK=$(LIB_PATH)/sdktyche
DLL_LIB= $(LIB_DRIVER)/dll
CAPA_LIB=$(LIB_DRIVER)/capabilities
COMMON_LIB=$(LIB_DRIVER)/common
ELF64=$(LIB_PATH)/elf64
PTS=$(LIB_PATH)/pts
DRIVER=$(DRIVERS_PATH)/tyche
CONTALLOC=$(DRIVERS_PATH)/contalloc

## ——————————————————————— Untrusted code and headers ——————————————————————— ##
CODE_BENCH=$(wildcard src/*.c)
HDRS_BENCH=$(wildcard include/*.h) $(wildcard src/*.h)

CODE_MOCK=$(wildcard mock/*.c)

# ——————————————————————————————— Domain code ———————————————————————————————— #

ifeq ($(ARCH), x86)
	CODE_DOM=domain/asm.S
else ifeq ($(ARCH), riscv)
	CODE_DOM=domain/riscv_asm.S
endif

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
CODE_CAPAS=$(wildcard $(CAPA_LIB)/src/*.c)
CODE_APP=$(CODE_ELF64) $(CODE_PTS) $(CODE_LOADER) $(CODE_CAPAS) $(CODE_BENCH)
HDRS_APP=$(HDRS_ELF64) $(HDRS_PTS) $(HDRS_LOADER) $(HDRS_BENCH)

## ———————————————————————— Trusted code and headers ———————————————————————— ##
CODE_TRANS=$(wildcard transition/*.c)
HDRS_TRANS=$(wildcard include/*.h)
CODE_TRANS+=$(CODE_CAPAS)
HDRS_TRANS += $(wildcard $(SDK)/include/*.h)

# Configuration for runtime.
ifeq ($(ARCH), x86)
	CODE_TRANS += $(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/asm.S)
	CODE_TRANS += transition/asm.S
else ifeq ($(ARCH), riscv)
	CODE_TRANS += $(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/riscv_asm.S)
	CODE_TRANS += transition/riscv_asm.S
endif

## ———————————————————————————————— Includes ———————————————————————————————— ##
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(ELF64)/include -I$(PTS)/include -I$(DRIVER)/include -I$(RB)/include

ifeq ($(KVM), 1)
	APP_INCLUDES+=-I$(CONTALLOC)/include 
endif

## ————————————————————— Configuration for the install —————————————————————— ##
ifeq ($(ARCH), x86)
DISK_PATH ?= /tmp/mount/tyche/benchmarks/
else ifeq ($(ARCH), riscv)
DISK_PATH ?= /tmp/ubuntu_riscv_mount/tyche/benchmarks/
endif

ifeq ($(ARCH), riscv)
	TYCHOOLS_ARG=--riscv-enabled
endif

TYCHOOLS_PATH ?= ../../crates/tychools/
## ———————————————————————————————— Targets ————————————————————————————————— ##

# Mock application to instrument with enclaves.
mock_app: $(CODE_MOCK)
	$(GCC) -g -static -o $@ $(CODE_MOCK)

# Mock code for the domain, it has two pages.
mock_dom: $(CODE_DOM)
	$(GCC) -g -nostdlib -static -o $@ $(CODE_DOM)

# Transition domain
trans_dom: $(CODE_TRANS) $(HDRS_TRANS)
	$(GCC) -DTYCHE_USER_SPACE=2 -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_TRANS)

sandboxes: mock_app mock_dom
	mkdir -p bin/sandboxes
	cargo -C $(TYCHOOLS_PATH) install --path . --locked -Z unstable-options
	tychools instrument -s manifests/sandboxes/8k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/sandboxes/12k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/sandboxes/128k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/sandboxes/256k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/sandboxes/512k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/sandboxes/1M.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/sandboxes/10M.json $(TYCHOOLS_ARG)

enclaves: mock_app mock_dom
	mkdir -p bin/enclaves
	cargo -C $(TYCHOOLS_PATH) install --path . --locked -Z unstable-options
	tychools instrument -s manifests/enclaves/8k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/enclaves/12k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/enclaves/128k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/enclaves/256k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/enclaves/512k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/enclaves/1M.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/enclaves/10M.json $(TYCHOOLS_ARG)

carve: mock_app mock_dom
	mkdir -p bin/carve
	cargo -C $(TYCHOOLS_PATH) install --path . --locked -Z unstable-options
	tychools instrument -s manifests/carve/8k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/carve/12k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/carve/128k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/carve/256k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/carve/512k.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/carve/1M.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/carve/10M.json $(TYCHOOLS_ARG)

transitions: mock_app trans_dom
	cargo -C $(TYCHOOLS_PATH) install --path . --locked -Z unstable-options
	tychools instrument -s manifests/enclaves/transition.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/sandboxes/transition.json $(TYCHOOLS_ARG)
	tychools instrument -s manifests/carve/transition.json $(TYCHOOLS_ARG)

runbench: $(CODE_APP) $(HDRS_APP) sandboxes enclaves carve transitions 
	$(GCC) -DTYCHE_USER_SPACE=1 $(LOADER_BACKEND) -g $(APP_INCLUDES) -static -o $@ $(CODE_APP)

install_disk: runbench 
	mkdir -p $(DISK_PATH)/
	cp -rt $(DISK_PATH)/ runbench bin config/Makefile

.PHONY: clean

clean:
	rm -rf bin/enclaves/ bin/sandboxes/ runbench mock_app mock_dom trans_dom
