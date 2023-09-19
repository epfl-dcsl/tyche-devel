all: test-trt


## ————————————————————————————————— Paths —————————————————————————————————— ##
LIB_PATH=../
DRIVERS_PATH=../../drivers/
LIB_BRICKS_PATH = ../../../target/x86_64-unknown-linux-gnu/release
BRICKS_PATH = ../../../crates/bricks
BRICKS = bricks
## ——————————————————————————————— Libraries ———————————————————————————————— ##
SDK=$(LIB_PATH)/sdktyche
DLL_LIB= $(LIB_PATH)/dll
CAPA_LIB=$(LIB_PATH)/capabilities
COMMON_LIB=$(LIB_PATH)/common
ELF64=$(LIB_PATH)/elf64
PTS=$(LIB_PATH)/pts
DRIVER=$(DRIVERS_PATH)/tyche

## ———————————————————————————————— Sources ————————————————————————————————— ##
CODE_TRT=$(wildcard rt/*.c) $(wildcard rt/*.S)
HDRS_TRT=$(wildcard include/*.h)
RELOC=linkers/custom.ld

## ————————————————————————— Load code and headers —————————————————————————— ##
CODE_LOAD=$(wildcard load/*.c)

## ———————————————————————— Loader code and headers ————————————————————————— ##
CODE_LOADER=$(wildcard $(SDK)/loader/*.c) $(wildcard $(SDK)/loader/*.S)
HDRS_LOADER=$(wildcard $(SDK)/include/*.h)

## ————————————————————————— ELF64 code and headers ————————————————————————— ##
CODE_ELF64=$(wildcard $(ELF64)/src/*.c)
HDRS_ELF64=$(wildcard $(ELF64)/include/*.h)

## —————————————————————— Page table code and headers ——————————————————————— ##
CODE_PTS=$(wildcard $(PTS)/src/*.c)
HDRS_PTS=$(wildcard $(PTS)/include/*.h)

## —————————————————————— Application code and headers —————————————————————— ##
CODE_APP=$(CODE_ELF64) $(CODE_PTS) $(CODE_LOADER) $(CODE_LOAD)
HDRS_APP=$(HDRS_ELF64) $(HDRS_PTS) $(HDRS_LOADER)

## ——————————————————————— Compilation Configuration ———————————————————————— ##
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(ELF64)/include -I$(PTS)/include -I$(DRIVER)/include
TRT_INCLUDES = -Iinclude -I$(COMMON_LIB)/include
## ————————————————————— Configuration for the install —————————————————————— ##
DISK_PATH ?= /tmp/mount/tyche/programs

TYCHOOLS_PATH ?= ../../../crates/tychools/ 

## ———————————————————————————————— Targets ————————————————————————————————— ##

trt-user: $(CODE_TRT) $(HDRS_TRT) $(RELOC)
	RUSTFLAGS='-C link-arg=-Tconfigs/x86-linker-rust.x -C link-arg=-nostartfiles -C relocation-model=static' cargo build --manifest-path $(BRICKS_PATH)/Cargo.toml -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem --target=x86_64-unknown-linux-gnu --release
	gcc --entry=user_main_wrapper -DTYCHE_USER_SPACE=1 -T $(RELOC) -g $(TRT_INCLUDES) -Xlinker --no-relax -nostdlib -static -o $@ $(CODE_TRT)
	chmod +x trt-user

loader: $(CODE_APP) $(HDRS_APP)
	gcc -DTYCHE_USER_SPACE=1 -g $(APP_INCLUDES) -o $@ $(CODE_APP)

test-trt : loader trt-user
	cargo -C $(TYCHOOLS_PATH) install --path . --locked
	tychools instrument -s manifests/user_kernel.json
	chmod +x test-trt
	rm -rf loader trt-user

install_disk: all
	mkdir -p $(DISK_PATH)
	cp -t $(DISK_PATH) test-trt

.PHONY: clean

clean:
	rm -rf trt loader test-trt trt-user
