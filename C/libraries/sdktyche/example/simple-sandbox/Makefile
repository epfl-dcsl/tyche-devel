all: app sandbox instrument


## ————————————————————————————————— Paths —————————————————————————————————— ##
LIB_PATH=../../../
DRIVERS_PATH=../../../../drivers/

## ——————————————————————————————— Libraries ———————————————————————————————— ##
SDK=$(LIB_PATH)/sdktyche
DLL_LIB= $(LIB_PATH)/dll
CAPA_LIB=$(LIB_PATH)/capabilities
COMMON_LIB=$(LIB_PATH)/common
ELF64=$(LIB_PATH)/elf64
PTS=$(LIB_PATH)/pts
DRIVER=$(DRIVERS_PATH)/tyche

## ————————————————————— Application code and headers ——————————————————————— ##
CODE_APPLICATION=$(wildcard application/*.c)
HDRS_APPLICATION=$(wildcard include/*.h)

## —————————————————————— Sandboxed code and headers ———————————————————————— ##
CODE_SANDBOXED=$(wildcard sandboxed/*.c)
HDRS_SANDBOXED=$(wildcard include/*.h)

## ———————————————————————— Runtime code and headers ———————————————————————— ##
CODE_RUNTIME=$(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/*.S)
HDRS_RUNTIME= $(wildcard $(SDK)/include/*.h)

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
CODE_APP=$(CODE_ELF64) $(CODE_PTS) $(CODE_LOADER) $(CODE_APPLICATION)
HDRS_APP=$(HDRS_ELF64) $(HDRS_PTS) $(HDRS_LOADER) $(HDRS_APPLICATION)

## ———————————————————————— Sandbox code and headers ———————————————————————— ##
CODE_SANDBOX=$(CODE_RUNTIME) $(CODE_SANDBOXED)
HDRS_SANDBOX=$(HDRS_RUNTIME) $(HDRS_SANDBOXED)

## ———————————————————————————————— Includes ———————————————————————————————— ##
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(ELF64)/include -I$(PTS)/include -I$(DRIVER)/include

## ————————————————————— Configuration for the install —————————————————————— ##
DISK_PATH ?= /tmp/mount/tyche/programs 

TYCHOOLS_PATH ?= ../../../../../crates/tychools/ 

## ———————————————————————————————— Targets ————————————————————————————————— ##

app: $(CODE_APP) $(HDRS_APP) 
	gcc -DTYCHE_USER_SPACE=1 -g $(APP_INCLUDES) -o $@ $(CODE_APP)

sandbox: $(CODE_SANDBOX) $(HDRS_SANDBOX)
	gcc -DTYCHE_USER_SPACE=1 -DTYCHOOLS=1 -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_SANDBOX)

instrument: app sandbox 
	cargo -C $(TYCHOOLS_PATH) install --path . --locked
	tychools instrument -s manifests/default.json 
	chmod +x application_with_sandbox
	rm app sandbox

install_disk: all 
	mkdir -p $(DISK_PATH)
	cp -t $(DISK_PATH) application_with_sandbox 


.PHONY: clean

clean:
	rm -rf app sandbox application_with_sandbox
