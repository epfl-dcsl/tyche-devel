all: attestation_enclave

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

## ——————————————————————— Untrusted code and headers ——————————————————————— ##
CODE_UNTRUSTED=$(wildcard untrusted/*.c)
HDRS_UNTRUSTED=$(wildcard include/*.h)

## ———————————————————————— Trusted code and headers ———————————————————————— ##
CODE_TRUSTED=$(wildcard trusted/*.c)
HDRS_TRUSTED=$(wildcard include/*.h)

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
CODE_APP=$(CODE_ELF64) $(CODE_PTS) $(CODE_LOADER) $(CODE_UNTRUSTED)
HDRS_APP=$(HDRS_ELF64) $(HDRS_PTS) $(HDRS_LOADER) $(HDRS_UNTRUSTED)

## —————————————————————— Capability lib code and headers —————————————————————— ##
CAPA_CODE = $(wildcard $(CAPA_LIB)/src/*.c)

## ———————————————————————— Enclave code and headers ———————————————————————— ##
CODE_ENCLAVE=$(CODE_RUNTIME) $(CODE_TRUSTED) $(CAPA_CODE)
HDRS_ENCLAVE=$(HDRS_RUNTIME) $(HDRS_TRUSTED)

## ———————————————————————————————— Includes ———————————————————————————————— ##
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(ELF64)/include -I$(PTS)/include -I$(DRIVER)/include

## ————————————————————— Configuration for the install —————————————————————— ##
DISK_PATH ?= /tmp/mount/tyche/programs 

TYCHOOLS_PATH ?= ../../../../../crates/tychools/ 

## ———————————————————————————————— Targets ————————————————————————————————— ##

app: $(CODE_APP) $(HDRS_APP) 
	gcc -DTYCHE_USER_SPACE=1 -g $(APP_INCLUDES) -o $@ $(CODE_APP)

enclave: $(CODE_ENCLAVE) $(HDRS_ENCLAVE)
	gcc -DTYCHE_USER_SPACE=1 -DTYCHE_ENCLAVE=1 -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_ENCLAVE)

simple_enclave: app enclave
	cargo -C $(TYCHOOLS_PATH) install --path .
	tychools instrument -s manifests/default.json 
	chmod +x simple_enclave
	rm app enclave

enclave_iso: app enclave
	cargo -C $(TYCHOOLS_PATH) install --path .
	tychools instrument -s manifests/enclave_iso.json 
	chmod +x enclave_iso
	rm app enclave

attestation_enclave: app enclave
	cargo -C $(TYCHOOLS_PATH) install --path . --locked
	tychools instrument -s manifests/default.json 
	chmod +x simple_enclave
	tychools instrument -s manifests/enclave_iso.json 
	chmod +x enclave_iso
	rm app enclave

install_disk: all 
	mkdir -p $(DISK_PATH)
	cp -t $(DISK_PATH) simple_enclave 
	cp -t $(DISK_PATH) enclave_iso

.PHONY: clean

clean:
	rm simple_enclave 
	rm enclave_iso
