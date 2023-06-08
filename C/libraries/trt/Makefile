all: trt loader trt_relocated


## ————————————————————————————————— Paths —————————————————————————————————— ##
LIB_PATH=../
DRIVERS_PATH=../../drivers/

## ——————————————————————————————— Libraries ———————————————————————————————— ##
SDK=$(LIB_PATH)/sdkenclave
DLL_LIB= $(LIB_PATH)/dll
CAPA_LIB=$(LIB_PATH)/capabilities
COMMON_LIB=$(LIB_PATH)/common
ELF64=$(LIB_PATH)/elf64
PTS=$(LIB_PATH)/pts
DRIVER=$(DRIVERS_PATH)/tyche

## ———————————————————————————————— Sources ————————————————————————————————— ##
ASM_TRT=$(wildcard rt/*.asm)
ASO_TRT=$(patsubst %.asm, %_asm.o, $(ASM_TRT))
CODE_TRT=$(wildcard rt/*.c) $(wildcard rt/*.S) $(ASO_TRT) 
HDRS_TRT=$(wildcard include/*.h)
RELOC=linkers/custom.ld

## —————————————————————— External Sources and Headers —————————————————————— ##
CODE_RUNTIME=$(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/*.S)
HDRS_RUNTIME= $(wildcard $(SDK)/include/*.h)

## ————————————————————————— Load code and headers —————————————————————————— ##
CODE_LOAD=$(wildcard load/*.c)
HDRS_LOAD=$(wildcard include/*.h)

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
HDRS_APP=$(HDRS_ELF64) $(HDRS_PTS) $(HDRS_LOADER) $(HDRS_LOAD)

## ——————————————————————— Compilation Configuration ———————————————————————— ##
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(ELF64)/include -I$(PTS)/include -I$(DRIVER)/include

## ————————————————————— Configuration for the install —————————————————————— ##
DISK_PATH ?= /tmp/mount/tyche/programs

## ———————————————————————————————— Targets ————————————————————————————————— ##
%_asm.o : %.asm
	nasm -w+all -f elf64 $< -o $@


trt: $(CODE_TRT) $(CODE_RUNTIME) $(HDRS_TRT) $(HDRS_RUNTIME)
	gcc -DTYCHE_USER_SPACE=1 -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_RUNTIME) $(CODE_TRT)
	@rm $(ASO_TRT)

trt_relocated: $(CODE_TRT) $(CODE_RUNTIME) $(HDRS_TRT) $(HDRS_RUNTIME) $(RELOC)
	gcc -DTYCHE_USER_SPACE=1 -T $(RELOC) -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_RUNTIME) $(CODE_TRT)
	@rm $(ASO_TRT)


loader: $(CODE_APP) $(HDRS_APP)
	gcc -DTYCHE_USER_SPACE=1 -g $(APP_INCLUDES) -o $@ $(CODE_APP)

install_disk: all
	mkdir -p $(DISK_PATH)
	cp -t $(DISK_PATH) loader trt

.PHONY: clean

clean:
	rm trt loader trt_relocated
