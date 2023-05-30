all: trt


## ———————————————————————————————— Sources ————————————————————————————————— ##
CODE_TRT=$(wildcard src/*.c) $(wildcard src/*.S) idt_asm.o 
HDRS_TRT=$(wildcard include/*.h)


## ——————————————————————————————— Libraries ———————————————————————————————— ##
LIB_PATH=../
DRIVERS_PATH=../../drivers/

SDK=$(LIB_PATH)/sdkenclave
DLL_LIB= $(LIB_PATH)/dll
CAPA_LIB=$(LIB_PATH)/capabilities
COMMON_LIB=$(LIB_PATH)/common

## —————————————————————— External Sources and Headers —————————————————————— ##
CODE_RUNTIME=$(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/*.S)
HDRS_RUNTIME= $(wildcard $(SDK)/include/*.h)

## ——————————————————————— Compilation Configuration ———————————————————————— ##
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 

idt_asm.o: src/idt.asm
	nasm -w+all -f elf64 $< -o $@

trt: $(CODE_TRT) $(CODE_RUNTIME) $(HDRS_TRT) $(HDRS_RUNTIME)
	gcc -DTYCHE_USER_SPACE=1 -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_RUNTIME) $(CODE_TRT)

.PHONY: clean

clean:
	rm trt
