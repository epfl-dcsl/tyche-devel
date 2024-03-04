all: sdk_tyche_loader.so sdk_tyche_runtime.so sdk_tyche_loader_kvm.so

ARCH ?=x86
$(info ARCH="$(ARCH)")

GCC ?=gcc

ifeq ($(ARCH), x86)
	GCC = gcc
else ifeq ($(ARCH), riscv)
	GCC = riscv64-unknown-linux-gnu-gcc
endif

$(info GCC="$(GCC)")

# Dependencies for the build.
TYCHE_DRIVER=../../../linux/drivers/tyche
CONTALLOC_DRIVER=../../../linux/drivers/contalloc
LIB_PATH=$(TYCHE_DRIVER)/libraries/
LIB_PT=../pts
ELF_LIB= ../elf64
DLL_LIB=$(LIB_PATH)/dll
CAPA_LIB=$(LIB_PATH)/capabilities
COMMON_LIB=$(LIB_PATH)/common

# Configuration for loader.
CODE_LOADER = $(wildcard loader/*.c)
HDRS_LOADER = $(wildcard loader/*.h) $(wildcard include/*.h)

# Plaftorm specific files.
CODE_BACK_TYCHE = loader/backends/back_tyche.c
CODE_BACK_KVM = loader/backends/back_kvm.c

# Configuration for the elf64 library.
CODE_ELF64 = $(wildcard $(ELF_LIB)/src/*.c)
HDRS_ELF64 = $(wildcard $(ELF_LIB)/include/*.h)

# Configuration for runtime.
ifeq ($(ARCH), x86)
CODE_RUNTIME = $(wildcard runtime/*.c) $(wildcard runtime/asm.S)
HDRS_RUNTIME = $(wildcard include/*.h)
else ifeq ($(ARCH), riscv)
CODE_RUNTIME = $(wildcard runtime/*.c) $(wildcard runtime/riscv_asm.S)
HDRS_RUNTIME = $(wildcard include/*.h)
endif

# Capabilities implementation
CODE_CAPAS = $(wildcard $(CAPA_LIB)/src/*.c)

# Configure the includes.
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include 
LOADER_INCLUDES = -Iinclude -I$(ELF_LIB)/include $(COMMON_INCLUDES)
WITH_PTS_INCLUDES = $(LOADER_INCLUDES) -I$(LIB_PT)/include
TYCHE_LOADER_INCLUDES = $(WITH_PTS_INCLUDES) -I$(TYCHE_DRIVER)/include
KVM_LOADER_INCLUDES = $(WITH_PTS_INCLUDES) -I$(CONTALLOC_DRIVER)/include

# Configs for dynamic library.
ELF_CONFIG= -Wl,-R $(ELF_LIB) -L$(ELF_LIB)

sdk_tyche_loader.so: $(CODE_LOADER) $(CODE_BACK_TYCHE) $(HDRS_LOADER) $(CODE_ELF64) $(HDRS_ELF64)
	echo $(CODE_LOADER)
	make -B -C $(ELF_LIB)
	$(GCC) -DTYCHE_USER_SPACE=1 -g $(TYCHE_LOADER_INCLUDES) -shared -o $@ -fPIC $(CODE_LOADER) $(CODE_BACK_TYCHE) $(CODE_ELF64)

sdk_tyche_loader_kvm.so: $(CODE_LOADER) $(CODE_BACK_KVM) $(HDRS_LOADER) $(CODE_ELF64) $(HDRS_ELF64)
	echo $(CODE_LOADER)
	make -B -C $(ELF_LIB)
	$(GCC) -DTYCHE_USER_SPACE=1 -DRUN_WITH_KVM=1 -g $(KVM_LOADER_INCLUDES) -shared -o $@ -fPIC $(CODE_LOADER) $(CODE_BACK_KVM) $(CODE_ELF64)

# This is mostly to make sure the code compiles.
# When used by a domain, include the code directly as shown below.
sdk_tyche_runtime.so: $(CODE_RUNTIME) $(CODE_CAPAS) $(HDRS_RUNTIME)
	$(GCC) -DTYCHE_USER_SPACE=1 -g $(COMMON_INCLUDES) -shared -o $@ -fPIC $(CODE_RUNTIME) $(CODE_CAPAS)

.PHONY: clean

clean:
	rm -rf sdk_tyche_loader.so sdk_tyche_runtime.so sdk_tyche_loader_kvm.so
