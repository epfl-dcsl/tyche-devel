TARGET_MODULE:=tyche_enclave

## ———————————————————————— Use Tyche's Linux build ————————————————————————— ##
BUILDSYSTEM_DIR ?= ../../../builds/linux-x86/

LIB_PT=../../libraries/pts
LIB_DLL=../../libraries/dll
LIB_CAPA=../../libraries/capabilities
LIB_COMMON=../../libraries/common


$(TARGET_MODULE)-objs := src/driver.o src/ioctl.o src/internal/enclave.o src/internal/process.o src/internal/mapper.o src/internal/tyche_vmcall.o src/dbg/dbg.o $(LIB_PT)/src/lib.o $(LIB_PT)/src/x86_64_pt.o
obj-m := $(TARGET_MODULE).o
#$(TARGET_MODULE)-obs += $(LIB_PT)/libpts.o
ccflags-y += -I$(src)/$(LIB_COMMON)/include -I$(src)/include -I$(src)/$(LIB_PT)/include -I$(src)/$(LIB_DLL)/include -I$(src)/$(LIB_CAPA)/include

## ——————————————————— Where to generate the build files ———————————————————— ##
PWD:=$(shell pwd)


## —————————————————————— Where to install the module ——————————————————————— ##
INSTALL_PATH ?= /tyche/tyche-enclave
DISK_PATH ?= /tmp/mount/tyche/tyche-enclave

all : 
# run kernel build system to make module
	KBUILD_MODPOST_WARN=1 $(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) modules

.PHONY: install 

install: all
	mkdir -p $(INSTALL_PATH)
	cp $(TARGET_MODULE).ko $(INSTALL_PATH) 
	cp $(TARGET_MODULE).sh $(INSTALL_PATH)
	cp $(TARGET_MODULE).mod $(INSTALL_PATH)
	cp Module.symvers $(INSTALL_PATH)
	cp modules.order $(INSTALL_PATH)

install_disk: all
	mkdir -p $(DISK_PATH)
	cp $(TARGET_MODULE).ko $(DISK_PATH)
	cp $(TARGET_MODULE).sh $(DISK_PATH)
	cp $(TARGET_MODULE).mod $(DISK_PATH)
	cp Module.symvers $(DISK_PATH)
	cp modules.order $(DISK_PATH)


clean:
# run kernel build system to cleanup in current directory
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) clean
