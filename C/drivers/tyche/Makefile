TARGET_MODULE:=tyche

## ———————————————————————— Use Tyche's Linux build ————————————————————————— ##
BUILDSYSTEM_DIR ?= ../../../builds/linux-x86/

LIB_PT=../../libraries/pts
LIB_DLL=../../libraries/dll
LIB_CAPA=../../libraries/capabilities
LIB_COMMON=../../libraries/common

# Capability sources.
CAPA_SRC=$(wildcard $(LIB_CAPA)/src/*.c)
CAPA_OBJS=$(patsubst %.c, %.o, $(CAPA_SRC))

# Page table sources.
PTS_SRC=$(wildcard $(LIB_PT)/src/*.c)
PTS_OBJS=$(patsubst %.c, %.o, $(PTS_SRC))

# Local files
LOCAL_SRC=$(wildcard src/*.c)
LOCAL_OBJS=$(patsubst %.c, %.o, $(LOCAL_SRC))

# Includes.
INCLUDES = -I$(src)/$(LIB_COMMON)/include -I$(src)/include -I$(src)/$(LIB_PT)/include -I$(src)/$(LIB_DLL)/include -I$(src)/$(LIB_CAPA)/include


# Kernel build system variables.
obj-m := $(TARGET_MODULE).o
$(TARGET_MODULE)-objs += src/driver.o src/ioctl.o src/domains.o src/capabilities.o
$(TARGET_MODULE)-objs += ../../libraries/pts/src/lib.o  ../../libraries/pts/src/x86_64_pt.o
$(TARGET_MODULE)-objs += ../../libraries/capabilities/src/ecs.o  ../../libraries/capabilities/src/lib.o  ../../libraries/capabilities/src/tyche_api.o

# TODO for some reason they don't like the variables.
# We can still use them to print though.
#$(TARGET_MODULE)-objs += $(LOCAL_OBJS) $(PTS_OBJS) $(CAPA_OBJS) 
ccflags-y += $(INCLUDES) 
## ——————————————————— Where to generate the build files ———————————————————— ##
PWD:=$(shell pwd)

## —————————————————————— Where to install the module ——————————————————————— ##
INSTALL_PATH ?= /tyche/tyche
DISK_PATH ?= /tmp/mount/tyche/drivers/

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
