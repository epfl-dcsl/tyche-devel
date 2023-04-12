TARGET_MODULE:=tyche-capabilities

## ———————————————————————— Use Tyche's Linux build ————————————————————————— ##

BUILDSYSTEM_DIR ?= ../../../builds/linux-x86

## —————————————————————————— Library Dependencies —————————————————————————— ## 

LIB_DLL=../../libraries/dll
LIB_COMMON=../../libraries/common
LIB_CAPA=../../libraries/capabilities

# This apparently does not work if used to specify objects.
CAPA_SRCS=$(wildcard $(LIB_CAPA)/src/*.c)
CAPA_OBJS=$(patsubst %.c,%.o,$(CAPA_SRCS))

## ———————————————————————————————— Objects ————————————————————————————————— ##

$(TARGET_MODULE)-objs := src/driver.o $(LIB_CAPA)/src/ecs.o $(LIB_CAPA)/src/lib.o $(LIB_CAPA)/src/tyche_api.o 
obj-m := $(TARGET_MODULE).o
ccflags-y += -I$(src)/$(LIB_COMMON)/include -I$(src)/$(LIB_DLL)/include -I$(src)/$(LIB_CAPA)/include 

## ——————————————————— Where to generate the build files ———————————————————— ##

PWD:=$(shell pwd)

## —————————————————————— Where to install the module ——————————————————————— ##

INSTALL_PATH ?= /tyche/tyche-capabilities
DISK_PATH ?= /tmp/mount/tyche/tyche-capabilities

all:
	KBUILD_MODPOST_WARN=1 $(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) modules

.PHONY: install

install: all
	mkdir -p $(INSTALL_PATH)
	cp $(TARGET_MODULE).ko $(INSTALL_PATH)
	cp $(TARGET_MODULE).sh $(INSTALL_PATH)
	cp $(TARGET_MODULE).mod $(INSTALL_PATH)

install_disk: all
	mkdir -p $(DISK_PATH)
	cp $(TARGET_MODULE).ko $(DISK_PATH)
	cp $(TARGET_MODULE).sh $(DISK_PATH)
	cp $(TARGET_MODULE).mod $(DISK_PATH)

clean:
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) clean
