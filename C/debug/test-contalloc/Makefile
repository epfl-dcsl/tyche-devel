all: test-contalloc

DISK_PATH ?= /tmp/mount/tyche/programs/debug

SRC = $(wildcard src/*)

test-contalloc: $(SRC)
	gcc -g -o $@ $(SRC)

install_disk: all 
	mkdir -p $(DISK_PATH)
	cp -t $(DISK_PATH) test-contalloc
