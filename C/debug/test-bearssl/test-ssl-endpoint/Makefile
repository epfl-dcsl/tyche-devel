all: test-ssl-endpoint

DISK_PATH ?= /tmp/mount/tyche/programs/debug

BEAR_SSL_PATH = ../../../../vendor/BearSSL/

BEAR_SSL_LIB = $(BEAR_SSL_PATH)/build/libbearssl.a 

INCLUDES = -I$(BEAR_SSL_PATH)/inc/

SRCS = $(wildcard src/*.c) $(BEAR_SSL_LIB)

$(BEAR_SSL_LIB):
	make -C $(BEAR_SSL_PATH) CFLAGS="-g -fno-stack-protector -fPIC"

test-ssl-endpoint: $(SRCS) 
	gcc -g $(INCLUDES) -o $@ $(SRCS)

install_disk: all
	mkdir -p $(DISK_PATH)
	cp -t $(DISK_PATH) test-ssl-endpoint $(BEAR_SSL_PATH)/build/brssl config/server.cert client.sh
