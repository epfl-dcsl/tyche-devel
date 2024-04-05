all: test-encrypt-decrypt


BEAR_SSL_PATH = ../../../../vendor/BearSSL/

BEAR_SSL_LIB = $(BEAR_SSL_PATH)/build/libbearssl.a 

INCLUDES = -I$(BEAR_SSL_PATH)/inc/

SRCS = $(wildcard src/*.c) $(BEAR_SSL_LIB)

$(BEAR_SSL_LIB):
	make -C $(BEAR_SSL_PATH)

test-encrypt-decrypt: $(SRCS) 
	gcc -g $(INCLUDES) -o $@ $(SRCS) 
