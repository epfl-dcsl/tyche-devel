all: libelf64.so test_elf64

COMMON=../common/
FILES=src/lib.c include/elf64.h $(COMMON)/include/common.h
INCLUDES= -I$(COMMON)/include -Iinclude/

libelf64.so: $(FILES) 
	gcc -DTYCHE_USER_SPACE=1 -g -shared $(INCLUDES) -o $@ -fPIC src/lib.c 

test_elf64: tests/test.c libelf64.so
	gcc -DTYCHE_USER_SPACE=1 -g -Iinclude/ -I$(COMMON)/include -Wl,-R . -L. tests/test.c -o $@ -lelf64

.PHONY: clean

clean:
	rm libelf64.so test_elf64
