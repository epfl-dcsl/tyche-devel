all: test

test: tests/main.c include/dll.h ../common/include/common.h
	gcc -DTYCHE_USER_SPACE=1 -ggdb -Iinclude/ -I../common/include -o $@ $<

.PHONY: clean

clean:
	rm test
