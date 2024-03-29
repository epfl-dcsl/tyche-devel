all: libpts.a test_x86 test_riscv48

ARCH ?=x86

ifeq ($(ARCH), x86)
        GCC = gcc
else ifeq ($(ARCH), riscv)
        GCC = riscv64-unknown-linux-gnu-gcc
endif

# External libraries.
COMMON_LIB=../../../linux/drivers/tyche/libraries/common

# Configuration for the library.
CODE_PTS=$(wildcard src/*.c)
HDRS_PTS=$(wildcard include/*.h)
OBJS_PTS=$(patsubst %.c, %.o, $(CODE_PTS))

# Configuration for test.
CODE_TEST=$(wildcard tests/*.c) libpts.a

# Include configuration.
INCLUDES=-Iinclude/ -I$(COMMON_LIB)/include

#$(OBJS_PTS) : $(CODE_PTS)
#	gcc -DTYCHE_USER_SPACE=1 -g -nostdlib -c $(INCLUDES) -o $@ $<

#libpts.a: $(CODE_PTS) $(HDRS_PTS) $(OBJS_PTS)
	#ar rcs $@ $(OBJS_PTS)
	#rm $(OBJS_PTS)

libpts.a: $(CODE_PTS) $(HDRS_PTS)
	$(GCC) -DTYCHE_USER_SPACE=1 -g -nostdlib -c $(INCLUDES) -o pts.o src/lib.c
	$(GCC) -DTYCHE_USER_SPACE=1 -g -nostdlib -c $(INCLUDES) -o x86.o src/x86_64_pt.c
	$(GCC) -DTYCHE_USER_SPACE=1 -g -nostdlib -c $(INCLUDES) -o riscv.o src/riscv48_pt.c
	ar rcs $@ pts.o x86.o riscv.o
	rm pts.o x86.o riscv.o

test_x86: tests/test_x86.c libpts.a
	$(GCC) -DTYCHE_USER_SPACE=1 -g $(INCLUDES) -L. -o $@ $< -l:libpts.a 

test_riscv48: tests/test_riscv48.c libpts.a
	$(GCC) -DTYCHE_USER_SPACE=1 -g $(INCLUDES) -L. -o $@ $< -l:libpts.a 

.PHONY: clean
clean:
	rm test_x86 libpts.a test_riscv48
