all: libpts.a test_x86

# External libraries.
COMMON_LIB=../common

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

libpts.a: $(CODE_PTS) $(HDRS_PTS) $(OBJS_PTS)
	gcc -DTYCHE_USER_SPACE=1 -g -nostdlib -c $(INCLUDES) -o pts.o src/lib.c
	gcc -DTYCHE_USER_SPACE=1 -g -nostdlib -c $(INCLUDES) -o x86.o src/x86_64_pt.c
	ar rcs $@ pts.o x86.o
	rm pts.o x86.o

test_x86: tests/test.c libpts.a
	gcc -DTYCHE_USER_SPACE=1 -g $(INCLUDES) -L. -o $@ $< -l:libpts.a 

.PHONY: clean
clean:
	rm test_x86 libpts.a
