all: rb_test_no_atomics rb_test_atomics librb_atomics.a librb_no_atomics.a

# ———————————————————————————————— Libraries ————————————————————————————————— #

COMMON_LIB=../../../linux/drivers/tyche/libraries/common

# ———————————————————————— Library sources & headers ————————————————————————— #

RB_SRC = $(wildcard src/*.c)
RB_HDR = $(wildcard include/*.h)

# —————————————————————————————— Tests sources ——————————————————————————————— #

TEST_SRC = $(wildcard tests/*.c)

# —————————————————————————— Include configuration ——————————————————————————— #

INCLUDES=-Iinclude/ -I$(COMMON_LIB)/include

librb_atomics.a: $(RB_SRC) $(RB_HDR)
	gcc -g -nostdlib -c $(INCLUDES) -o rb.o src/lib.c
	ar rcs $@ rb.o
	rm rb.o

librb_no_atomics.a: $(RB_SRC) $(RB_HDR)
	gcc -g -DRB_NO_ATOMICS=1 -nostdlib -c $(INCLUDES) -o rb.o src/lib.c
	ar rcs $@ rb.o
	rm rb.o

rb_test_no_atomics: $(RB_SRC) $(RB_HDR) $(TEST_SRC)
	gcc -DRB_NO_ATOMICS=1 -DTYCHE_USER_SPACE=1 -g $(INCLUDES) -o $@ $(TEST_SRC) $(RB_SRC)

rb_test_atomics: $(RB_SRC) $(RB_HDR) $(TEST_SRC)
	gcc -g -DTYCHE_USER_SPACE=1 $(INCLUDES) -o $@ $(TEST_SRC) $(RB_SRC)

.PHONY: clean

clean:
	rm -f rb_test_no_atomics rb_test_atomics *.a

