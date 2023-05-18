all: test-capa

LIB_DLL=../../dll/
LIB_COMMON=../../common/
LIB_CAPA=../libcapabilities.a

INCLUDES= -I../include/ -I$(LIB_DLL)/include -I$(LIB_COMMON)/include

# Sources and objects
SRC_FILES =	$(wildcard src/*.c) 

test-capa: $(SRC_FILES)
	gcc -DTYCHE_USER_SPACE=1 -g $(INCLUDES)  $^ -o $@ -L../ -l:libcapabilities.a

clean:
	rm test-capa
