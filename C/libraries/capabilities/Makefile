all: libcapabilities.a libcapabilities.so

LIB_DLL=../dll
LIB_COMMON=../common
SRC_FILES =	$(wildcard src/*.c) 
OBJ_FILES = $(patsubst %.c, %.o, $(SRC_FILES)) 
HDR_FILES = $(wildcard include/*.h)
INCLUDES= -Iinclude/ -I$(LIB_DLL)/include -I$(LIB_COMMON)/include

libcapabilities.so: $(SRC_FILES) $(HDR_FILES)
	gcc -DTYCHE_USER_SPACE=1 -g -nostdlib -shared $(INCLUDES) -o $@ -fPIC $(SRC_FILES) 

%.o : %.c
	gcc -DTYCHE_USER_SPACE=1 -g -nostdlib $(INCLUDES) -c $< -o $@

libcapabilities.a: $(OBJ_FILES) $(HDR_FILES)
	ar rcs $@ $(OBJ_FILES)
	rm $(OBJ_FILES)

.PHONY: clean

clean:
	rm libcapabilities.so libcapabilities.a

