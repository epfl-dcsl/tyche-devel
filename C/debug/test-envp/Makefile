all: print-envp

SRC =$(wildcard src/*.c)

print-envp: $(SRC)
	gcc -g -o $@ $<

.PHONY: clean

clean:
	rm -f print-envp
