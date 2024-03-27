all: server

SRC = $(wildcard src/*.c)

server: $(SRC)
	gcc -g -o $@ $(SRC) -pthread

.PHONY: clean

clean:
	rm server
