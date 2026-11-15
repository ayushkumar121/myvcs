CC=cc
CFLAGS=-Wall -Wextra -g
LIBS=-lz

.PHONY: format clean all

all: myvcs
myvcs: myvcs.c sha1.o utils.o
	$(CC) -o myvcs myvcs.c sha1.o utils.o $(CFLAGS) $(LIBS)

sha1.o: sha1.c sha1.h
	$(CC) -o sha1.o -c sha1.c $(CFLAGS)

utils.o: utils.c utils.h
	$(CC) -o utils.o -c utils.c $(CFLAGS)

format:
	astyle --indent=tab --recursive "*.c" "*.h"

clean:
	rm -f *.o
	rm -f myvcs
