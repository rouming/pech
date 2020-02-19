CC = gcc
INCDIR = ./include
CFLAGS = -I$(INCDIR) -D_GNU_SOURCE -g -O2

DEPS = $(shell find include/ -name '*.h')
SOURCES:= $(shell find src/ -name '*.c')
OBJ = $(SOURCES:.c=.o)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

pech: $(OBJ)
	$(CC) -o $@ $^ -lresolv

.PHONY: clean

clean:
	rm -f pech core
	find src \( -name \*.o -or -name \*.c~ \) -delete
