CC = gcc
INCDIR = ./include
DEFINES =  -D_GNU_SOURCE -D__KERNEL__
ifdef USE_VALGRIND
DEFINES += -D_USE_VALGRIND
endif
CFLAGS = -g -O2 -I$(INCDIR) $(DEFINES)

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
