CC = gcc
INCDIR = ./include
DEFINES =  -D_GNU_SOURCE -D__KERNEL__
ifdef USE_VALGRIND
DEFINES += -D_USE_VALGRIND
endif

# Unfortunately format checks are disabled with -Wno-format,
# because kernel defines __uin64_t as `unsigned long long`
# (IMO which is sane), but stdint.h defines as `unsigned long`.

CFLAGS = -g -O2 -std=gnu89 -Wall -Wdeclaration-after-statement -Wno-format -Werror -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -Wno-unused-const-variable -Wno-unused-but-set-variable -Wno-pointer-sign -fno-strict-aliasing -fstack-protector-strong -I$(INCDIR) $(DEFINES)

DEPS = $(shell find include/ -name '*.h')
SOURCES:= $(shell find src/ -name '*.c')
OBJ = $(SOURCES:.c=.o)

ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif

ifeq ($(VERBOSE),1)
  Q =
else
  Q = @
endif

%.o: %.c $(DEPS)
ifneq ($(VERBOSE),1)
	@echo CC $@
endif
	$(Q)$(CC) -c -o $@ $< $(CFLAGS)

pech-osd: $(OBJ)
ifneq ($(VERBOSE),1)
	@echo LD $@
endif
	$(Q)$(CC) -o $@ $^ -lresolv -ldl -rdynamic

.PHONY: clean

clean:
	$(Q)rm -f pech-osd core
	$(Q)find src \( -name \*.o -or -name \*.c~ \) -delete
