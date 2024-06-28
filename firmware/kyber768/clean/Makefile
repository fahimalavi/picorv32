# This Makefile can be used with GNU Make or BSD Make

LIB=libkyber768_clean.a
HEADERS=api.h cbd.h indcpa.h kem.h ntt.h params.h poly.h polyvec.h reduce.h symmetric.h verify.h 
OBJECTS=cbd.o indcpa.o kem.o ntt.o poly.o polyvec.o reduce.o symmetric-shake.o verify.o 

RISCV_GNU_TOOLCHAIN_INSTALL_PREFIX = ../../../
TOOLCHAIN_PREFIX = $(RISCV_GNU_TOOLCHAIN_INSTALL_PREFIX)riscv32ic/bin/riscv32-unknown-elf-
CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -std=c99 -I../../common $(EXTRAFLAGS)

all: $(LIB)

%.o: %.c $(HEADERS)
	$(TOOLCHAIN_PREFIX)gcc  $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJECTS)
	$(TOOLCHAIN_PREFIX)ar -r $@ $(OBJECTS)

clean:
	$(RM) $(OBJECTS)
	$(RM) $(LIB)
