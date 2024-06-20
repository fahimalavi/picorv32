# This Makefile can be used with GNU Make or BSD Make

LIB=libdilithium3_clean.a
HEADERS=api.h ntt.h packing.h params.h poly.h polyvec.h reduce.h rounding.h sign.h symmetric.h 
OBJECTS=ntt.o packing.o poly.o polyvec.o reduce.o rounding.o sign.o symmetric-shake.o 

RISCV_GNU_TOOLCHAIN_INSTALL_PREFIX = /opt/riscv32
TOOLCHAIN_PREFIX = $(RISCV_GNU_TOOLCHAIN_INSTALL_PREFIX)ic_aes_kyber/bin/riscv32-unknown-elf-
CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -std=c99 -I../../common $(EXTRAFLAGS)

all: $(LIB)

%.o: %.c $(HEADERS)
	$(TOOLCHAIN_PREFIX)gcc $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJECTS)
	$(TOOLCHAIN_PREFIX)ar -r $@ $(OBJECTS)

clean:
	$(RM) $(OBJECTS)
	$(RM) $(LIB)
