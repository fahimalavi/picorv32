# This Makefile can be used with GNU Make or BSD Make

LIB=libkyber1024_clean.a
#LIB=cherry_libkyber1024_clean.a
HEADERS=api.h cbd.h indcpa.h kem.h ntt.h params.h poly.h polyvec.h reduce.h symmetric.h verify.h 
OBJECTS=cbd.o indcpa.o kem.o ntt.o poly.o polyvec.o reduce.o symmetric-shake.o verify.o 

RISCV_GNU_TOOLCHAIN_INSTALL_PREFIX = /opt/riscv32
TOOLCHAIN_PREFIX = $(RISCV_GNU_TOOLCHAIN_INSTALL_PREFIX)i/bin/riscv32-unknown-elf-
#CHERY_CC=/home/alavis/cheri/output/sdk/bin/clang
#CHERY_AR=/home/alavis/cheri/output/sdk/bin/ar
#CHERY_SYSROOT=/home/alavis/cheri/output/rootfs-riscv64-purecap
#CHERY_CFLAGS += -g -O2 -target riscv64-unknown-freebsd --sysroot="$(CHERY_SYSROOT)" -fuse-ld=lld -mno-relax -march=rv64gcxcheri -mabi=l64pc128d -Wall -Wcheri -fomit-frame-pointer -I../../common $(EXTRAFLAGS)
CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -std=c99 -I../../common $(EXTRAFLAGS)
#CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -std=c99 -I../common $(EXTRAFLAGS)

all: $(LIB)

%.o: %.c $(HEADERS)
	#$(CC) $(CFLAGS) -c -o $@ $<
	#$(CHERY_CC) $(CHERY_CFLAGS) -c -o $@ $<
	$(TOOLCHAIN_PREFIX)gcc  $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJECTS)
	#$(AR) -r $@ $(OBJECTS)
	#$(CHERY_AR) -r $@ $(OBJECTS)
	$(TOOLCHAIN_PREFIX)ar -r $@ $(OBJECTS)

clean:
	$(RM) $(OBJECTS)
	$(RM) $(LIB)
