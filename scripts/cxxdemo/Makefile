RISCV_TOOLS_PREFIX = /opt/riscv32ic/bin/riscv32-unknown-elf-
CXX = $(RISCV_TOOLS_PREFIX)g++
CC = $(RISCV_TOOLS_PREFIX)gcc
AS = $(RISCV_TOOLS_PREFIX)gcc
CXXFLAGS = -MD -Os -Wall -std=c++11
CCFLAGS = -MD -Os -Wall -std=c++11
LDFLAGS = -Wl,--gc-sections
LDLIBS = -lstdc++

TYPE=kem
SCHEME=kyber1024
IMPLEMENTATION=clean
KAT_RNG=nist

SCHEME_DIR=../../firmware/$(SCHEME)/$(IMPLEMENTATION)
SCHEME_UPPERCASE=$(shell echo $(SCHEME) | tr a-z A-Z | sed 's/-//g')
IMPLEMENTATION_UPPERCASE=$(shell echo $(IMPLEMENTATION) | tr a-z A-Z | sed 's/-//g')

TEST_COMMON_DIR=../../firmware/test/common
COMMON_DIR=../../firmware/common
COMMON_FILES=$(COMMON_DIR)/aes.c $(COMMON_DIR)/sha2.c $(COMMON_DIR)/fips202.c $(COMMON_DIR)/nistseedexpander.c $(COMMON_DIR)/sp800-185.c
COMMON_HEADERS=$(COMMON_DIR)/*.h

SCHEME_LIBRARY=$(SCHEME_DIR)/lib$(SCHEME)_$(IMPLEMENTATION).a
SCHEME_FILES=$(wildcard $(SCHEME_DIR)/*.[chsS])

# This -Wall was supported by the European Commission through the ERC Starting Grant 805031 (EPOQUE)
#CRYPTO_CFLAGS=-O3 -Wall -Wextra -Wvla -Werror \
	   -Wundef -Wshadow -Wcast-align -Wpointer-arith \
	   -fstrict-aliasing -fno-common -pipe \
	   -I$(COMMON_DIR) $(EXTRAFLAGS)

VERILATOR = verilator
COMPRESSED_ISA = C

$(SCHEME_LIBRARY): $(SCHEME_FILES)
	cd $(SCHEME_DIR) && $(MAKE)
	
test: testbench.vvp firmware32.hex
	vvp -N testbench.vvp
	
test_crypto: testbench.vvp crypto32.hex
	vvp -N testbench.vvp

testbench.vvp: testbench.v ../../picorv32.v
	iverilog -o testbench.vvp testbench.v ../../picorv32.v
	chmod -x testbench.vvp

firmware32.hex: firmware.elf start.elf hex8tohex32.py
	$(RISCV_TOOLS_PREFIX)objcopy -O verilog start.elf start.tmp
	$(RISCV_TOOLS_PREFIX)objcopy -O verilog firmware.elf firmware.tmp
	cat start.tmp firmware.tmp > firmware.hex
	python3 hex8tohex32.py firmware.hex > firmware32.hex
	rm -f start.tmp firmware.tmp

crypto32.hex: crypto.elf start.elf hex8tohex32.py
	$(RISCV_TOOLS_PREFIX)objcopy -O verilog start.elf start.tmp
	$(RISCV_TOOLS_PREFIX)objcopy -O verilog crypto.elf firmware.tmp
	cat start.tmp firmware.tmp > firmware.hex
	python3 hex8tohex32.py firmware.hex > firmware32.hex
	rm -f start.tmp firmware.tmp

firmware.elf: firmware.o syscalls.o
	$(CC) $(LDFLAGS) -o $@ $^ -T ../../firmware/riscv.ld $(LDLIBS)
	chmod -x firmware.elf

crypto.elf: syscalls.o $(SCHEME_LIBRARY) $(COMMON_FILES) $(TEST_COMMON_DIR)/$(KAT_RNG)katrng.c $(COMMON_HEADERS)
	$(CC) $(LDFLAGS) $(CRYPTO_CFLAGS) -I$(COMMON_DIR) -DPQCLEAN_NAMESPACE=PQCLEAN_$(SCHEME_UPPERCASE)_$(IMPLEMENTATION_UPPERCASE) -I$(SCHEME_DIR) $(KAT_RNG)kat.c $(COMMON_FILES) $(TEST_COMMON_DIR)/$(KAT_RNG)katrng.c -o $@  syscalls.o  -T ../../firmware/riscv.ld -L$(SCHEME_DIR) -l$(SCHEME)_$(IMPLEMENTATION) 
	chmod -x crypto.elf

start.elf: start.S start.ld
	$(CC) -nostdlib -o start.elf start.S -T start.ld $(LDLIBS)
	chmod -x start.elf

clean:
	rm -f *.o *.d *.tmp start.elf
	rm -f firmware.elf crypto.elf firmware.hex firmware32.hex
	rm -f testbench.vvp testbench.vcd
	cd $(SCHEME_DIR) && $(MAKE) clean

-include *.d
.PHONY: test clean
