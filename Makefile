.PHONY: all clean

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN := bin/ps5-linux-1360.elf
SRC := $(wildcard source/*.c source/byepervisor/*.c)
OBJS := $(SRC:.c=.o)

CFLAGS  := -std=c23 -Wall -Iinclude -Iinclude/byepervisor -Ishellcode/hv \
           -Ishellcode/break_hv -Ishellcode/hv_takeover

# Toolchain override. Pass LLVM_CONFIG in the environment:
#   export LLVM_CONFIG=$(brew --prefix llvm@18)/bin/llvm-config
LDFLAGS :=

# Extra defines for the diagnostic builds, appended rather than substituted so a
# build like `make EXTRA_CFLAGS=-DMANUAL_SLEEP` keeps the include paths.
#
#   -DMANUAL_SLEEP      park after arming and let the operator sleep the console
#                       from the PS menu, as the reference payload does, instead
#                       of calling enter_rest_mode()
#   -DSKIP_SELFTEST     drop the khook self-test
#   -DSKIP_FETCH_LINUX  load no Linux images
#   -DSKIP_HV_STAGING   do not build the cave
CFLAGS += $(EXTRA_CFLAGS)

# The shellcode half is x86-64 freestanding and cannot be built with the host
# compiler: on macOS that is arm64 clang, which rejects -mno-sse outright. These
# used to be passed by hand on every invocation, so a plain `make` failed on the
# first shellcode subdirectory and SC_BREAK_H was never defined at all - which
# meant break_hv was never built and a fresh clone had no break_hv.h to compile
# against. Both are fixed here.
#
# Override on the command line if the tools are named differently, e.g.
#   make SC_CC=x86_64-elf-gcc-14
SC_CC      ?= x86_64-elf-gcc
SC_LD      ?= x86_64-elf-ld
SC_OBJCOPY ?= x86_64-elf-objcopy
SC_CFLAGS  := -O2 -fno-stack-protector -ffreestanding -nostdlib -fcf-protection=none \
              -fomit-frame-pointer -mno-sse -mno-sse2 -m64 -I$(CURDIR)/stubinc
SC_TOOLS   := CC=$(SC_CC) LD=$(SC_LD) OBJCOPY=$(SC_OBJCOPY)

SC_HV_H := shellcode/hv/shellcode_hv.h
SC_BREAK_H := shellcode/break_hv/break_hv.h
SC_TAKEOVER_H := shellcode/hv_takeover/takeover.h

# The blobs are built first because the userland sources include their generated
# headers, so `make -j` must not compile them before the blobs exist.
SC_ALL := $(SC_HV_H) $(SC_BREAK_H) $(SC_TAKEOVER_H)

all: $(SC_ALL) $(BIN)


# Three blobs, all built with the freestanding C flags.

$(SC_HV_H):
	$(MAKE) -C shellcode/hv $(SC_TOOLS) CFLAGS="$(SC_CFLAGS)"


$(SC_TAKEOVER_H):
	$(MAKE) -C shellcode/hv_takeover $(SC_TOOLS) CFLAGS="$(SC_CFLAGS)"

# break_hv sets CFLAGS itself - it is assembled with -DCAVE_HV_PAGING and
# -DCAVE_HV_CODE, so overriding CFLAGS here would drop the cave addresses and
# produce a payload that jumps into the wrong place.
$(SC_BREAK_H):
	$(MAKE) -C shellcode/break_hv $(SC_TOOLS)


$(OBJS): %.o: %.c $(SC_ALL)
	$(CC) $(CFLAGS) -c -o $@ $<

# The userland objects include the generated shellcode headers; make the
# dependency explicit so `make -j` cannot compile them before the blobs exist.

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

clean:
	rm -f $(BIN) $(OBJS)
	$(MAKE) -C shellcode/hv clean
	$(MAKE) -C shellcode/break_hv clean
	$(MAKE) -C shellcode/hv_takeover clean
