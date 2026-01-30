BPF_CLANG ?= clang
CC        ?= gcc

ARCH := $(shell uname -m)

ifeq ($(ARCH),x86_64)
BPF_ARCH := x86
else ifeq ($(ARCH),aarch64)
BPF_ARCH := arm64
else ifeq ($(ARCH),armv7l)
BPF_ARCH := arm
else
BPF_ARCH := $(ARCH)
endif

INCLUDES := -I/usr/include -I/usr/include/$(ARCH)-linux-gnu

BPF_CFLAGS  := -O2 -g -Wall -target bpf $(INCLUDES) -D__TARGET_ARCH_$(BPF_ARCH)
USER_CFLAGS := -O2 -g -Wall

LIBS := -lbpf -lelf -lz

.PHONY: all clean

all: portscan_simple.o loader_simple

portscan_simple.o: portscan_simple.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

loader_simple: loader_simple.c
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBS)

clean:
	rm -f *.o loader_simple
