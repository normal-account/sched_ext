# See https://github.com/sched-ext/scx/wiki
LOADER_NAME := scx_weightedcg
SCHED_NAME := $(LOADER_NAME).bpf

# Kernel version
KVER=$(shell uname -r)

# Strip distro-specific suffixes (e.g. -generic, -amd64) from kernel version
BASVER=$(shell echo "$(KVER)" | sed -e 's/-.*//' -e 's/[[:space:]]//g')

KERNEL_SRC_DIR := linux-$(BASVER)

# --- loader config ---
CC      ?= cc
CFLAGS = -O2 -g -std=gnu11
PKGCONF ?= pkg-config
LIBBPF_CFLAGS := $(shell $(PKGCONF) --cflags libbpf)
LIBBPF_LIBS   := $(shell $(PKGCONF) --libs   libbpf)

.PHONY: all build vmlinux start stop logs state loader start_loader clean

all: build stop loader start_loader

build: $(SCHED_NAME).c
	clang $(CFLAGS) -target bpf \
	  -I . \
	  -I $(KERNEL_SRC_DIR)/tools/sched_ext/include \
	  -c $(SCHED_NAME).c -o $(SCHED_NAME).o
	bpftool gen skeleton $(SCHED_NAME).o > $(SCHED_NAME).skel.h

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

start: stop
	./clear_traces.sh
	sudo bpftool struct_ops register $(SCHED_NAME).o /sys/fs/bpf/sched_ext

stop:
	sudo rm -rf /sys/fs/bpf/sched_ext

logs:
	sudo dmesg | grep -i 'sched_ext\|bpf'

state:
	sudo cat /sys/kernel/sched_ext/state
	sudo cat /sys/kernel/sched_ext/root/ops

# ------------------------------
# Loader: build & run (libbpf)
# ------------------------------

# Build the userspace loader; depends on the generated skeleton header
loader: $(LOADER_NAME)

$(LOADER_NAME): $(SCHED_NAME).skel.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) \
	  -I . \
	  -I /usr/include/bpf \
	  -I $(KERNEL_SRC_DIR)/tools/sched_ext/include \
	  $(LOADER_NAME).c -o $(LOADER_NAME) $(LIBBPF_LIBS)

# Start your scheduler via the loader (keeps the process alive)
start_loader: loader
	./clear_traces.sh
	sudo ./$(LOADER_NAME)

clean:
	rm -f $(SCHED_NAME).o $(SCHED_NAME).skel.h $(LOADER_NAME)
