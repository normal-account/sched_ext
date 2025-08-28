# See https://github.com/sched-ext/scx/wiki
FILENAME := scx_flatcg.bpf

all: build stop start

build:
	clang -O2 -g -target bpf   -I . -I linux-6.15/tools/sched_ext/include -c $(FILENAME).c

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

start: stop
	./clear_traces.sh
	sudo bpftool struct_ops register $(FILENAME).o /sys/fs/bpf/sched_ext

stop:
	sudo rm -rf /sys/fs/bpf/sched_ext

logs:
	sudo dmesg | grep -i 'sched_ext\|bpf'

state:
	sudo cat /sys/kernel/sched_ext/state
	sudo cat /sys/kernel/sched_ext/root/ops
