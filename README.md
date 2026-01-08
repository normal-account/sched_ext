# About

This is my draft implementation of a weighted cgroup sched_ext scheduler. It's in a rough shape, I will polish things out once I have a satisfactory implementation.

# Code

* **scx_weightedcg.c**: The C loader used to load the BPF scheduler.
* **scx_weightedcg.bpf.c**: The actual BPF scheduler.

# Dependencies

To build and use this scheduler, you'll need the following libraries:

* 1. **clang** for the compilation. You can most likely get it from your package manager.
* 2. **bpftool** to generate the `vmlinux` header and load the scheduler as a BPF module. You should download and build it from source. You may need to install the **base-devel** package first.
```
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
make
sudo make install
```


# Build

* 1. Verify that your kernel supports sched_ext. Run `uname -r` and confirm that your version is 6.12 or higher.
* 2. Verify that sched_ext is enabled on your kernel by running `zgrep CONFIG_SCHED_CLASS_EXT /proc/config.gz`. This should print `CONFIG_SCHED_CLASS_EXT=y`. If you don't see this output, it means that sched_ext is not enabled on your distribution by default, and you need to recompile your kernel with the option enabled.
* 3. Generate a `vmlinux.h` header by running the following command: `make vmlinux`
* 4. Download the source code of your kernel so the scheduler can compile against its include headers. You can run the following script to do so: `./fetch_kernel_src.h`.
* 5. Compile the BPF scheduler by running `make build`.
* 6. Compile the C loader and run it by running `make`.

