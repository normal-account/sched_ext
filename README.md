# Unfair Scheduler

This repository contains the implementation of the **Unfair Scheduler**, a selectively unfair `sched_ext` eBPF scheduler designed for mixed database workloads.

For more details, see our paper: https://arxiv.org/abs/2605.02377

## Code Structure

- `scx_weightedcg.c`: C loader used to load and run the BPF scheduler.
- `scx_weightedcg.bpf.c`: BPF scheduler implementation.

## Dependencies

To build and run the scheduler, you need the following dependencies:

1. **clang**

   Used to compile the scheduler. It should be available through your distribution's package manager.

2. **bpftool**

   Used to generate the `vmlinux.h` header and load the scheduler as a BPF module.

   You can build and install it from source:

   ```bash
   git clone --recurse-submodules https://github.com/libbpf/bpftool.git
   cd bpftool/src
   make
   sudo make install
   ```

   On some distributions, you may need to install development tools first, such as `base-devel` on Arch Linux.

## Build Instructions

1. Verify that your kernel supports `sched_ext`:

   ```bash
   uname -r
   ```

   The kernel version should be **6.12 or newer**.

2. Verify that `sched_ext` is enabled in your kernel:

   ```bash
   zgrep CONFIG_SCHED_CLASS_EXT /proc/config.gz
   ```

   This should print:

   ```text
   CONFIG_SCHED_CLASS_EXT=y
   ```

   If it does not, your distribution may not enable `sched_ext` by default. In that case, you need to rebuild your kernel with `CONFIG_SCHED_CLASS_EXT=y`.

3. Generate the `vmlinux.h` header:

   ```bash
   make vmlinux
   ```

4. Download the source code for your running kernel, so the scheduler can compile against the correct kernel headers:

   ```bash
   ./fetch_kernel_src.sh
   ```

5. Compile the BPF scheduler:

   ```bash
   make build
   ```

6. Compile and run the C loader:

   ```bash
   make
   ```

## Experiments

To reproduce the experiments from the paper, see the companion environment repository, which contains the Dockerfile and scripts used for the evaluation:

https://github.com/normal-account/unfair_scheduler_env

## Artifacts

The artifacts from the paper, along with the scripts used to generate the plots, are available in the artifact repository:

https://github.com/normal-account/unfair_scheduler_artifacts
