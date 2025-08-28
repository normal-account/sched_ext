#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/bpf_helpers.h>

// A BPF map to serve as a simple run queue.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_QUEUE);
    __uint(value_size, sizeof(struct bpf_task_struct *));
    __uint(max_entries, 1024);
} runq SEC(".maps");

// Called when a task becomes runnable. We add it to the back of our queue.
SEC("scx_enqueue")
void BPF_PROG(scx_enqueue, struct bpf_task_struct *task) {
    bpf_map_push_elem(&runq, &task, BPF_EXIST);
}

// Called when the CPU needs a new task to run.
SEC("scx_select_task")
int BPF_PROG(scx_select_task, int cpu, struct scx_rq *rq) {
    struct bpf_task_struct *task;

    // Pop the next task from the front of the queue.
    if (bpf_map_pop_elem(&runq, &task) != 0) {
        // No tasks in our queue, tell the kernel to go idle.
        return SCX_SELECT_IDLE;
    }

    // Dispatch the task we found.
    return bpf_scx_dispatch(rq, task, 0);
}

char LICENSE[] SEC("license") = "GPL";