/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A demo sched_ext flattened cgroup hierarchy scheduler. It implements
 * hierarchical weight-based cgroup CPU control by flattening the cgroup
 * hierarchy into a single layer by compounding the active weight share at each
 * level. Consider the following hierarchy with weights in parentheses:
 *
 * R + A (100) + B (100)
 *   |         \ C (100)
 *   \ D (200)
 *
 * Ignoring the root and threaded cgroups, only B, C and D can contain tasks.
 * Let's say all three have runnable tasks. The total share that each of these
 * three cgroups is entitled to can be calculated by compounding its share at
 * each level.
 *
 * For example, B is competing against C and in that competition its share is
 * 100/(100+100) == 1/2. At its parent level, A is competing against D and A's
 * share in that competition is 100/(200+100) == 1/3. B's eventual share in the
 * system can be calculated by multiplying the two shares, 1/2 * 1/3 == 1/6. C's
 * eventual shaer is the same at 1/6. D is only competing at the top level and
 * its share is 200/(100+200) == 2/3.
 *
 * So, instead of hierarchically scheduling level-by-level, we can consider it
 * as B, C and D competing each other with respective share of 1/6, 1/6 and 2/3
 * and keep updating the eventual shares as the cgroups' runnable states change.
 *
 * This flattening of hierarchy can bring a substantial performance gain when
 * the cgroup hierarchy is nested multiple levels. in a simple benchmark using
 * wrk[8] on apache serving a CGI script calculating sha1sum of a small file, it
 * outperforms CFS by ~3% with CPU controller disabled and by ~10% with two
 * apache instances competing with 2:1 weight ratio nested four level deep.
 *
 * However, the gain comes at the cost of not being able to properly handle
 * thundering herd of cgroups. For example, if many cgroups which are nested
 * behind a low priority parent cgroup wake up around the same time, they may be
 * able to consume more CPU cycles than they are entitled to. In many use cases,
 * this isn't a real concern especially given the performance gain. Also, there
 * are ways to mitigate the problem further by e.g. introducing an extra
 * scheduling layer on cgroup delegation boundaries.
 *
 * The scheduler first picks the cgroup to run and then schedule the tasks
 * within by using nested weighted vtime scheduling by default. The
 * cgroup-internal scheduling can be switched to FIFO with the -f option.
 */
#include <scx/common.bpf.h>
#include "scx_flatcg.h"

/*
 * Maximum amount of retries to find a valid cgroup.
 */
enum {
	FALLBACK_DSQ		= 0,
	CGROUP_MAX_RETRIES	= 1024,
};

char _license[] SEC("license") = "GPL";

const volatile u32 nr_cpus = 32;	/* !0 for veristat, set during init */
const volatile u64 cgrp_slice_ns = 50000; /* default when no userspace sets rodata */
const volatile bool fifo_sched = false; /* default FIFO off */

u64 cvtime_now;
UEI_DEFINE(uei);
u64 scx_start_ts_ns;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, FCG_NR_STATS);
} stats SEC(".maps");

static void stat_inc(enum fcg_stat_idx idx)
{
	u32 idx_v = idx;

	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx_v);
	if (cnt_p)
		(*cnt_p)++;
}

struct fcg_cpu_ctx {
	u64			cur_cgid;
	u64			cur_at;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct fcg_cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct fcg_cgrp_ctx);
} cgrp_ctx SEC(".maps");

struct cgv_node {
	struct bpf_rb_node	rb_node;
	__u64			cvtime;
	__u64			cgid;
};

private(CGV_TREE) struct bpf_spin_lock cgv_tree_lock;
private(CGV_TREE) struct bpf_rb_root cgv_tree __contains(cgv_node, rb_node);

struct cgv_node_stash {
	struct cgv_node __kptr *node;
};

/* CPU -> current cgid (0 if none). Updated in dispatch; used to spread hw in select_cpu */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 1024);
} cur_cgid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct cgv_node_stash);
} cgv_node_stash SEC(".maps");

struct fcg_task_ctx {
	u64		bypassed_at;
    s32		desired_cpu;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct fcg_task_ctx);
} task_ctx SEC(".maps");

/* gets inc'd on weight tree changes to expire the cached hweights */
u64 hweight_gen = 1;

static __inline bool comm_eq(const char *a, const char *b)
{
	#pragma unroll
	for (int i = 0; i < 16; i++) {
		if (a[i] != b[i])
			return false;
		if (a[i] == '\0')
			return true;
	}
	return true;
}

static bool should_log(const char *comm, s32 cpu)
{
	if (cpu > 1)
		return false;
	return NULL == comm ? false : comm_eq(comm, "intermittent");// || comm_eq(comm, "burn_cpu");
}

static u64 div_round_up(u64 dividend, u64 divisor)
{
	return (dividend + divisor - 1) / divisor;
}

static bool cgv_node_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct cgv_node *cgc_a, *cgc_b;

	cgc_a = container_of(a, struct cgv_node, rb_node);
	cgc_b = container_of(b, struct cgv_node, rb_node);

	return cgc_a->cvtime < cgc_b->cvtime;
}

static struct fcg_cpu_ctx *find_cpu_ctx(void)
{
	struct fcg_cpu_ctx *cpuc;
	u32 idx = 0;

	cpuc = bpf_map_lookup_elem(&cpu_ctx, &idx);
	if (!cpuc) {
		scx_bpf_error("cpu_ctx lookup failed");
		return NULL;
	}
	return cpuc;
}

static struct fcg_cgrp_ctx *find_cgrp_ctx(struct cgroup *cgrp)
{
	struct fcg_cgrp_ctx *cgc;

	cgc = bpf_cgrp_storage_get(&cgrp_ctx, cgrp, 0, 0);
	if (!cgc) {
		scx_bpf_error("cgrp_ctx lookup failed for cgid %llu", cgrp->kn->id);
		return NULL;
	}
	return cgc;
}

static struct fcg_cgrp_ctx *find_ancestor_cgrp_ctx(struct cgroup *cgrp, int level)
{
	struct fcg_cgrp_ctx *cgc;

	cgrp = bpf_cgroup_ancestor(cgrp, level);
	if (!cgrp) {
		scx_bpf_error("ancestor cgroup lookup failed");
		return NULL;
	}

	cgc = find_cgrp_ctx(cgrp);
	if (!cgc)
		scx_bpf_error("ancestor cgrp_ctx lookup failed");
	bpf_cgroup_release(cgrp);
	return cgc;
}

static void cgrp_refresh_hweight(struct cgroup *cgrp, struct fcg_cgrp_ctx *cgc)
{
	int level;

	if (!cgc->nr_active) {
		stat_inc(FCG_STAT_HWT_SKIP);
		return;
	}

	if (cgc->hweight_gen == hweight_gen) {
		stat_inc(FCG_STAT_HWT_CACHE);
		return;
	}

	stat_inc(FCG_STAT_HWT_UPDATES);
	bpf_for(level, 0, cgrp->level + 1) {
		struct fcg_cgrp_ctx *cgc;
		bool is_active;

		cgc = find_ancestor_cgrp_ctx(cgrp, level);
		if (!cgc)
			break;

		if (!level) {
			cgc->hweight = FCG_HWEIGHT_ONE;
			cgc->hweight_gen = hweight_gen;
		} else {
			struct fcg_cgrp_ctx *pcgc;

			pcgc = find_ancestor_cgrp_ctx(cgrp, level - 1);
			if (!pcgc)
				break;

			/*
			 * We can be opportunistic here and not grab the
			 * cgv_tree_lock and deal with the occasional races.
			 * However, hweight updates are already cached and
			 * relatively low-frequency. Let's just do the
			 * straightforward thing.
			 */
			bpf_spin_lock(&cgv_tree_lock);
			is_active = cgc->nr_active;
			if (is_active) {
				cgc->hweight_gen = pcgc->hweight_gen;
				cgc->hweight =
					div_round_up(pcgc->hweight * cgc->weight,
						     pcgc->child_weight_sum);
			}
			bpf_spin_unlock(&cgv_tree_lock);

			if (!is_active) {
				stat_inc(FCG_STAT_HWT_RACE);
				break;
			}
		}

		/* Temporary override based on cgroup name: "hw" => 10000, "lw" => 1 */
		{
			struct cgroup *curc = bpf_cgroup_ancestor(cgrp, level);
			if (curc) {
				char namebuf[32];
				bpf_probe_read_kernel(&namebuf, sizeof(namebuf), curc->kn->name);
				if (namebuf[0] == 'h' && namebuf[1] == 'w' && namebuf[2] == '\0')
					cgc->hweight = 10000;
				else if (namebuf[0] == 'l' && namebuf[1] == 'w' && namebuf[2] == '\0')
					cgc->hweight = 1;
				bpf_cgroup_release(curc);
			}
		}
	}
}

static void cgrp_cap_budget(struct cgv_node *cgv_node, struct fcg_cgrp_ctx *cgc)
{
	u64 delta, cvtime, max_budget;

	/*
	 * A node which is on the rbtree can't be pointed to from elsewhere yet
	 * and thus can't be updated and repositioned. Instead, we collect the
	 * vtime deltas separately and apply it asynchronously here.
	 */
	delta = __sync_fetch_and_sub(&cgc->cvtime_delta, cgc->cvtime_delta);
	cvtime = cgv_node->cvtime + delta;

	/*
	 * Allow a cgroup to carry the maximum budget proportional to its
	 * hweight such that a full-hweight cgroup can immediately take up half
	 * of the CPUs at the most while staying at the front of the rbtree.
	 */
	max_budget = (cgrp_slice_ns * nr_cpus * cgc->hweight) /
		(2 * FCG_HWEIGHT_ONE);
	if (time_before(cvtime, cvtime_now - max_budget))
		cvtime = cvtime_now - max_budget;

	cgv_node->cvtime = cvtime;
}

static void cgrp_enqueued(struct cgroup *cgrp, struct fcg_cgrp_ctx *cgc)
{
	struct cgv_node_stash *stash;
	struct cgv_node *cgv_node;
	u64 cgid = cgrp->kn->id;

	/* paired with cmpxchg in try_pick_next_cgroup() */
	if (__sync_val_compare_and_swap(&cgc->queued, 0, 1)) {
		stat_inc(FCG_STAT_ENQ_SKIP);
		return;
	}

	stash = bpf_map_lookup_elem(&cgv_node_stash, &cgid);
	if (!stash) {
		scx_bpf_error("cgv_node lookup failed for cgid %llu", cgid);
		return;
	}

	/* NULL if the node is already on the rbtree */
	cgv_node = bpf_kptr_xchg(&stash->node, NULL);
	if (!cgv_node) {
		stat_inc(FCG_STAT_ENQ_RACE);
		return;
	}

	bpf_spin_lock(&cgv_tree_lock);
	cgrp_cap_budget(cgv_node, cgc);
	bpf_rbtree_add(&cgv_tree, &cgv_node->rb_node, cgv_node_less);
	bpf_spin_unlock(&cgv_tree_lock);
}

static void set_bypassed_at(struct task_struct *p, struct fcg_task_ctx *taskc)
{
	/*
	 * Tell fcg_stopping() that this bypassed the regular scheduling path
	 * and should be force charged to the cgroup. 0 is used to indicate that
	 * the task isn't bypassing, so if the current runtime is 0, go back by
	 * one nanosecond.
	 */
	taskc->bypassed_at = p->se.sum_exec_runtime ?: (u64)-1;
}

/*
 * Common CPU selection logic for HW tasks - finds a CPU not currently running HW
 * Returns selected CPU or -1 if no suitable CPU found
 */
static s32 select_cpu_for_hw_task(struct task_struct *p, s32 prev_cpu, 
				struct bpf_cpumask *allowed_mask, bool log)
{
	s32 selected_cpu = -1;
	
	/* First consider prev_cpu if allowed and not already running hw */
	if (prev_cpu >= 0) {
		u32 pc = (u32)prev_cpu;
		if (bpf_cpumask_test_cpu(pc, cast_mask(allowed_mask))) {
			u64 *cgidp_prev = bpf_map_lookup_elem(&cur_cgid, &pc);
			bool prev_is_hw = false;
			if (cgidp_prev && *cgidp_prev) {
				struct cgroup *tc = bpf_cgroup_from_id(*cgidp_prev);
				if (tc) {
					char name2[32];
					bpf_probe_read_kernel(&name2, sizeof(name2), tc->kn->name);
					prev_is_hw = (name2[0]=='h' && name2[1]=='w' && name2[2]=='\0');
					bpf_cgroup_release(tc);
				}
			}
			if (!prev_is_hw) {
				selected_cpu = prev_cpu;
				if (log)
					bpf_printk("\tselect_cpu_for_hw_task: choose prev_cpu=%d (not running hw)", prev_cpu);
				return selected_cpu;
			} else if (log) {
				bpf_printk("\tselect_cpu_for_hw_task: skip prev_cpu=%d (already running hw)", prev_cpu);
			}
		} else if (log) {
			bpf_printk("\tselect_cpu_for_hw_task: prev_cpu=%d not in affinity", prev_cpu);
		}
	}

	/* Iterate allowed CPUs and pick one not running hw */
	int *pc;
	for_each_online_cpu(pc) {
		u32 c = (u32)(*pc);
		if (!bpf_cpumask_test_cpu(c, cast_mask(allowed_mask)))
			continue;
		u64 *cgidp = bpf_map_lookup_elem(&cur_cgid, &c);
		bool is_hw = false;
		if (cgidp && *cgidp) {
			/* look up name of that cgid */
			struct cgroup *tc = bpf_cgroup_from_id(*cgidp);
			if (tc) {
				char name2[32];
				bpf_probe_read_kernel(&name2, sizeof(name2), tc->kn->name);
				is_hw = (name2[0]=='h' && name2[1]=='w' && name2[2]=='\0');
				bpf_cgroup_release(tc);
			}
		}
		if (!is_hw) {
			selected_cpu = (s32)c;
			if (log)
				bpf_printk("\tselect_cpu_for_hw_task: choose cpu=%d (not running hw)", c);
			break;
		}
		else if (log)
		{
			bpf_printk("\tselect_cpu_for_hw_task: SKIP cpu=%d (running hw)", c);
		}
	}
	
	if (log)
		bpf_printk("\tselect_cpu_for_hw_task: final cpu=%d", selected_cpu);
	
	return selected_cpu;
}

s32 BPF_STRUCT_OPS(fcg_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct fcg_task_ctx *taskc;
	bool is_idle = false;
	s32 cpu;

    cpu = prev_cpu;

    bpf_printk("\tselect_cpu: at first, cpu is %d for pid %d", cpu, p->pid);

    struct bpf_cpumask *tmp = bpf_cpumask_create();
    if (!tmp) {
        scx_bpf_error("failed to alloc temp cpumask");
        return cpu;
    }

    bpf_cpumask_copy(tmp, (const struct cpumask *)p->cpus_ptr);

    int log = should_log(p->comm, 0);

    /* Prefer spreading hw across CPUs: choose a CPU not currently running hw */
    struct cgroup *cgrp = __COMPAT_scx_bpf_task_cgroup(p);
    if (cgrp) {
        char cg_name_buf[32];
        bpf_probe_read_kernel(&cg_name_buf, sizeof(cg_name_buf), cgrp->kn->name);
        if (cg_name_buf[0] == 'h' && cg_name_buf[1] == 'w' && cg_name_buf[2] == '\0') {
            bpf_printk("\tselect_cpu: pid %d comm %s hw wake, prev_cpu=%d dfl_cpu=%d",
                       p->pid, p->comm, prev_cpu, cpu);

            /* Use common HW CPU selection logic */
            s32 hw_cpu = select_cpu_for_hw_task(p, prev_cpu, tmp, log);
            if (hw_cpu >= 0) {
                cpu = hw_cpu;
                bpf_cgroup_release(cgrp);
                goto after_select_hw;
            }
            /* If no HW-specific CPU found, fall back to default CPU */
        }
        else if (log)
        {
            bpf_printk("\tselect_cpu: for pid %d not part of hw cgroup!?!?! (in %s)", p->pid, cg_name_buf);
        }
        bpf_cgroup_release(cgrp);
    }
    else {
        bpf_printk("\tselect_cpu: no cgrp for pid %d!!!", p->pid);
    }
    
after_select_hw:

    taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("task_ctx lookup failed");
        bpf_cpumask_release(tmp);
		return cpu;
	}
    
    /* Only set desired_cpu if the selected CPU is actually in task's affinity */
    if (bpf_cpumask_test_cpu((u32)cpu, cast_mask(tmp))) {
        taskc->desired_cpu = cpu;
        bpf_printk("\tselect_cpu: setting desired_cpu to selected cpu=%d for pid %d", cpu, p->pid);

        /* Update per-CPU current cgid immediately for selected CPU */
        {
            struct cgroup *sc = __COMPAT_scx_bpf_task_cgroup(p);
            if (sc) {
                u32 kcpu = (u32)cpu;
                u64 sel_id = sc->kn->id;
                bpf_map_update_elem(&cur_cgid, &kcpu, &sel_id, BPF_ANY);
                if (should_log(p->comm, cpu))
                    bpf_printk("\tselect_cpu: cur_cgid[cpu=%d] <= %llu for pid %d", cpu, sel_id, p->pid);
                bpf_cgroup_release(sc);
            }
        }
    } else {
        /* CPU not in affinity - find any allowed CPU as fallback */
        s32 fallback_cpu = scx_bpf_pick_any_cpu((const struct cpumask *)p->cpus_ptr, 0);
        if (fallback_cpu >= 0) {
            taskc->desired_cpu = fallback_cpu;
            if (should_log(p->comm, cpu))
                bpf_printk("\tselect_cpu: selected cpu=%d NOT in affinity, using fallback cpu=%d for pid %d", cpu, fallback_cpu, p->pid);
        } else {
            /* No valid CPU found - let dispatch handle it normally */
            taskc->desired_cpu = -1;
            if (should_log(p->comm, cpu))
                bpf_printk("\tselect_cpu: selected cpu=%d NOT in affinity, no fallback found for pid %d", cpu, p->pid);
        }
    }

    bpf_cpumask_release(tmp);

	/*
	 * If select_cpu_dfl() is recommending local enqueue, the target CPU is
	 * idle. Follow it and charge the cgroup later in fcg_stopping() after
	 * the fact.
	 */
    //if (is_idle) {
	//	set_bypassed_at(p, taskc);
	//	stat_inc(FCG_STAT_LOCAL);
	//	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	//}

	return cpu;
}

void BPF_STRUCT_OPS(fcg_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct fcg_task_ctx *taskc;
	struct cgroup *cgrp;
	struct fcg_cgrp_ctx *cgc;

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("task_ctx lookup failed");
		return;
	}

	/*
	 * Use the direct dispatching and force charging to deal with tasks with
	 * custom affinities so that we don't have to worry about per-cgroup
	 * dq's containing tasks that can't be executed from some CPUs.
	 */
	//if (p->nr_cpus_allowed != nr_cpus) {
	//	set_bypassed_at(p, taskc);
    //
	//	/*
	//	 * The global dq is deprioritized as we don't want to let tasks
	//	 * to boost themselves by constraining its cpumask. The
	//	 * deprioritization is rather severe, so let's not apply that to
	//	 * per-cpu kernel threads. This is ham-fisted. We probably wanna
	//	 * implement per-cgroup fallback dq's instead so that we have
	//	 * more control over when tasks with custom cpumask get issued.
	//	 */
	//	if (p->nr_cpus_allowed == 1 && (p->flags & PF_KTHREAD)) {
	//		stat_inc(FCG_STAT_LOCAL);
	//		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL,
	//				   enq_flags);
	//	} else {
	//		stat_inc(FCG_STAT_GLOBAL);
	//		scx_bpf_dsq_insert(p, FALLBACK_DSQ, SCX_SLICE_DFL,
	//				   enq_flags);
	//	}
    //
    //    stat_inc(FCG_STAT_LOCAL);
    //    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL,
    //               enq_flags);
	//	return;
	//}

	cgrp = __COMPAT_scx_bpf_task_cgroup(p);
	cgc = find_cgrp_ctx(cgrp);
	if (!cgc)
		goto out_release;

    ///* If enqueued cgroup is hw but current CPU isn't running hw, kick this CPU */
    //{
    //    char enq_cg_name[32];
    //    bpf_probe_read_kernel(&enq_cg_name, sizeof(enq_cg_name), cgrp->kn->name);
    //    if (enq_cg_name[0] == 'h' && enq_cg_name[1] == 'w' && enq_cg_name[2] == '\0') {
    //        u32 kcpu = (u32)bpf_get_smp_processor_id();
    //        u64 *cur_id = bpf_map_lookup_elem(&cur_cgid, &kcpu);
    //        bool cur_is_hw = false;
    //        if (cur_id && *cur_id) {
    //            struct cgroup *rc = bpf_cgroup_from_id(*cur_id);
    //            if (rc) {
    //                char run_name[32];
    //                bpf_probe_read_kernel(&run_name, sizeof(run_name), rc->kn->name);
    //                cur_is_hw = (run_name[0]=='h' && run_name[1]=='w' && run_name[2]=='\0');
    //                bpf_cgroup_release(rc);
    //            }
    //        }
    //        if (!cur_is_hw) {
    //            scx_bpf_kick_cpu((s32)kcpu, SCX_KICK_PREEMPT);
    //            if (should_log(p->comm, (s32)kcpu))
    //                bpf_printk("\tfcg_enqueue: kick local CPU %d (running not hw) for pid %d", (s32)kcpu, p->pid);
    //        } else if (should_log(p->comm, (s32)kcpu)) {
    //            bpf_printk("\tfcg_enqueue: skip kick local CPU (already running hw) for pid %d", p->pid);
    //        }
    //    }
    //}

	///* Simple: if cgroup is "hw", insert as preempt and kick CPUs immediately */
	//{
	//	char cg_name_buf[32];
	//	bpf_probe_read_kernel(&cg_name_buf, sizeof(cg_name_buf), cgrp->kn->name);
    //    if (cg_name_buf[0] == 'h' && cg_name_buf[1] == 'w' && cg_name_buf[2] == '\0') {
    //        /* Kick smarter: if this CPU is already running this cgroup, kick another CPU */
	//		s32 this_cpu = (s32)bpf_get_smp_processor_id();
	//		u32 k0 = 0;
	//		struct fcg_cpu_ctx *cpuc = bpf_map_lookup_elem(&cpu_ctx, &k0);
	//		s32 target_cpu = this_cpu;
	//		if (cpuc && cpuc->cur_cgid == cgrp->kn->id) {
	//			if (should_log(p->comm, this_cpu))
	//				bpf_printk("\tfcg_enqueue: CPU %d already running cgroup %s, searching affinity for idle", this_cpu, cg_name_buf);
    //            /* Prefer an idle CPU within task's affinity if available */
    //            const struct cpumask *allowed = (const struct cpumask *)p->cpus_ptr;
    //            s32 idle = scx_bpf_pick_idle_cpu(allowed, 0);
    //            if (idle >= 0 && idle != this_cpu) {
	//				if (should_log(p->comm, this_cpu))
	//					bpf_printk("\tfcg_enqueue: picked idle CPU %d within affinity", idle);
    //                target_cpu = idle;
    //            } else {
    //                /* Fallback: pick any CPU from affinity, distributed, excluding this_cpu */
    //                struct bpf_cpumask *tmp = bpf_cpumask_create();
    //                if (tmp) {
    //                    bpf_cpumask_copy(tmp, allowed);
    //                    bpf_cpumask_clear_cpu((u32)this_cpu, tmp);
    //                    target_cpu = bpf_cpumask_any_distribute(cast_mask(tmp));
    //                    bpf_cpumask_release(tmp);
    //                    if (target_cpu < 0) {
    //                        //if (should_log(p->comm, this_cpu))
    //                        //    bpf_printk("\tfcg_enqueue: distribute returned <0, fallback to this_cpu %d", this_cpu);
    //                        target_cpu = this_cpu;
    //                    //} else if (should_log(p->comm, this_cpu)) {
    //                    //    bpf_printk("\tfcg_enqueue: distribute chose CPU %d within affinity (excl this_cpu)", target_cpu);
    //                    }
    //                } else {
    //                    if (should_log(p->comm, this_cpu))
    //                        bpf_printk("\tfcg_enqueue: failed to alloc temp cpumask, fallback to this_cpu %d", this_cpu);
    //                    target_cpu = this_cpu;
    //                }
    //            }
	//		} else {
	//			/* Not currently running here; kick this CPU */
	//			target_cpu = this_cpu;
	//			if (should_log(p->comm, this_cpu))
	//				bpf_printk("\tfcg_enqueue: CPU %d not running cgroup %s, kicking local", this_cpu, cg_name_buf);
    //        }
//
    //        /* Insert into cgroup DSQ (portable), let target CPU dispatch it */
    //        scx_bpf_dsq_insert(p, cgrp->kn->id, SCX_SLICE_DFL,
    //                           enq_flags | SCX_ENQ_PREEMPT | SCX_ENQ_HEAD);
    //        cgrp_enqueued(cgrp, cgc);
//
    //        scx_bpf_kick_cpu(target_cpu, SCX_KICK_PREEMPT);
    //        if (should_log(p->comm, this_cpu))
    //            bpf_printk("\tfcg_enqueue: cgrp-insert+kick CPU %d for cgroup %s pid %d (this_cpu=%d)",
    //                       target_cpu, cg_name_buf, p->pid, this_cpu);
	//		goto out_release;
	//	}
	//}
    
    /* Always insert into cgroup DSQ with simple logic; dispatch will handle vtime properly */
    bpf_printk("\tfcg_enqueue: enqueued pid %d to group runqueue", p->pid);
    scx_bpf_dsq_insert(p, cgrp->kn->id, SCX_SLICE_DFL, enq_flags);
    cgrp_enqueued(cgrp, cgc);


    if (taskc && taskc->desired_cpu >= 0)        // <-- kick the right cpu
    {
        scx_bpf_kick_cpu(taskc->desired_cpu, SCX_KICK_PREEMPT);
        bpf_printk("\tfcg_enqueue: kick local CPU %d for pid %d", (s32)taskc->desired_cpu, p->pid);
    }

out_release:
	bpf_cgroup_release(cgrp);
}

/*
 * Walk the cgroup tree to update the active weight sums as tasks wake up and
 * sleep. The weight sums are used as the base when calculating the proportion a
 * given cgroup or task is entitled to at each level.
 */
static void update_active_weight_sums(struct cgroup *cgrp, bool runnable)
{
	struct fcg_cgrp_ctx *cgc;
	bool updated = false;
	int idx;

	cgc = find_cgrp_ctx(cgrp);
	if (!cgc)
		return;

	/*
	 * In most cases, a hot cgroup would have multiple threads going to
	 * sleep and waking up while the whole cgroup stays active. In leaf
	 * cgroups, ->nr_runnable which is updated with __sync operations gates
	 * ->nr_active updates, so that we don't have to grab the cgv_tree_lock
	 * repeatedly for a busy cgroup which is staying active.
	 */
	if (runnable) {
		if (__sync_fetch_and_add(&cgc->nr_runnable, 1))
			return;
		stat_inc(FCG_STAT_ACT);
	} else {
		if (__sync_sub_and_fetch(&cgc->nr_runnable, 1))
			return;
		stat_inc(FCG_STAT_DEACT);
	}

	/*
	 * If @cgrp is becoming runnable, its hweight should be refreshed after
	 * it's added to the weight tree so that enqueue has the up-to-date
	 * value. If @cgrp is becoming quiescent, the hweight should be
	 * refreshed before it's removed from the weight tree so that the usage
	 * charging which happens afterwards has access to the latest value.
	 */
	if (!runnable)
		cgrp_refresh_hweight(cgrp, cgc);

	/* propagate upwards */
	bpf_for(idx, 0, cgrp->level) {
		int level = cgrp->level - idx;
		struct fcg_cgrp_ctx *cgc, *pcgc = NULL;
		bool propagate = false;

		cgc = find_ancestor_cgrp_ctx(cgrp, level);
		if (!cgc)
			break;
		if (level) {
			pcgc = find_ancestor_cgrp_ctx(cgrp, level - 1);
			if (!pcgc)
				break;
		}

		/*
		 * We need the propagation protected by a lock to synchronize
		 * against weight changes. There's no reason to drop the lock at
		 * each level but bpf_spin_lock() doesn't want any function
		 * calls while locked.
		 */
		bpf_spin_lock(&cgv_tree_lock);

		if (runnable) {
			if (!cgc->nr_active++) {
				updated = true;
				if (pcgc) {
					propagate = true;
					pcgc->child_weight_sum += cgc->weight;
				}
			}
		} else {
			if (!--cgc->nr_active) {
				updated = true;
				if (pcgc) {
					propagate = true;
					pcgc->child_weight_sum -= cgc->weight;
				}
			}
		}

		bpf_spin_unlock(&cgv_tree_lock);

		if (!propagate)
			break;
	}

	if (updated)
		__sync_fetch_and_add(&hweight_gen, 1);

	if (runnable)
		cgrp_refresh_hweight(cgrp, cgc);
}

void BPF_STRUCT_OPS(fcg_runnable, struct task_struct *p, u64 enq_flags)
{
	struct cgroup *cgrp;
	u64 now = scx_bpf_now();
	u64 off_ns = scx_start_ts_ns ? (now - scx_start_ts_ns) : 0;
	u64 off_us = off_ns / 1000ULL;
	u64 off_ms_int = off_us / 1000ULL;
	u64 off_ms_frac = off_us % 1000ULL;
	s32 cpu = (s32)bpf_get_smp_processor_id();
	int log = should_log(p->comm, cpu);

	if (log) {
		if (enq_flags & SCX_ENQ_WAKEUP)
			bpf_printk("\trunnable: wake pid %d comm %s at %llu.%03llu ms", p->pid, p->comm, off_ms_int, off_ms_frac);
		else
			bpf_printk("\trunnable: enqueue pid %d comm %s at %llu.%03llu ms (flags=0x%llx)", p->pid, p->comm, off_ms_int, off_ms_frac, enq_flags);
	}

	cgrp = __COMPAT_scx_bpf_task_cgroup(p);
	update_active_weight_sums(cgrp, true);
	bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(fcg_running, struct task_struct *p)
{
	struct cgroup *cgrp;
	struct fcg_cgrp_ctx *cgc;
	s32 cpu = bpf_get_smp_processor_id();
	int log = should_log(p->comm, cpu);
	u64 now = scx_bpf_now();
	u64 off_ns = scx_start_ts_ns ? (now - scx_start_ts_ns) : 0;
	u64 off_us = off_ns / 1000ULL;
	u64 off_ms_int = off_us / 1000ULL;
	u64 off_ms_frac = off_us % 1000ULL;

	if (fifo_sched)
		return;

	cgrp = __COMPAT_scx_bpf_task_cgroup(p);
    if (log) {
        s32 cpu = (s32)bpf_get_smp_processor_id();
        bpf_printk("\trunning: start pid %d comm %s on cpu %d at %llu.%03llu ms", p->pid, p->comm, cpu, off_ms_int, off_ms_frac);
    }
	cgc = find_cgrp_ctx(cgrp);
	if (cgc) {
		/*
		 * @cgc->tvtime_now always progresses forward as tasks start
		 * executing. The test and update can be performed concurrently
		 * from multiple CPUs and thus racy. Any error should be
		 * contained and temporary. Let's just live with it.
		 */
		if (time_before(cgc->tvtime_now, p->scx.dsq_vtime))
			cgc->tvtime_now = p->scx.dsq_vtime;
	}
	bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(fcg_stopping, struct task_struct *p, bool runnable)
{
	struct fcg_task_ctx *taskc;
	struct cgroup *cgrp;
	struct fcg_cgrp_ctx *cgc;
	s32 cpu = bpf_get_smp_processor_id();
	int log = should_log(p->comm, cpu);
	u64 now = scx_bpf_now();
	u64 off_ns = scx_bpf_now() - scx_start_ts_ns;
	u64 off_us = off_ns / 1000ULL;
	u64 off_ms_int = off_us / 1000ULL;
	u64 off_ms_frac = off_us % 1000ULL;

	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	if (!fifo_sched)
		p->scx.dsq_vtime +=
			(SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("task_ctx lookup failed");
		return;
	}

	if (!taskc->bypassed_at)
		goto log_and_out;

	cgrp = __COMPAT_scx_bpf_task_cgroup(p);
	cgc = find_cgrp_ctx(cgrp);
	if (cgc) {
		__sync_fetch_and_add(&cgc->cvtime_delta,
				     p->se.sum_exec_runtime - taskc->bypassed_at);
		taskc->bypassed_at = 0;
	}
	bpf_cgroup_release(cgrp);

log_and_out:
    /* Clear per-CPU current cgid only on sleep so select_cpu can consider this CPU again */
    if (!runnable) {
        u32 kcpu = (u32)bpf_get_smp_processor_id();
        u64 zero = 0;
        bpf_map_update_elem(&cur_cgid, &kcpu, &zero, BPF_ANY);
        if (should_log(p->comm, (s32)kcpu))
            bpf_printk("\tstopping: cur_cgid[cpu=%d] cleared by pid %d", (s32)kcpu, p->pid);
    }
    if (log) {
        s32 cpu = (s32)bpf_get_smp_processor_id();
		if (!runnable)
			bpf_printk("\tstopping: sleep   pid %d comm %s on cpu %d at %llu.%03llu ms", p->pid, p->comm, cpu, off_ms_int, off_ms_frac);
		else if (p->scx.slice > 0)
			bpf_printk("\tstopping: preempt pid %d comm %s on cpu %d at %llu.%03llu ms (slice_left=%u)", p->pid, p->comm, cpu, off_ms_int, off_ms_frac, p->scx.slice);
		else
			bpf_printk("\tstopping: timeslice/yield pid %d comm %s on cpu %d at %llu.%03llu ms", p->pid, p->comm, cpu, off_ms_int, off_ms_frac);
	}
}

void BPF_STRUCT_OPS(fcg_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct cgroup *cgrp;

	cgrp = __COMPAT_scx_bpf_task_cgroup(p);
	update_active_weight_sums(cgrp, false);
	bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(fcg_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	struct fcg_cgrp_ctx *cgc, *pcgc = NULL;

	cgc = find_cgrp_ctx(cgrp);
	if (!cgc)
		return;

	if (cgrp->level) {
		pcgc = find_ancestor_cgrp_ctx(cgrp, cgrp->level - 1);
		if (!pcgc)
			return;
	}

	bpf_spin_lock(&cgv_tree_lock);
	if (pcgc && cgc->nr_active)
		pcgc->child_weight_sum += (s64)weight - cgc->weight;
	cgc->weight = weight;
	bpf_spin_unlock(&cgv_tree_lock);
}

static bool try_pick_next_cgroup(u64 *cgidp)
{
	struct bpf_rb_node *rb_node;
	struct cgv_node_stash *stash;
	struct cgv_node *cgv_node;
	struct fcg_cgrp_ctx *cgc;
	struct cgroup *cgrp;
	u64 cgid;

	/* pop the front cgroup and wind cvtime_now accordingly */
	bpf_spin_lock(&cgv_tree_lock);

	rb_node = bpf_rbtree_first(&cgv_tree);
	if (!rb_node) {
		bpf_spin_unlock(&cgv_tree_lock);
		stat_inc(FCG_STAT_PNC_NO_CGRP);
		*cgidp = 0;
		return true;
	}

	rb_node = bpf_rbtree_remove(&cgv_tree, rb_node);
	bpf_spin_unlock(&cgv_tree_lock);

	if (!rb_node) {
		/*
		 * This should never happen. bpf_rbtree_first() was called
		 * above while the tree lock was held, so the node should
		 * always be present.
		 */
		scx_bpf_error("node could not be removed");
		return true;
	}

	cgv_node = container_of(rb_node, struct cgv_node, rb_node);
	cgid = cgv_node->cgid;

	if (time_before(cvtime_now, cgv_node->cvtime))
		cvtime_now = cgv_node->cvtime;

	/*
	 * If lookup fails, the cgroup's gone. Free and move on. See
	 * fcg_cgroup_exit().
	 */
	cgrp = bpf_cgroup_from_id(cgid);
	if (!cgrp) {
		stat_inc(FCG_STAT_PNC_GONE);
		goto out_free;
	}

	cgc = bpf_cgrp_storage_get(&cgrp_ctx, cgrp, 0, 0);
	if (!cgc) {
    bpf_cgroup_release(cgrp);
		stat_inc(FCG_STAT_PNC_GONE);
		goto out_free;
	}

	/* Only move tasks that are mapped to this CPU */
	{
		bool found_task = false;
		struct task_struct *p;
		s32 this_cpu = bpf_get_smp_processor_id();
		bpf_for_each(scx_dsq, p, cgid, 0) {
			struct fcg_task_ctx *taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
			if (taskc && (taskc->desired_cpu == this_cpu || taskc->desired_cpu < 0)) {
				if (!fifo_sched) {
					scx_bpf_dsq_insert_vtime(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, p->scx.dsq_vtime, 0);
				} else {
					scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
				}
				if (should_log(p->comm, this_cpu)) bpf_printk("\t\t\ttry_pick_next_cgroup: moved task pid %d (desired_cpu=%d) to local CPU %d (vtime=%llu)", p->pid, taskc->desired_cpu, this_cpu, p->scx.dsq_vtime);
				found_task = true;
				break;
			} else if (taskc) {
				//if (should_log(p->comm, this_cpu)) bpf_printk("\t\t\ttry_pick_next_cgroup: SKIP task pid %d (desired_cpu=%d) on CPU %d", p->pid, taskc->desired_cpu, this_cpu);
			}
		}
		if (!found_task) {
			bpf_cgroup_release(cgrp);
			stat_inc(FCG_STAT_PNC_EMPTY);
			goto out_stash;
		}
	}

	/*
	 * Successfully consumed from the cgroup. This will be our current
	 * cgroup for the new slice. Refresh its hweight.
	 */
	cgrp_refresh_hweight(cgrp, cgc);

    char cg_name_buf[32];
    bpf_probe_read_kernel(&cg_name_buf, sizeof(cg_name_buf), cgrp->kn->name);
    bpf_printk("\t\t\ttry_pick_next_cgroup: picked new cgroup %s!", cg_name_buf);

		/* Log the allocated slice (ms) for this cgroup based on its hweight */
		u64 alloc_slice = cgrp_slice_ns * FCG_HWEIGHT_ONE / (cgc->hweight ?: 1);
		u64 alloc_ms = alloc_slice / 1000000ULL;
		u64 base_ms = cgrp_slice_ns / 1000000ULL;
		bpf_printk("\t\t\ttry_pick_next_cgroup: slice_ms for %s: %llu ms (hweight=%u, base=%llu ms)",
			   cg_name_buf, alloc_ms, cgc->hweight, base_ms);

	bpf_cgroup_release(cgrp);

	/*
	 * As the cgroup may have more tasks, add it back to the rbtree. Note
	 * that here we charge the full slice upfront and then exact later
	 * according to the actual consumption. This prevents lowpri thundering
	 * herd from saturating the machine.
	 */
    bpf_spin_lock(&cgv_tree_lock);
	cgv_node->cvtime += cgrp_slice_ns * FCG_HWEIGHT_ONE / (cgc->hweight ?: 1);
	cgrp_cap_budget(cgv_node, cgc);
	bpf_rbtree_add(&cgv_tree, &cgv_node->rb_node, cgv_node_less);
	bpf_spin_unlock(&cgv_tree_lock);

    *cgidp = cgid;
	stat_inc(FCG_STAT_PNC_NEXT);
	return true;

out_stash:
	stash = bpf_map_lookup_elem(&cgv_node_stash, &cgid);
	if (!stash) {
		stat_inc(FCG_STAT_PNC_GONE);
		goto out_free;
	}

	/*
	 * Paired with cmpxchg in cgrp_enqueued(). If they see the following
	 * transition, they'll enqueue the cgroup. If they are earlier, we'll
	 * see their task in the dq below and requeue the cgroup.
	 */
	__sync_val_compare_and_swap(&cgc->queued, 1, 0);

	if (scx_bpf_dsq_nr_queued(cgid)) {
		bpf_spin_lock(&cgv_tree_lock);
		bpf_rbtree_add(&cgv_tree, &cgv_node->rb_node, cgv_node_less);
		bpf_spin_unlock(&cgv_tree_lock);
		stat_inc(FCG_STAT_PNC_RACE);
	} else {
		cgv_node = bpf_kptr_xchg(&stash->node, cgv_node);
		if (cgv_node) {
			scx_bpf_error("unexpected !NULL cgv_node stash");
			goto out_free;
		}
	}

	return false;

out_free:
	bpf_obj_drop(cgv_node);
	return false;
}

static __always_inline void dbg_log_qsizes(u64 cgid, s32 cpu, const char *tag)
{
    u32 cg_q  = scx_bpf_dsq_nr_queued(cgid);
    u32 loc_q = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL); // LOCAL == this cpu
    bpf_printk("[%s] cpu=%d cgid=%llu: cg_q=%u local_q=%u", tag, cpu, cgid, cg_q, loc_q);

    loc_q = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL); // LOCAL == this cpu
    bpf_printk("[%s] cpu=%d cgid=%llu: cg_q=%u local_q=%u", tag, cpu, cgid, cg_q, loc_q);
}

void BPF_STRUCT_OPS(fcg_dispatch, s32 cpu, struct task_struct *prev)
{
	struct fcg_cpu_ctx *cpuc;
	struct fcg_cgrp_ctx *cgc;
	struct cgroup *cgrp;
	u64 now = scx_bpf_now();
	bool picked_next = false;

	bool log = false;
	if (prev && prev->comm) {
		log = comm_eq(prev->comm, "intermittent");
	}

    if (log) bpf_printk("\tfcg_dispatch: Called on CPU %d with prev task pid %d comm %s", cpu, prev == NULL ? -1 : prev->pid, prev == NULL ? "[]" : prev->comm);

	cpuc = find_cpu_ctx();
	if (!cpuc)
		return;

	if (!cpuc->cur_cgid) {
		if (log) bpf_printk("\t\tfcg_dispatch: !cpuc->cur_cgid, picking next cgroup.");
		goto pick_next_cgroup;
	}

	/* The current cgroup is expiring. It was already charged a full slice. */
	cgrp = bpf_cgroup_from_id(cpuc->cur_cgid);
	if (!cgrp) {
		stat_inc(FCG_STAT_CNS_GONE);
		if (log) bpf_printk("\t\tfcg_dispatch: picking next cgroup, cgroup is expiring for good!");
		goto pick_next_cgroup;
	}

	char cg_name_buf[32];
	bpf_probe_read_kernel(&cg_name_buf, sizeof(cg_name_buf), cgrp->kn->name);
	if (log) bpf_printk("\t\tfcg_dispatch: re-evaluating cgroup %s!", cg_name_buf);

    bool task_log = false;
	/* Prevent preemption of "hw" while it has runnable tasks */
    if (time_before(now, cpuc->cur_at + cgrp_slice_ns) ||
        (cg_name_buf[0] == 'h' && cg_name_buf[1] == 'w' && cg_name_buf[2] == '\0')) {
		/* Only move tasks that are mapped to this CPU */
		bool found_task = false;
		struct task_struct *p;
		bpf_for_each(scx_dsq, p, cpuc->cur_cgid, 0) {
			struct fcg_task_ctx *taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
			task_log = comm_eq(p->comm, "intermittent");
			if (taskc && (taskc->desired_cpu == cpu || taskc->desired_cpu < 0)) {
				if (!fifo_sched) {
					scx_bpf_dsq_insert_vtime(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, p->scx.dsq_vtime, 0);
				} else {
					scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
				}
				if (task_log) 
                {
                    bpf_printk("\t\t\tfcg_dispatch: moved task pid %d (desired_cpu=%d) to local CPU %d (vtime=%llu)", p->pid, taskc->desired_cpu, cpu, p->scx.dsq_vtime);
                    dbg_log_qsizes(cpuc->cur_cgid, cpu, "post-move");
                }
                found_task = true;
				break;
			} else if (taskc) {
				if (task_log) bpf_printk("\t\t\tfcg_dispatch: SKIP task pid %d (desired_cpu=%d) on CPU %d", p->pid, taskc->desired_cpu, cpu);
			}
		}
		if (found_task) {
			stat_inc(FCG_STAT_CNS_KEEP);
			if (task_log) bpf_printk("\t\t\tfcg_dispatch: cgroup %s still active, NOT preempted!", cg_name_buf);
			bpf_cgroup_release(cgrp);
			return;
		}
		if (task_log) bpf_printk("\t\t\tfcg_dispatch: cgroup %s empty or no tasks for CPU %d!", cg_name_buf, cpu);
		stat_inc(FCG_STAT_CNS_EMPTY);
	} else {
		if (task_log) bpf_printk("\t\t\tfcg_dispatch: cgroup %s expired!", cg_name_buf);
		stat_inc(FCG_STAT_CNS_EXPIRE);
	}

	cgc = bpf_cgrp_storage_get(&cgrp_ctx, cgrp, 0, 0);
	if (cgc) {
		/*
		 * We want to update the vtime delta and then look for the next
		 * cgroup to execute but the latter needs to be done in a loop
		 * and we can't keep the lock held. Oh well...
		 */
		bpf_spin_lock(&cgv_tree_lock);
		__sync_fetch_and_add(&cgc->cvtime_delta,
				     (cpuc->cur_at + cgrp_slice_ns - now) *
				     FCG_HWEIGHT_ONE / (cgc->hweight ?: 1));
		bpf_spin_unlock(&cgv_tree_lock);
	} else {
		stat_inc(FCG_STAT_CNS_GONE);
	}

	bpf_cgroup_release(cgrp);

pick_next_cgroup:
	cpuc->cur_at = now;

    /* Pull desired cgroup work to this CPU first, else fallback */
    {
        u32 kcpu = (u32)cpu;
        u64 *want = bpf_map_lookup_elem(&cur_cgid, &kcpu);
        if (want && *want) {
            /* Only move tasks that are mapped to this CPU */
            struct task_struct *p;
            bpf_for_each(scx_dsq, p, *want, 0) {
                struct fcg_task_ctx *taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
                bool task_log = comm_eq(p->comm, "intermittent");
                if (taskc && (taskc->desired_cpu == cpu/*|| taskc->desired_cpu < 0*/)) {
                    if (task_log) dbg_log_qsizes(cpuc->cur_cgid, cpu, "pre-move");
                    if (!fifo_sched) {
                        scx_bpf_dsq_insert_vtime(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, p->scx.dsq_vtime, 0);
                    } else {
                        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
                    }
                    if (task_log) 
                    {
                        bpf_printk("\t\t\tfcg_dispatch 2: Moved desired cgroup task pid %d (desired_cpu=%d) to local CPU %d (vtime=%llu)", p->pid, taskc->desired_cpu, cpu, p->scx.dsq_vtime);
                        dbg_log_qsizes(cpuc->cur_cgid, cpu, "post-move");
                    }
                    return;
                } else if (taskc) {
                    //if (task_log) bpf_printk("\t\t\tfcg_dispatch 2: SKIP desired cgroup task pid %d (desired_cpu=%d) on CPU %d", p->pid, taskc->desired_cpu, cpu);
                }
            }
        }
    }
    /* Only move fallback tasks that are mapped to this CPU */
    {
        struct task_struct *p;
        bpf_for_each(scx_dsq, p, FALLBACK_DSQ, 0) {
            struct fcg_task_ctx *taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
            bool task_log = comm_eq(p->comm, "intermittent");
            if (taskc && (taskc->desired_cpu == cpu || taskc->desired_cpu < 0)) {
                if (!fifo_sched) {
                    scx_bpf_dsq_insert_vtime(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, p->scx.dsq_vtime, 0);
                } else {
                    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
                }
                if (task_log) 
                {
                    bpf_printk("\t\t\tfcg_dispatch: Moved FALLBACK_DSQ task pid %d (desired_cpu=%d) to local CPU %d (vtime=%llu)", p->pid, taskc->desired_cpu, cpu, p->scx.dsq_vtime);
                }
                cpuc->cur_cgid = 0;
                return;
            } else if (taskc) {
                if (task_log) bpf_printk("\t\t\tfcg_dispatch: SKIP FALLBACK_DSQ task pid %d (desired_cpu=%d) on CPU %d", p->pid, taskc->desired_cpu, cpu);
            }
        }
    }

	bpf_repeat(CGROUP_MAX_RETRIES) {
		if (try_pick_next_cgroup(&cpuc->cur_cgid)) {
			picked_next = true;
			break;
		}
	}

	/*
	 * This only happens if try_pick_next_cgroup() races against enqueue
	 * path for more than CGROUP_MAX_RETRIES times, which is extremely
	 * unlikely and likely indicates an underlying bug. There shouldn't be
	 * any stall risk as the race is against enqueue.
	 */
	if (!picked_next)
		stat_inc(FCG_STAT_PNC_FAIL);
}

s32 BPF_STRUCT_OPS(fcg_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct fcg_task_ctx *taskc;
	struct fcg_cgrp_ctx *cgc;

	/*
	 * @p is new. Let's ensure that its task_ctx is available. We can sleep
	 * in this function and the following will automatically use GFP_KERNEL.
	 */
	taskc = bpf_task_storage_get(&task_ctx, p, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!taskc)
		return -ENOMEM;

	taskc->bypassed_at = 0;

	if (!(cgc = find_cgrp_ctx(args->cgroup)))
		return -ENOENT;

	p->scx.dsq_vtime = cgc->tvtime_now;

	return 0;
}

int BPF_STRUCT_OPS_SLEEPABLE(fcg_cgroup_init, struct cgroup *cgrp,
			     struct scx_cgroup_init_args *args)
{
	struct fcg_cgrp_ctx *cgc;
	struct cgv_node *cgv_node;
	struct cgv_node_stash empty_stash = {}, *stash;
	u64 cgid = cgrp->kn->id;
	int ret;

	/*
	 * Technically incorrect as cgroup ID is full 64bit while dsq ID is
	 * 63bit. Should not be a problem in practice and easy to spot in the
	 * unlikely case that it breaks.
	 */
	ret = scx_bpf_create_dsq(cgid, -1);
	if (ret)
		return ret;

	cgc = bpf_cgrp_storage_get(&cgrp_ctx, cgrp, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cgc) {
		ret = -ENOMEM;
		goto err_destroy_dsq;
	}

	cgc->weight = args->weight;
	cgc->hweight = FCG_HWEIGHT_ONE;

	ret = bpf_map_update_elem(&cgv_node_stash, &cgid, &empty_stash,
				  BPF_NOEXIST);
	if (ret) {
		if (ret != -ENOMEM)
			scx_bpf_error("unexpected stash creation error (%d)",
				      ret);
		goto err_destroy_dsq;
	}

	stash = bpf_map_lookup_elem(&cgv_node_stash, &cgid);
	if (!stash) {
		scx_bpf_error("unexpected cgv_node stash lookup failure");
		ret = -ENOENT;
		goto err_destroy_dsq;
	}

	cgv_node = bpf_obj_new(struct cgv_node);
	if (!cgv_node) {
		ret = -ENOMEM;
		goto err_del_cgv_node;
	}

	cgv_node->cgid = cgid;
	cgv_node->cvtime = cvtime_now;

	cgv_node = bpf_kptr_xchg(&stash->node, cgv_node);
	if (cgv_node) {
		scx_bpf_error("unexpected !NULL cgv_node stash");
		ret = -EBUSY;
		goto err_drop;
	}

	return 0;

err_drop:
	bpf_obj_drop(cgv_node);
err_del_cgv_node:
	bpf_map_delete_elem(&cgv_node_stash, &cgid);
err_destroy_dsq:
	scx_bpf_destroy_dsq(cgid);
	return ret;
}

void BPF_STRUCT_OPS(fcg_cgroup_exit, struct cgroup *cgrp)
{
	u64 cgid = cgrp->kn->id;

	/*
	 * For now, there's no way find and remove the cgv_node if it's on the
	 * cgv_tree. Let's drain them in the dispatch path as they get popped
	 * off the front of the tree.
	 */
	bpf_map_delete_elem(&cgv_node_stash, &cgid);
	scx_bpf_destroy_dsq(cgid);
}

void BPF_STRUCT_OPS(fcg_cgroup_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	struct fcg_cgrp_ctx *from_cgc, *to_cgc;
	struct fcg_task_ctx *taskc;
	s64 delta;

	/* find_cgrp_ctx() triggers scx_ops_error() on lookup failures */
	if (!(from_cgc = find_cgrp_ctx(from)) || !(to_cgc = find_cgrp_ctx(to)))
		return;

	delta = time_delta(p->scx.dsq_vtime, from_cgc->tvtime_now);
	p->scx.dsq_vtime = to_cgc->tvtime_now + delta;

	/* Re-select CPU when task moves to different cgroup */
	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (taskc) {
		char to_name[32], from_name[32];
		bpf_probe_read_kernel(&to_name, sizeof(to_name), to->kn->name);
		bpf_probe_read_kernel(&from_name, sizeof(from_name), from->kn->name);
		
		/* Check if moving to/from hw cgroup - if so, re-run CPU selection */
		bool to_is_hw = (to_name[0] == 'h' && to_name[1] == 'w' && to_name[2] == '\0');
		bool from_is_hw = (from_name[0] == 'h' && from_name[1] == 'w' && from_name[2] == '\0');
		
		if (to_is_hw != from_is_hw) {
			/* Moving between hw and non-hw cgroups - re-select CPU */
			s32 new_cpu = -1;
			
			if (to_is_hw) {
				/* Moving TO hw cgroup - use common HW CPU selection logic */
				s32 prev_cpu = scx_bpf_task_cpu(p);
				struct bpf_cpumask *tmp = bpf_cpumask_create();
				if (tmp) {
					bpf_cpumask_copy(tmp, (const struct cpumask *)p->cpus_ptr);
					new_cpu = select_cpu_for_hw_task(p, prev_cpu, tmp, true);
					bpf_cpumask_release(tmp);
				}
			} else {
				/* Moving FROM hw cgroup - use any CPU in affinity */
				new_cpu = scx_bpf_pick_any_cpu((const struct cpumask *)p->cpus_ptr, 0);
			}
			
			/* Update desired_cpu if we found a suitable one */
			if (new_cpu >= 0 && bpf_cpumask_test_cpu(new_cpu, (const struct cpumask *)p->cpus_ptr)) {
				taskc->desired_cpu = new_cpu;
				bpf_printk("\tfcg_cgroup_move: pid %d moved %s->%s, new desired_cpu=%d", 
						   p->pid, from_name, to_name, new_cpu);
				
				/* Update cur_cgid for the new CPU */
				u32 kcpu = (u32)new_cpu;
				u64 new_cgid = to->kn->id;
				bpf_map_update_elem(&cur_cgid, &kcpu, &new_cgid, BPF_ANY);
			} else {
				bpf_printk("\tfcg_cgroup_move: pid %d moved %s->%s, no suitable CPU found", 
						   p->pid, from_name, to_name);
			}
		}
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(fcg_init)
{
	scx_start_ts_ns = scx_bpf_now();
	return scx_bpf_create_dsq(FALLBACK_DSQ, -1);
}

void BPF_STRUCT_OPS(fcg_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(flatcg_ops,
	       .select_cpu		= (void *)fcg_select_cpu,
	       .enqueue			= (void *)fcg_enqueue,
	       .dispatch		= (void *)fcg_dispatch,
	       .runnable		= (void *)fcg_runnable,
	       .running			= (void *)fcg_running,
	       .stopping		= (void *)fcg_stopping,
	       .quiescent		= (void *)fcg_quiescent,
	       .init_task		= (void *)fcg_init_task,
	       .cgroup_set_weight	= (void *)fcg_cgroup_set_weight,
	       .cgroup_init		= (void *)fcg_cgroup_init,
	       .cgroup_exit		= (void *)fcg_cgroup_exit,
	       .cgroup_move		= (void *)fcg_cgroup_move,
	       .init			= (void *)fcg_init,
	       .exit			= (void *)fcg_exit,
	       .flags			= SCX_OPS_HAS_CGROUP_WEIGHT | SCX_OPS_ENQ_EXITING | SCX_OPS_SWITCH_PARTIAL,
	       .name			= "flatcg");