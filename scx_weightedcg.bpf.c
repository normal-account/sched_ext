#include <scx/common.bpf.h>
#include "scx_weightedcg.h"
/*
* Maximum amount of retries to find a valid cgroup.
*/
enum {
    FALLBACK_DSQ		= 0,
    CGROUP_MAX_RETRIES	= 1024,
};

char _license[] SEC("license") = "GPL";

const volatile u32 nr_cpus;	/* !0 for veristat, set during init */
const volatile u64 cgrp_slice_ns;
const volatile u64 task_slice_ns;

const u32 NR_CPUS_LOG = 96;
#if RT_ACTIVE_CHECK
const u64 BK_ACTIVE_SLICE_NS = 20000ULL;
#endif
u64 cvtime_now;
#if WEIGHTED_FALLBACK_DSQ
u64 fallback_vtime_now;
#endif

UEI_DEFINE(uei);

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, STAT_NR);
} stats SEC(".maps");

static void stat_inc(enum stat_idx idx)
{
    u32 idx_v = idx;

    u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx_v);
    if (cnt_p)
        (*cnt_p)++;
}

struct cpu_ctx {
    u64			cur_bk_cgid;
    u64			cur_bk_at;

    u64         rt_cnt;
    u64         bk_cnt;
    u64         bk_cnt_pending;

    u64 rt_vtime_now;   // min-vtime base for RT tasks on this CPU

    u32 rt_claim_pid;  // 0 = free, else pid that reserved this cpu for RT
    #if RT_ACTIVE_CHECK
    u32 rt_active;     // 1 once an RT task has been assigned to this CPU
    #endif

#if DEBUG
    u64  first_move_ts;         // when we successfully moved that DSQ to local
#endif
};


#define MAX_CPUS 1024

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_CPUS);
    __type(key, u32);
    __type(value, struct cpu_ctx);
} cpu_ctx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct cgrp_ctx);
} cgrp_ctx SEC(".maps");

struct cgv_node {
    struct bpf_rb_node	rb_node;
    __u64			cvtime;
    __u64			cgid;
};

private(CGV_TREE) struct bpf_spin_lock cgv_tree_lock;
private(CGV_TREE) struct bpf_rb_root cgv_tree_bk __contains(cgv_node, rb_node);
private(CGV_TREE) struct bpf_rb_root cgv_tree_rt __contains(cgv_node, rb_node);

struct cgv_node_stash {
    struct cgv_node __kptr *node;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct cgv_node_stash);
} cgv_node_stash SEC(".maps");

struct task_ctx {
    u64		bypassed_at;    // when the task bypassed the regular scheduling path
    u64     enq_cgid;       // cgroup we credited enq_count to
    
    u32     sel_cls;
    u32     sel_cpu;
    u32     rt_cpu;         // stable CPU assigned to this RT task

    u32     cur_cpu;        // where it's running

    u32     last_cpu;       // where it last ran

#if WEIGHTED_FALLBACK_DSQ
    u64     fallback_slice_ns;
    u8      fallback_weighted; // task is resident in weighted fallback DSQ
#endif

#if DEBUG
    u64 run_start_exec_ns;

    u64 first_enq_ts;     // armed timestamp for enqueue->dispatch latency
    u8  rt_enq_bucket;
#endif
};

struct cls_counters {
    u64 rt;   // # RT cgroups with non-empty DSQ
    u64 bk;   // # BK cgroups with non-empty DSQ
};

/* CLUSTER COUNTS START */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct cls_counters);
} cls_cnts SEC(".maps");

static __always_inline void cls_inc(u32 is_rt)
{
    u32 k = 0;
    struct cls_counters *c = bpf_map_lookup_elem(&cls_cnts, &k);
    if (!c) return;
    if (is_rt) 
        __sync_fetch_and_add(&c->rt, 1);   // lowers to BPF_XADD
    else
        __sync_fetch_and_add(&c->bk, 1);
}

static __always_inline void cls_dec(u32 is_rt)
{
    u32 k = 0;
    struct cls_counters *c = bpf_map_lookup_elem(&cls_cnts, &k);
    if (!c) return;
    if (is_rt)
        __sync_fetch_and_sub(&c->rt, 1);
    else
        __sync_fetch_and_sub(&c->bk, 1);
}

static __always_inline u64 cls_get_rt(void)
{
    u32 k = 0;
    struct cls_counters *c = bpf_map_lookup_elem(&cls_cnts, &k);
    return c ? c->rt : 0;
}

static __always_inline u64 cls_get_bk(void)
{
    u32 k = 0;
    struct cls_counters *c = bpf_map_lookup_elem(&cls_cnts, &k);
    return c ? c->bk : 0;
}

static __always_inline bool increment_enq_count( struct task_ctx *taskc, struct cgrp_ctx *cgc, u64 cgid)
{
    if (!taskc || !cgc) return false;

    // Win once per residency: 0 -> cgid
    if (__sync_val_compare_and_swap(&taskc->enq_cgid, 0, cgid) == 0) 
    {
        u64 old = __sync_fetch_and_add(&cgc->enq_count, 1);
    
        if ( 0 == old )
        {
            cls_inc(cgc->rt_class);
        }

        return true;
    }

    return false;
}

static __always_inline void decrement_enq_count( struct task_ctx *taskc, struct cgrp_ctx *cgc, u64 cgid )
{
    if (!taskc || !cgc ) return;

    u64 task_cgid = taskc->enq_cgid;

    // Win once per residency: cgid -> 0
    u64 enq_cgid = __sync_val_compare_and_swap(&taskc->enq_cgid, task_cgid, 0);

    if ( 0 != enq_cgid && enq_cgid == task_cgid ) 
    {
        // Make sure we decrement the actual cgc which had been incremented (and be move agnostic)
        if ( enq_cgid != cgid )
        {
            log("\tdecrement_enq_count: CGID (%llu) != taskc->enq_cgid (%llu) when decrementing enq_count!", 1, cgid, taskc->enq_cgid);
            struct cgroup *cg = bpf_cgroup_from_id(enq_cgid);
            if ( cg )
            {
                cgc = bpf_cgrp_storage_get(&cgrp_ctx, cg, 0, 0);
                bpf_cgroup_release(cg);
            }
        }

        if ( cgc )
        {
            u64 old = __sync_fetch_and_sub(&cgc->enq_count, 1);
            
            if ( 1 == old )
            {
                cls_dec(cgc->rt_class);
            }
        }
    }
}


/* CLUSTER COUNTS END */


/* PER-CPU ACCOUNTING START */

static __always_inline void cnt_inc(struct cpu_ctx *cpuc, u32 cpu, s32 pid, bool is_rt)
{
    if (!cpuc) return;
    if (is_rt) {
        __sync_fetch_and_add(&cpuc->rt_cnt, 1);
        #if RT_ACTIVE_CHECK
        cpuc->rt_active = 1;
        #endif
    }
    else       __sync_fetch_and_add(&cpuc->bk_cnt, 1);
}

static __always_inline void cnt_inc_pending(struct cpu_ctx *cpuc, u32 cpu)
{
    if (!cpuc) return;
    
    __sync_fetch_and_add(&cpuc->bk_cnt_pending, 1);
}

static __always_inline void cnt_dec_pending(struct cpu_ctx *cpuc, u32 cpu, s32 pid, u64 cgid)
{
    if (!cpuc) {
        scx_bpf_error("cnt_dec_pending: cpuc NULL for cpu %u", cpu);
        return;
    }

    // atomic decrement; returns previous value
    u64 old = __sync_fetch_and_sub(&cpuc->bk_cnt_pending, 1);

    if (old == 0) {
        log("\tcnt_dec_pending: ERROR, cnt PENDING underflow on cpu %u", 0, cpu);
        __sync_fetch_and_add(&cpuc->bk_cnt_pending, 1);
    }
}

static __always_inline void cnt_dec(struct cpu_ctx *cpuc, bool is_rt, u32 cpu, s32 pid, u64 cgid)
{
    if (!cpuc) {
        scx_bpf_error("cnt_dec: cpuc NULL for cpu %u (rt=%u)", cpu, (u32)is_rt);
        return;
    }

    u64 *cnt_ptr = is_rt ? &cpuc->rt_cnt : &cpuc->bk_cnt;

    // atomic decrement; returns previous value
    u64 old = __sync_fetch_and_sub(cnt_ptr, 1);

    if (old == 0) {
        log("\tcnt_dec: ERROR, cnt underflow on cpu %u for pid %d", is_rt, cpu, pid);

        scx_bpf_error("cnt underflow for cpu %u for pid %d (rt=%u)", cpu, pid, (u32)is_rt);
    }
    #if RT_ACTIVE_CHECK
    // TODO: Evaluate the impact of keeping this check
    // else if (old == 1 && cpuc->rt_active)
    // {
    //     cpuc->rt_active = 0;
    // }
    #endif
}

enum cpu_runcls { CPU_IDLING = 0, CPU_BK, CPU_RT };

static __always_inline enum cpu_runcls cpu_cls(u32 cpu, u32 pid)
{  
    struct cpu_ctx *cpuc = bpf_map_lookup_elem(&cpu_ctx, &cpu);
    if (!cpuc) return CPU_BK; // conservative

    if (__sync_fetch_and_add(&cpuc->rt_cnt, 0) )
        return CPU_RT;

    u32 claim_pid = __sync_fetch_and_add(&cpuc->rt_claim_pid, 0);

    if ( claim_pid != 0 && claim_pid != pid )
        return CPU_RT;

    if (__sync_fetch_and_add(&cpuc->bk_cnt, 0) || __sync_fetch_and_add(&cpuc->bk_cnt_pending, 0))
        return CPU_BK;
    return CPU_IDLING;
}

/* PER-CPU ACCOUNTING END */


/* CPUSET TRACKING START*/

struct cpuset_bits {
    __u64 mask[MASK_WORDS];
    __u32 init;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64); // cgid
    __type(value, struct cpuset_bits);
} cpuset_map SEC(".maps");

static __always_inline void cpuset_ensure_entry(__u64 cgid) {
    struct cpuset_bits zero = {};
    bpf_map_update_elem(&cpuset_map, &cgid, &zero, BPF_NOEXIST);
}

static __always_inline void mask_set_cpu(struct cpuset_bits *st, __u32 cpu) {
    __u32 w = cpu >> 6;  // cpu / 64
    __u32 bit = cpu & 63;   // cpu % 64
    if (w >= MASK_WORDS) return;

    __u64 new_bit = (1ull << bit);
    __u64 *slot = &st->mask[w];

    __sync_fetch_and_or(slot, new_bit);
}

static __always_inline bool mask_test_cpu(struct cpuset_bits *st, __u32 cpu) 
{
    __u32 w = cpu >> 6;  // cpu / 64
    __u32 bit = cpu & 63;   // cpu % 64

    if (w >= MASK_WORDS)
        return false;

    __u64 *slot = &st->mask[w];
    __u64 word = __sync_fetch_and_add(slot, 0); // atomic read

    return (word >> bit) & 1ull;
}
static __always_inline void refresh_cgrp_cpuset(__u64 cgid, const struct task_struct *p)
{
    const struct cpumask *src = (const struct cpumask *)p->cpus_ptr;

    struct cpuset_bits *st = bpf_map_lookup_elem(&cpuset_map, &cgid);
    if (!st) return;

    for (int i = 0; i < CPU_MASK_BITS; i++)
    {
        if (i >= nr_cpus || i >= CPU_MASK_BITS) break;
        
        if (bpf_cpumask_test_cpu(i, src)) 
        {   
            mask_set_cpu(st, i);
        }
    }
    st->init = 1;
}

/* CPUSET TRACKING END */

// DUMPING UTILITIES START

#if DEBUG

struct task_vtime_info {
    __u64 cgid;   // cgroup ID (cgrp->kn->id)
    __u64 vtime;  // p->scx.dsq_vtime
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);   // adjust as needed
    __type(key, __u32);           // pid
    __type(value, struct task_vtime_info);
} task_vtime_map SEC(".maps");

struct dump_cgroup_tasks_ctx {
    __u64 target_cgid;
};

static long dump_cgroup_task_cb(void *map, void *key, void *val, void *priv)
{
    __u32 *pidp = key;
    struct task_vtime_info *info = val;
    struct dump_cgroup_tasks_ctx *ctx = priv;

    if (info->cgid != ctx->target_cgid)
        return 0;

    // Channel 0 or rt_class doesn’t matter here; use 0
    log("\tTASK_VTIME cgid=%llu pid=%u vtime=%llu",
        0,
        info->cgid,
        (__u32)*pidp,
        info->vtime);

    return 0;
}

static __always_inline void dump_cgroup_tasks( u32 pid, u64 cgid, u64 vtime )
{
    // 1. Update cur task
    struct task_vtime_info info = {
        .cgid  = cgid,
        .vtime = vtime,
    };
    bpf_map_update_elem(&task_vtime_map, &pid, &info, BPF_ANY);

    // 2. Dump all tasks and their vtime
    struct dump_cgroup_tasks_ctx ctx = {
        .target_cgid = cgid,
    };

    log("TASK_VTIME_DUMP_BEGIN cgid=%llu", 0, cgid);

    bpf_for_each_map_elem(&task_vtime_map, dump_cgroup_task_cb, &ctx, 0);

    log("TASK_VTIME_DUMP_END cgid=%llu", 0, cgid);
}

#endif /* DEBUG */

// DUMPING UTILITIES END

static __always_inline bool str_contains_rt_cgroup_name(const char *s)
{
    const char target[] = RT_CGROUP_NAME;

    _Static_assert(sizeof(target) > 1, "RT_CGROUP_NAME must not be empty");
    _Static_assert(sizeof(target) <= CGROUP_NAME_LEN,
                   "RT_CGROUP_NAME is longer than CGROUP_NAME_LEN");

#pragma clang loop unroll(full)
    for (u32 i = 0; i <= CGROUP_NAME_LEN - sizeof(target); i++) {
        bool match = true;

#pragma clang loop unroll(full)
        for (u32 j = 0; j < sizeof(target) - 1; j++) {
            if (s[i + j] != target[j])
                match = false;
        }

        if (match)
            return true;

        if (!s[i])
            return false;
    }

    return false;
}

// Check if cgroup name or its parent contains RT_CGROUP_NAME.
// Change RT_CGROUP_NAME to "time-sensitive", "interactive", or the string of your liking.
static __always_inline bool is_cgroup_rt(struct cgroup *cgrp)
{
    struct kernfs_node *kn  = NULL;
    struct kernfs_node *pkn = NULL;
    const char *nptr = NULL, *pptr = NULL;
    char leaf[CGROUP_NAME_LEN] = {}, par[CGROUP_NAME_LEN] = {};

    if (!cgrp)
        return false;

    /* leaf name */
    bpf_probe_read_kernel(&kn, sizeof(kn), &cgrp->kn);
    if (!kn)
        return false;

    bpf_probe_read_kernel(&nptr, sizeof(nptr), &kn->name);
    bpf_probe_read_kernel_str(leaf, sizeof(leaf), nptr);
    if (str_contains_rt_cgroup_name(leaf))
        return true;

    // parent name (root has no parent)
    bpf_probe_read_kernel(&pkn, sizeof(pkn), &kn->__parent);
    if (!pkn)
        return false;

    bpf_probe_read_kernel(&pptr, sizeof(pptr), &pkn->name);
    bpf_probe_read_kernel_str(par, sizeof(par), pptr);

    return str_contains_rt_cgroup_name(par);
}

// CGROUP STAT UTILS START

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);             // cgid (cgrp->kn->id)
    __type(value, struct cgrp_stats);
} cgrp_stats SEC(".maps");

static void cgrp_enqueue_stat( struct cgroup *cgrp, struct cgrp_ctx* cgc, s32 pid )
{
#if DEBUG
    if ( !cgrp || !cgc ) return;

    u64 cgid = cgrp->kn->id;

    if ( cgid <= 1 ) return; // Ignore default cgroup

    struct cgrp_stats *cg_stat = bpf_map_lookup_elem(&cgrp_stats, &cgid );
    if (!cg_stat) {
        struct cgrp_stats zero = {};
        if (bpf_map_update_elem(&cgrp_stats, &cgid, &zero, BPF_NOEXIST))
        {
            return;
        }
        
        cg_stat = bpf_map_lookup_elem(&cgrp_stats, &cgid);
    
        if (!cg_stat) return;

        bpf_probe_read_kernel_str(cg_stat->name, sizeof(cg_stat->name), cgrp->kn->name);
        cg_stat->weight = cgc->weight;
        cg_stat->rt_class = is_cgroup_rt( cgrp );
    }

    __sync_fetch_and_add( &cg_stat->enq_cnt, 1 );

    // Read atomically
    if ( 0 == __sync_fetch_and_add( &cg_stat->first_enq_ts, 0) )
    {
        //__u64 ts = scx_bpf_now();
        __u64 ts = bpf_ktime_get_ns();

        __sync_val_compare_and_swap( &cg_stat->first_enq_ts, 0, ts );
        log("\tcgrp_enqueue_stat: setting first_enq_ts = %llu for pid %d", cgc->rt_class, ts, pid);
    }
#endif
}

static void cgrp_dispatch_stat( __u64 cgid, struct cgrp_ctx* cgc, struct cpu_ctx *cpuc )
{
#if DEBUG
    if ( !cgc || !cpuc ) return;

    // 1. Store enqueue-dispatch stats
    struct cgrp_stats *cg_stat = bpf_map_lookup_elem(&cgrp_stats, &cgid );
    if (!cg_stat) return;

    // Read atomically
    __u64 ts = __sync_fetch_and_add( &cg_stat->first_enq_ts, 0 );
    if ( ts == 0 ) return; // Not armed

    // Win the race to clear to 0
    if (__sync_val_compare_and_swap( &cg_stat->first_enq_ts, ts, 0 ) != ts )
        return; // Someone else recorded


    //u64 now = scx_bpf_now();
    u64 now = bpf_ktime_get_ns();

    if ( ts > now ) return;
    
    __u64 lat = now - ts;

    log("\tcgrp_dispatch_stat: ts = %llu, now = %llu, bumping count", cgc->rt_class, ts, now);

    __sync_fetch_and_add( &cg_stat->lat_sum_ns, lat );
    __u64 lat_cnt = __sync_fetch_and_add( &cg_stat->lat_cnt, 1 );

    __u64 lat_max = __sync_fetch_and_add( &cg_stat->lat_max, 0 );

    // No floating point types in BPF code
    __u64 lat_ms_int = lat / 1000000;
    __u64 lat_ms_frac = lat % 1000000;

    if ( lat_cnt > 100 && ( lat > lat_max || ( lat / 10000 ) >= 10 ) )
    {
        if ( cgc->rt_class )
            log("\tcgrp_dispatch_stat: lat = %llu.%llu ms (rt_class = %d), NEW MAX!", cgc->rt_class, lat_ms_int, lat_ms_frac, cgc->rt_class);

        __sync_val_compare_and_swap( &cg_stat->lat_max, lat_max, lat );
    }

    // Prep dispatch-running stats
    if ( cpuc->first_move_ts == 0 )
    {
        __sync_fetch_and_add( &cpuc->first_move_ts, now );
    }

#endif
}

static void cgrp_running_stat( __u64 cgid, struct cgrp_ctx* cgc, struct cpu_ctx *cpuc )
{
#if DEBUG
    if ( !cgc || !cpuc ) return;

    struct cgrp_stats *cg_stat = bpf_map_lookup_elem( &cgrp_stats, &cgid );
    if (!cg_stat) return;

    // Read atomically
    u64 ts = __sync_fetch_and_add( &cpuc->first_move_ts, 0 );
    if ( ts == 0 ) return; // Not armed

    // Win the race to clear to 0
    if (__sync_val_compare_and_swap( &cpuc->first_move_ts, ts, 0 ) != ts )
        return; // Someone else recorded

    u64 lat = scx_bpf_now() - ts;

    // Increment the CGRP stats with the CPU stats
    __sync_fetch_and_add( &cg_stat->move_lat_sum_ns, lat );
    __sync_fetch_and_add( &cg_stat->move_lat_cnt, 1 );

#endif
}

static __always_inline void
task_enqueue_stat(struct task_struct *p, struct task_ctx *taskc, u64 cgid, bool is_idle, bool can_kick)
{
#if DEBUG
    if (!p || !taskc)
        return;

    if (p->pid <= 0)
        return;

    struct cgrp_stats *cg_stat = bpf_map_lookup_elem(&cgrp_stats, &cgid);
    if (!cg_stat)
        return;

    if (__sync_fetch_and_add(&taskc->first_enq_ts, 0) == 0) {
        u64 ts = bpf_ktime_get_ns();
        __sync_val_compare_and_swap(&taskc->first_enq_ts, 0, ts);

        if (is_idle)
        {
            taskc->rt_enq_bucket = CPU_IDLING;
        }
        else if (can_kick)
        {
            taskc->rt_enq_bucket = CPU_BK;
        }
        else 
        {
            taskc->rt_enq_bucket = CPU_RT;
        }
    }
#endif
}

static __always_inline void
task_running_stat(struct task_struct *p, struct task_ctx *taskc,
                   u64 cgid, struct cgrp_ctx *cgc)
{
#if DEBUG
    if (!p || !taskc || !cgc)
        return;

    // Read armed ts from the task
    u64 ts = __sync_fetch_and_add(&taskc->first_enq_ts, 0);
    if (ts == 0)
        return;

    // Win race to consume it once
    if (__sync_val_compare_and_swap(&taskc->first_enq_ts, ts, 0) != ts)
        return;

    u64 now = bpf_ktime_get_ns();
    if (ts > now)
        return;

    u64 lat = now - ts;

    // Attribute to cgroup stats
    struct cgrp_stats *cg_stat = bpf_map_lookup_elem(&cgrp_stats, &cgid);
    if (!cg_stat)
        return;

    u64 *enq_cnt;
    u64 *enq_sum_ns;
    u64 *enq_max;
    
    if ( CPU_IDLING == taskc->rt_enq_bucket )
    {
        enq_cnt = &cg_stat->enq_idle_cnt;
        enq_max = &cg_stat->enq_idle_max;
        enq_sum_ns = &cg_stat->enq_idle_sum_ns;
    }
    else if ( CPU_BK == taskc->rt_enq_bucket)
    {
        enq_cnt = &cg_stat->enq_bk_cnt;
        enq_max = &cg_stat->enq_bk_max;
        enq_sum_ns = &cg_stat->enq_bk_sum_ns;
    }
    else
    {
        enq_cnt = &cg_stat->enq_rt_cnt;
        enq_max = &cg_stat->enq_rt_max;
        enq_sum_ns = &cg_stat->enq_rt_sum_ns;
    }

    __sync_fetch_and_add(enq_sum_ns, lat);
    u64 lat_cnt = __sync_fetch_and_add(enq_cnt, 1);
    u64 lat_max = __sync_fetch_and_add(enq_max, 0);

    if (lat_cnt > 100 && (lat > lat_max || (lat / 10000) >= 1 )) {
        u64 lat_ms_int  = lat / 1000000;
        u64 lat_ms_frac = lat % 1000000;

        log("\t\ttask_running_stat: NEW MAX %u with lat = %llu.%llu ms for pid %d (ts=%llu),", cgc->rt_class, taskc->rt_enq_bucket, lat_ms_int, lat_ms_frac, p->pid, ts);

        __sync_val_compare_and_swap(enq_max, lat_max, lat);
    }
#endif
}


// CGROUP STAT UTILS END

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_ctx);
} task_ctx SEC(".maps");

// Gets inc'd on weight tree changes to expire the cached hweights
u64 hweight_gen = 1;

static __inline bool comm_eq(const char *a, const char *b)
{
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
    if (cpu >= nr_cpus)
        return false;
    return NULL == comm ? false : comm_eq(comm, "intermittent") || comm_eq(comm, "burn_cpu");
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

#define DUMP_MAX_NODES 16


static __always_inline void dump_bk_tree(void)
{
#if DEBUG
    struct cgv_node *nodes[DUMP_MAX_NODES];
    int i, cnt = 0;
    struct bpf_rb_root *root = &cgv_tree_bk;

    /* 1) Take up to DUMP_MAX_NODES nodes out of the BK tree */
    bpf_spin_lock(&cgv_tree_lock);

#pragma clang loop unroll(full)
    for (i = 0; i < DUMP_MAX_NODES; i++) {
        struct bpf_rb_node *rb;
        struct bpf_rb_node *removed;
        struct cgv_node *node;

        rb = bpf_rbtree_first(root);
        if (!rb)
            break;

        removed = bpf_rbtree_remove(root, rb);
        if (!removed)
            break;

        node = container_of(removed, struct cgv_node, rb_node);
        nodes[i] = node;
        cnt++;
    }

    bpf_spin_unlock(&cgv_tree_lock);

    /* 2) Log outside the lock to avoid "function calls under lock" issues */
#pragma clang loop unroll(full)
    for (i = 0; i < DUMP_MAX_NODES; i++) {
        if (i >= cnt)
            break;

        struct cgv_node *node = nodes[i];

        /* First log argument is your "rt_class"/channel; use 0 for BK */
        log("TREE_DEBUG_BK[%d] cgid=%llu cvtime=%llu",
            0,          /* rt_class / channel */
            i,
            node->cgid,
            node->cvtime);
    }

    /* 3) Re-insert the nodes to restore the BK tree exactly as it was */
    bpf_spin_lock(&cgv_tree_lock);

#pragma clang loop unroll(full)
    for (i = 0; i < DUMP_MAX_NODES; i++) {
        if (i >= cnt)
            break;

        struct cgv_node *node = nodes[i];
        bpf_rbtree_add(root, &node->rb_node, cgv_node_less);
    }

    bpf_spin_unlock(&cgv_tree_lock);
#endif
}

static struct cpu_ctx *find_cpu_ctx(u32 cpu)
{
    struct cpu_ctx *cpuc;
    cpuc = bpf_map_lookup_elem(&cpu_ctx, &cpu);
    if (!cpuc) {
        scx_bpf_error("cpu_ctx lookup failed");
        return NULL;
    }
    return cpuc;
}

static struct cgrp_ctx *find_cgrp_ctx(struct cgroup *cgrp)
{
    struct cgrp_ctx *cgc;

    cgc = bpf_cgrp_storage_get(&cgrp_ctx, cgrp, 0, 0);
    if (!cgc) {
        scx_bpf_error("cgrp_ctx lookup failed for cgid %llu", cgrp->kn->id);
        return NULL;
    }
    return cgc;
}

static struct cgrp_ctx *find_ancestor_cgrp_ctx(struct cgroup *cgrp, int level)
{
    struct cgrp_ctx *cgc;

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

static void cgrp_refresh_hweight(struct cgroup *cgrp, struct cgrp_ctx *cgc)
{
    int level;

    if (!cgc->nr_active) {
        stat_inc(STAT_HWT_SKIP);
        return;
    }

    if (cgc->hweight_gen == hweight_gen) {
        stat_inc(STAT_HWT_CACHE);
        return;
    }

    stat_inc(STAT_HWT_UPDATES);
    bpf_for(level, 0, cgrp->level + 1) {
        struct cgrp_ctx *cgc;
        bool is_active;

        cgc = find_ancestor_cgrp_ctx(cgrp, level);
        if (!cgc)
            break;

        if (!level) {
            cgc->hweight = HWEIGHT_ONE;
            cgc->hweight_gen = hweight_gen;
        } else {
            struct cgrp_ctx *pcgc;

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
                stat_inc(STAT_HWT_RACE);
                break;
            }
        }
    }
}

static void cgrp_cap_budget(struct cgv_node *cgv_node, struct cgrp_ctx *cgc)
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
        (2 * HWEIGHT_ONE);
    if (time_before(cvtime, cvtime_now - max_budget))
        cvtime = cvtime_now - max_budget;

    cgv_node->cvtime = cvtime;
}

static void cgrp_enqueued(struct cgroup *cgrp, struct cgrp_ctx *cgc)
{
    struct cgv_node_stash *stash;
    struct cgv_node *cgv_node;
    u64 cgid = cgrp->kn->id;

    char cg_name_buf[32];
    bpf_probe_read_kernel(&cg_name_buf, sizeof(cg_name_buf), cgrp->kn->name);


    stash = bpf_map_lookup_elem(&cgv_node_stash, &cgid);
    if (!stash) {
        scx_bpf_error("cgv_node lookup failed for cgid %llu", cgid);
        return;
    }

    /* paired with cmpxchg in try_pick_next_cgroup() */
    if (__sync_val_compare_and_swap(&cgc->queued, 0, 1)) {

        cgv_node = bpf_kptr_xchg(&stash->node, NULL);
        if (!cgv_node) {
            log("\tcgrp_enqueued: skip because cgc->queued == 1 for cgid %llu (%s)", cgc->rt_class, cgid, cg_name_buf);
            stat_inc(STAT_ENQ_SKIP);
            return;
        }
    }
    else
    {
        /* NULL if the node is already on the rbtree */
        cgv_node = bpf_kptr_xchg(&stash->node, NULL);
    }

    if (!cgv_node) 
    {
        log("\tcgrp_enqueued: cancelled because stash->node is NULL (already on the rbtree) for cgid %llu (%s)", cgc->rt_class, cgid, cg_name_buf);
        stat_inc(STAT_ENQ_RACE);
        return;
    }

    log("\tcgrp_enqueued: confirmed stash->node has been set to NULL for cgid %llu (%s) with cvtime=%llu", cgc->rt_class, cgid, cg_name_buf, cgv_node->cvtime);

    if (cgc->rt_class)
    {
        log("\tcgrp_enqueued: enqueue new cgid %llu (%s) to REAL-TIME tree!", cgc->rt_class, cgid, cg_name_buf);
    }
    else
    {
        log("\tcgrp_enqueued: enqueue new cgid %llu (%s) to BACKGROUND tree!", cgc->rt_class, cgid, cg_name_buf);
    }

    bpf_spin_lock(&cgv_tree_lock);
    cgrp_cap_budget(cgv_node, cgc);

    if (cgc->rt_class)
    {
        bpf_rbtree_add(&cgv_tree_rt, &cgv_node->rb_node, cgv_node_less);
    }
    else 
    {
        bpf_rbtree_add(&cgv_tree_bk, &cgv_node->rb_node, cgv_node_less);
    }

    bpf_spin_unlock(&cgv_tree_lock);
}

/* CPUSET ASSIGNMENT START */

struct rt_cpu_assign_state {
    u32 next_cpu;   // 0, 2, 4, ...
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct rt_cpu_assign_state);
} rt_cpu_assign_map SEC(".maps");

static __always_inline u32 find_first_allowed_cpu(const struct cpumask *allowed)
{
#pragma clang loop unroll(disable)
    for (u32 cpu = 0; cpu < CPU_MASK_BITS; cpu++) {
        if (cpu >= nr_cpus)
            break;

        if (bpf_cpumask_test_cpu((s32)cpu, allowed))
            return cpu;
    }

    return nr_cpus;
}

static s32 alloc_even_rt_cpu(const struct cpumask *allowed)
{
    u32 k = 0;
    struct rt_cpu_assign_state *st = bpf_map_lookup_elem(&rt_cpu_assign_map, &k);

    if (!st)
        return 0;

    s32 cpu = __sync_fetch_and_add(&st->next_cpu, 2);

    /* Naive wrap for masks like 0,2,4,...,14 */
    if (cpu >= nr_cpus || !bpf_cpumask_test_cpu(cpu, allowed)) {
        __sync_lock_test_and_set(&st->next_cpu, 2);
        return 0;
    }

    return cpu;
}

static __always_inline u32 get_or_assign_rt_cpu(struct task_struct *p,
                                                const struct cpumask *allowed)
{
    struct task_ctx * taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);

    if (!taskc)
    {
        scx_bpf_error("get_or_assign_rt_cpu:: taskc is NULL");
        return find_first_allowed_cpu(allowed);
    }

    s32 cpu = taskc->rt_cpu;

    if (cpu >= 0 && cpu < nr_cpus && bpf_cpumask_test_cpu(cpu, allowed))
        return cpu;

    cpu = alloc_even_rt_cpu(allowed);
    taskc->rt_cpu = cpu;
    return cpu;
}


/* CPUSET ASSIGNMENT END */

#if PIN_TASKS
static __attribute__((noinline)) u32
pick_cpu_to_kick_for_rt(struct task_struct *p, u32 hint_cpu,
                        bool *is_idle, bool *can_kick)
{
    const struct cpumask *allowed = (const struct cpumask *)p->cpus_ptr;
    u32 cpu;
    enum cpu_runcls cls;

    if (!is_idle || !can_kick)
        return nr_cpus;

    *is_idle = false;
    *can_kick = false;

    cpu = get_or_assign_rt_cpu(p, allowed);
    if (cpu >= nr_cpus)
        return nr_cpus;

    cls = cpu_cls(cpu, p->pid);

    *is_idle = (cls == CPU_IDLING);
    *can_kick = (cls == CPU_BK);

    return cpu;
}
#else
static __always_inline bool rt_try_claim_cpu(u32 cpu, u32 pid, bool is_idle)
{
    //struct cpu_ctx *cpuc = find_cpu_ctx(cpu);
    struct cpu_ctx *cpuc = bpf_map_lookup_elem(&cpu_ctx, &cpu);
    if (!cpuc) return false;

    if (is_idle && __sync_fetch_and_add(&cpuc->bk_cnt_pending, 0))
        return false;

    // Winner takes CPU. Loser must pick another CPU.
    bool val = __sync_val_compare_and_swap(&cpuc->rt_claim_pid, 0, pid) == 0;

    if ( !val )
    {
        log("pick_cpu_to_kick_for_rt: REJECTED by %u (locked by %u) %d", 1, cpu, cpuc->rt_claim_pid, pid);
    }
    else
    {
        log("pick_cpu_to_kick_for_rt: ACCEPTED by %u (locked by %u)", 1, cpu, cpuc->rt_claim_pid);
    }

    return val;
}


static __always_inline void rt_clear_claim(u32 cpu, u32 pid)
{
    struct cpu_ctx *cpuc = find_cpu_ctx(cpu);
    if (cpuc) 
    {
        // Clear only if this task owns the claim
        u32 prev_pid = __sync_val_compare_and_swap(&cpuc->rt_claim_pid, pid, 0);
    }
}

static __always_inline u32 cpu_load_for_pick(u32 cpu)
{
    struct cpu_ctx *cpuc = bpf_map_lookup_elem(&cpu_ctx, &cpu);

    if ( !cpuc ) return 0;

    u64 num_bk = __sync_fetch_and_add(&cpuc->bk_cnt, 0);
    u64 num_rt = __sync_fetch_and_add(&cpuc->rt_cnt, 0);

    return (u32) ( num_bk + num_rt );
}


static __always_inline void set_flags_from_cls(enum cpu_runcls cls,
                                              bool *is_idle, bool *can_kick)
{
    *is_idle  = (cls == CPU_IDLING);
    *can_kick = (cls == CPU_BK);
}

/* Bounded Euclid gcd (verifier-friendly). */
static __always_inline u32 gcd_u32(u32 a, u32 b)
{
#pragma clang loop unroll(disable)
    for (int i = 0; i < 32; i++) {
        if (!b)
            break;
        u32 t = a % b;
        a = b;
        b = t;
    }
    return a;
}

/* Pick a stride in [1, n-1] such that gcd(stride, n) == 1.
 * Bounded retries, fallback to 1 (always coprime).
 */
static __always_inline u32 pick_coprime_stride(u32 n)
{
    if (n <= 1)
        return 1;

    u32 step = 1;

#pragma clang loop unroll(disable)
    for (int tries = 0; tries < 8; tries++) {
        /* candidate in [1, n-1] */
        u32 cand = (bpf_get_prandom_u32() % (n - 1)) + 1;
        if (gcd_u32(cand, n) == 1) {
            step = cand;
            break;
        }
    }

    return step; /* 1 if we failed to find one in a few tries */
}
static __attribute__((noinline)) u32
pick_cpu_to_kick_for_rt(struct task_struct *p, u32 hint_cpu,
                        bool *is_idle, bool *can_kick)
{
    if (!is_idle || !can_kick)
        return nr_cpus;

    *is_idle = false;
    *can_kick = false;

    const struct cpumask *allowed = (const struct cpumask *)p->cpus_ptr;
    const u32 n = nr_cpus;
    if (!n)
        return nr_cpus;

    /* pid used for claims */
    const u32 pid = (u32)p->pid;

    const bool hint_ok = (hint_cpu < n) &&
                         bpf_cpumask_test_cpu((s32)hint_cpu, allowed);

    enum cpu_runcls hint_cls = CPU_RT;
    u32 hint_load = 0;

    if (hint_ok) {
        hint_cls = cpu_cls(hint_cpu, p->pid);
        if (hint_cls != CPU_IDLING)
            hint_load = cpu_load_for_pick(hint_cpu);
    }

    // Pseudo-random permutation (full cycle via coprime stride)

    u32 start = bpf_get_prandom_u32() % n;
    u32 step  = (n == 1) ? 0 : pick_coprime_stride(n);
    u32 blacklisted = nr_cpus;

    u32 best_bk, best_rt, best_bk_load, best_rt_load;

#pragma clang loop unroll(disable)
    for (u32 attempt = 0; attempt < 2; attempt++) {
        /* If hint is idle, try to claim it (don’t return unclaimed). */
        if (hint_ok && hint_cls == CPU_IDLING) {
            if (rt_try_claim_cpu(hint_cpu, pid, true)) {
                *is_idle = true;
                return hint_cpu;
            }
            /* someone else claimed it – fall through and scan */
        }

        best_bk = nr_cpus, best_bk_load = ~0u;
        best_rt = nr_cpus, best_rt_load = ~0u;
        
        u32 idx = start;

        u32 k = 0;
        bpf_for(k, 0, n) {
            if (bpf_cpumask_test_cpu((s32)idx, allowed)) {
                enum cpu_runcls cls = cpu_cls(idx, p->pid);

                if (cls == CPU_IDLING) {
                    log("cpu IDLE=%u (cls=%u)", 2, idx);

                    // Try to claim immediately; if fails, keep scanning.
                    if (rt_try_claim_cpu(idx, pid, true)) {
                        *is_idle = true;
                        return idx;
                    }

                    // Prevent edge case where all CPUs are idle but claimed. This ensures a valid CPU is returned.
                    if ( best_rt == nr_cpus ) 
                    {
                        log("fallback to best_rt=%u (cls=%u)", 1, idx, (u32)cls);
                        best_rt = idx;
                    }
                } else {
                    //log("cpu NOT IDLE=%u (cls=%u)", 1, idx, (u32)cls);

                    u32 load = cpu_load_for_pick(idx);

                    if (cls == CPU_BK) {
                        if (load < best_bk_load && idx != blacklisted) {
                            best_bk = idx;
                            best_bk_load = load;
                        }
                    } else { /* CPU_RT */
                        if (load < best_rt_load) {
                            best_rt = idx;
                            best_rt_load = load;
                        }
                    }
                }
            }

            if (n > 1) {
                idx += step;
                if (idx >= n)
                    idx -= n;
            }
        }


        log("pick_cpu_to_kick_for_rt: best bk=%u and rt=%u for pid %d", 2, best_bk, best_rt, p->pid);

        // Prefer BK, but claim deterministically before returning.
        if (best_bk != nr_cpus) {
            if (hint_ok && hint_cls == CPU_BK && hint_load == best_bk_load) {
                if (rt_try_claim_cpu(hint_cpu, pid, false)) {
                    set_flags_from_cls(hint_cls, is_idle, can_kick);
                    return hint_cpu;
                }
                if (hint_cpu != best_bk && rt_try_claim_cpu(best_bk, pid, false)) {
                    set_flags_from_cls(CPU_BK, is_idle, can_kick);
                    return best_bk;
                }
            } else {
                if (rt_try_claim_cpu(best_bk, pid, false)) {
                    set_flags_from_cls(CPU_BK, is_idle, can_kick);
                    return best_bk;
                }
            }

            // claim failed -> retry a fresh permutation
            blacklisted = best_bk;
        }
        // nothing usable this attempt
    }

    // If there are no RT CPUs, but all the BK ones were claimed
    if ( best_rt == nr_cpus ) 
    {
        best_rt = best_bk;
    }

    // Fall back to RT, with claim + hint tie-break.
    if (best_rt != nr_cpus) {
        if (hint_ok && hint_cls == CPU_RT && hint_load == best_rt_load) 
        {
            set_flags_from_cls(hint_cls, is_idle, can_kick);
            return hint_cpu;
        } else {
            set_flags_from_cls(CPU_RT, is_idle, can_kick);
            return best_rt;
        }
    }

    log("pick_cpu_to_kick_for_rt: FOUND NOTHING for pid %d", 2, p->pid);

    return nr_cpus;
}
#endif // PIN_TASKS

static void set_bypassed_at(struct task_struct *p, struct task_ctx *taskc)
{
	/*
	 * Tell stopping() that this bypassed the regular scheduling path
	 * and should be force charged to the cgroup. 0 is used to indicate that
	 * the task isn't bypassing, so if the current runtime is 0, go back by
	 * one nanosecond.
	 */
	taskc->bypassed_at = p->se.sum_exec_runtime ?: (u64)-1;
}

s32 BPF_STRUCT_OPS(select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    bool is_idle = false;

    struct task_ctx * taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (!taskc) {
        scx_bpf_error("task_ctx lookup failed");
        return prev_cpu;
    }

    struct cgroup *cgrp;
    struct cgrp_ctx *cgc;

    cgrp = scx_bpf_task_cgroup(p);
    cgc = find_cgrp_ctx(cgrp);

    // IF this is the RT class
    if ( cgc && cgc->rt_class)
    {
        if ( taskc->last_cpu != nr_cpus && taskc->last_cpu != prev_cpu )
        {
            log("\tselect_cpu: MISMATCH in select_cpu, taskc->last_cpu=%u while prev_cpu=%d", 2, taskc->last_cpu, prev_cpu);
        }


        bool can_kick = false;
        taskc->sel_cpu = pick_cpu_to_kick_for_rt(p, prev_cpu, &is_idle, &can_kick);
        taskc->sel_cls = cpu_cls(taskc->sel_cpu, p->pid);

        log("\tselect_cpu: setting SEL CPU %d for pid %d (cls=%u)", 2, taskc->sel_cpu, p->pid, (u32)taskc->sel_cls);

        //if ( taskc->sel_cls == CPU_IDLING )
        //if( false )
        {
            s32 tgt = taskc->sel_cpu;
            u64 cgid = cgrp->kn->id;

            cgrp_enqueue_stat(cgrp, cgc, p->pid);
            task_enqueue_stat(p, taskc, cgid, is_idle, can_kick);
            taskc->sel_cpu = nr_cpus;

            bool is_behind = false;
            struct cpu_ctx *tgtc = bpf_map_lookup_elem(&cpu_ctx, &tgt);
            if (tgtc)
            {
                #if RT_VTIME
                if ( !is_idle && !can_kick )
                {
                    // Determine if task should be enqueued at head or not
                    u64 now_v = __sync_fetch_and_add(&tgtc->rt_vtime_now, 0);
                    u64 tv    = p->scx.dsq_vtime;
                    //u64 slack_v = task_slice_ns * 100 / (p->scx.weight ?: 1);
    
                    s64 d = time_delta(now_v, tv);   // signed
                    is_behind = d > 0;
                    //is_behind = d > (s64)slack_v;
    
                     log("\tenqueue: pid %d cpu %u behind=%d (now_v=%llu, dsd_vtime=%llu, d=%lld > slack=%llu)", cgc->rt_class, p->pid, tgt, is_behind, now_v, tv, d, slack_v );
                }
                #endif
                
                cnt_inc(tgtc, tgt, p->pid, true);
            }

            u64 rt_flags = SCX_ENQ_CPU_SELECTED;
            if ( is_idle || can_kick || is_behind ) rt_flags |= SCX_ENQ_HEAD | SCX_ENQ_PREEMPT;

            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | tgt, task_slice_ns, rt_flags);

            taskc->cur_cpu = tgt;
            #if !PIN_TASKS
                rt_clear_claim(tgt, p->pid);
            #endif

            if ( is_idle )
                scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
           else if ( can_kick || is_behind)
                scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);


            bpf_cgroup_release(cgrp);
            return tgt;
        }

        bpf_cgroup_release(cgrp);

        return taskc->sel_cpu;
    }

    bpf_cgroup_release(cgrp);

    // ELSE: This is a Background task

	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
    
	if (is_idle) {
    //if (is_idle && p->nr_cpus_allowed != nr_cpus) {
		struct cpu_ctx *cpuc = find_cpu_ctx(cpu);
		enum cpu_runcls cls = cpu_cls(cpu, 0);

		if ( cpuc && cls != CPU_RT )
		{
			cnt_inc_pending(cpuc, cpu);

			cls = cpu_cls(cpu, 0);
			if ( cls != CPU_RT )
			{
				set_bypassed_at(p, taskc);
				stat_inc(STAT_LOCAL);
#if WEIGHTED_FALLBACK_DSQ
                taskc->fallback_weighted = 0;
#endif
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
            }
			else
			{
				cnt_dec_pending(cpuc, cpu, 0, 0);
			}
		}
	}

	return cpu;


    // 1. Try to pick a fully idle CPU from the allowed mask
    // SCX_PICK_IDLE_CORE prefers physical cores that are totally idle
    // s32 idle_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, SCX_PICK_IDLE_CORE);
    
    // if (idle_cpu >= 0) {
    //     return idle_cpu; // Found an idle CPU, move there immediately!
    // }

    // // 2. If no idle CPU, fall back to default (locality)
    // return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

static __always_inline void log_enq_flags(const char *tag,
    struct task_struct *p,
    u64 f)
{
/* Raw mask */
log("%s: pid=%d enq_flags=0x%llx", 0, tag, p->pid, f);

#define SHOW(_fl) do { if (f & (_fl)) log("  - " #_fl, 0); } while (0)

/* public flags */
SHOW(SCX_ENQ_WAKEUP);        /* enqueue due to wakeup */
SHOW(SCX_ENQ_HEAD);          /* place at head of DSQ */
SHOW(SCX_ENQ_CPU_SELECTED);  /* select_cpu chose a CPU */
SHOW(SCX_ENQ_PREEMPT);       /* preempt target */
SHOW(SCX_ENQ_REENQ);         /* re-enqueue (e.g. yield/time slice) */
SHOW(SCX_ENQ_LAST);          /* last public bit (sentinel-ish) */

/* internal/reserved range (top bits) */
SHOW(SCX_ENQ_CLEAR_OPSS);    /* clear op-sched state (internal) */
SHOW(SCX_ENQ_DSQ_PRIQ);      /* DSQ is prio-queued (internal) */

#undef SHOW

/* highlight any unknown bits (handy when your headers differ) */
{
const u64 known =
SCX_ENQ_WAKEUP | SCX_ENQ_HEAD | SCX_ENQ_CPU_SELECTED |
SCX_ENQ_PREEMPT | SCX_ENQ_REENQ | SCX_ENQ_LAST |
SCX_ENQ_CLEAR_OPSS | SCX_ENQ_DSQ_PRIQ;
u64 unknown = f & ~known;
if (unknown)
log("  - unknown_bits: 0x%llx", 0, unknown);
}
}

static __always_inline bool starts_with(const char s[TASK_COMM_LEN],
                                        const char *prefix)
{
#pragma unroll
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        char pc = prefix[i];
        char sc = s[i];

        if (pc == '\0')
            return true;   // matched the whole prefix

        if (sc == '\0')
            return false;  // string ended before prefix

        if (sc != pc)
            return false;  // mismatch
    }

    return false; // prefix longer than TASK_COMM_LEN
}

void BPF_STRUCT_OPS(enqueue, struct task_struct *p, u64 enq_flags)
{
    struct task_ctx *taskc;
    struct cgroup *cgrp;
    struct cgrp_ctx *cgc;
    struct cpu_ctx *tgtc;

    taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (!taskc) {
        scx_bpf_error("task_ctx lookup failed");
        return;
    }

    cgrp = scx_bpf_task_cgroup(p);

    cgc = find_cgrp_ctx(cgrp);
    if (!cgc)
        goto out_release;

    u64 cgid = cgrp->kn->id;

    bool is_idle = false;
    bool can_kick = false;
    u32 tgt = nr_cpus;

    cgrp_enqueue_stat( cgrp, cgc, p->pid );

    if ( cgc->rt_class )
    {
        const struct cpumask *allowed = (const struct cpumask *)p->cpus_ptr;

        bool sel_cpu_allowed = taskc->sel_cpu < nr_cpus &&
                               bpf_cpumask_test_cpu(taskc->sel_cpu, allowed);

        enum cpu_runcls cls = taskc->sel_cls;

        if (sel_cpu_allowed)
        {
            tgt = taskc->sel_cpu;
            is_idle  = (cls == CPU_IDLING);
            can_kick = (cls == CPU_BK);
        }
        else
        {
            tgt = pick_cpu_to_kick_for_rt(p, taskc->last_cpu, &is_idle, &can_kick);
            cls = cpu_cls(tgt, p->pid);
            taskc->sel_cls = cls;
        }

        tgtc = bpf_map_lookup_elem(&cpu_ctx, &tgt);

        // Task accounting
        task_enqueue_stat( p, taskc, cgid, is_idle, can_kick );
        taskc->sel_cpu = nr_cpus;

        bool is_behind = false;
        if (tgtc)
        {
            #if RT_VTIME
            if ( !is_idle && !can_kick )
            {
                // Determine if task should be enqueued at head or not
                u64 now_v = __sync_fetch_and_add(&tgtc->rt_vtime_now, 0);
                u64 tv    = p->scx.dsq_vtime;
                //u64 slack_v = task_slice_ns * 100 / (p->scx.weight ?: 1);

                s64 d = time_delta(now_v, tv);   // signed
                is_behind = d > 0;
                //is_behind = d > (s64)slack_v;

                 log("\tenqueue: pid %d cpu %u behind=%d (now_v=%llu, dsd_vtime=%llu, d=%lld > slack=%llu)", cgc->rt_class, p->pid, tgt, is_behind, now_v, tv, d, slack_v );
            }
            #endif

            cnt_inc(tgtc, tgt, p->pid, true);
        }
        
        // Task direct enqueue 
        u64 rt_flags = enq_flags | SCX_ENQ_CPU_SELECTED;// | SCX_ENQ_HEAD; //| SCX_ENQ_PREEMPT;

        if ( is_idle || can_kick || is_behind ) rt_flags = rt_flags | SCX_ENQ_HEAD | SCX_ENQ_PREEMPT;
        
#if WEIGHTED_FALLBACK_DSQ
        taskc->fallback_weighted = 0;
#endif
        scx_bpf_dsq_insert( p, SCX_DSQ_LOCAL_ON | tgt, task_slice_ns, rt_flags );

        taskc->cur_cpu = tgt;

        #if !PIN_TASKS
            rt_clear_claim( tgt, p->pid );
        #endif

        if ( is_idle )
        {
            log("\tenqueue: direct kick IDLE CPU %d for pid %d", cgc->rt_class, tgt, p->pid);
            scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
        }
        else if ( can_kick || is_behind )
        {
            log("\tenqueue: direct kick PREEMPT CPU %d for pid %d ", /*cgc->rt_class*/2, tgt, p->pid);
            scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
        }
    }
    else
    {

        if (p->nr_cpus_allowed != nr_cpus) {
            set_bypassed_at(p, taskc);
    
            u32 cpu = bpf_get_smp_processor_id();
            struct cpu_ctx *cpuc = find_cpu_ctx(cpu);

            /*
             * The global dq is deprioritized as we don't want to let tasks
             * to boost themselves by constraining its cpumask. The
             * deprioritization is rather severe, so let's not apply that to
             * per-cpu kernel threads. This is ham-fisted. We probably wanna
             * implement per-cgroup fallback dq's instead so that we have
             * more control over when tasks with custom cpumask get issued.
             */
            //
            //if (p->nr_cpus_allowed == 1 && (p->flags & PF_WQ_WORKER)) {
            if (p->nr_cpus_allowed == 1 && (p->flags & PF_KTHREAD)) {
                stat_inc(STAT_LOCAL);
#if WEIGHTED_FALLBACK_DSQ
                taskc->fallback_weighted = 0;
#endif
                scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL,
                    enq_flags);
            } else
            {

            log("\tenqueue: RT active and weight < 100, skipping global enqueue for pid %d", 2, p->pid);

#if WEIGHTED_FALLBACK_DSQ
                u64 tvtime = p->scx.dsq_vtime;
                #if RT_ACTIVE_CHECK
                u64 slice = cpuc && cpuc->rt_active ? BK_ACTIVE_SLICE_NS : task_slice_ns;
                #else
                u64 slice = task_slice_ns;
                #endif

                stat_inc(STAT_GLOBAL);
                cgrp_refresh_hweight(cgrp, cgc);

                if (time_before(tvtime, fallback_vtime_now - task_slice_ns))
                    tvtime = fallback_vtime_now - task_slice_ns;

                taskc->fallback_weighted = 1;
                taskc->fallback_slice_ns = slice;
                scx_bpf_dsq_insert_vtime(p, FALLBACK_DSQ, slice, tvtime, enq_flags);
#else
                stat_inc(STAT_GLOBAL);
                scx_bpf_dsq_insert(p, FALLBACK_DSQ, SCX_SLICE_DFL,
                    enq_flags);
#endif
            }
            goto out_release;
        }
        
        u64 tvtime = p->scx.dsq_vtime;

        /*
        * Limit the amount of budget that an idling task can accumulate
        * to one slice.
        */
        if (time_before(tvtime, cgc->tvtime_now - task_slice_ns))
            tvtime = cgc->tvtime_now - task_slice_ns;

        log("\tenqueue: NOT A DIRECT ENQUEUE ON CPU %d for pid %d on cgid %llu with slice %llu", cgc->rt_class, tgt, p->pid, cgid, task_slice_ns);

        // Credit once per DSQ residency
        increment_enq_count( taskc, cgc, cgid );
#if WEIGHTED_FALLBACK_DSQ
        taskc->fallback_weighted = 0;
#endif

        cgrp_enqueued(cgrp, cgc);

        scx_bpf_dsq_insert_vtime(p, cgrp->kn->id, task_slice_ns, tvtime, enq_flags);
    }

    log("\tenqueue: enqueue task %d (cgid %llu, q=%d) slice=%llu enq_count=%llu", cgc->rt_class, p->pid, cgrp->kn->id,
        scx_bpf_dsq_nr_queued(cgrp->kn->id), cgrp_slice_ns, cgc->enq_count);

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
    struct cgrp_ctx *cgc;
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
        stat_inc(STAT_ACT);
    } else {
        if (__sync_sub_and_fetch(&cgc->nr_runnable, 1))
            return;
        stat_inc(STAT_DEACT);
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
        struct cgrp_ctx *cgc, *pcgc = NULL;
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

void BPF_STRUCT_OPS(runnable, struct task_struct *p, u64 enq_flags)
{
    struct cgroup *cgrp;
    struct cgrp_ctx *cgc;

    cgrp = scx_bpf_task_cgroup(p);
    cgc = find_cgrp_ctx(cgrp);

#if DEBUG
    u8 rt_class = cgc ? cgc->rt_class : 0;
    log("\trunnable: pid %d comm %s", rt_class, p->pid, p->comm);
#endif
    refresh_cgrp_cpuset( cgrp->kn->id, p );
    update_active_weight_sums(cgrp, true);
    bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(running, struct task_struct *p)
{
    struct cgroup *cgrp;
    struct cgrp_ctx *cgc;
    struct cpu_ctx *cpuc;

    /* Update per-CPU current cgid immediately for selected CPU */
    cgrp = scx_bpf_task_cgroup(p);
    cgc = find_cgrp_ctx(cgrp);

    u32 cpu = bpf_get_smp_processor_id();
    cpuc = find_cpu_ctx(cpu);

    if (cpuc && cpuc->rt_claim_pid == p->pid)
    {
        // Sometimes a process goes straight from select_cpu to running, skipping enqueue.
        // In that case, we need to clear the claim here.
        #if !PIN_TASKS
            rt_clear_claim(cpu, p->pid);
        #endif    
    }

    u64 cgid = cgrp->kn->id;
    struct task_ctx *taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (taskc) {
        taskc->last_cpu = cpu;
        
        if (taskc->cur_cpu == nr_cpus)
        {
            taskc->cur_cpu = cpu;

            cnt_inc(cpuc, cpu, p->pid, cgc ? cgc->rt_class : 0);
            cnt_dec_pending(cpuc, cpu, p->pid, cgid);
        }

        #if DEBUG
            taskc->run_start_exec_ns = p->se.sum_exec_runtime;
        #endif
    }

    log("\trunning cpu=%d: pid %d comm %s (cur_cgid <= %llu, slice=%llu)", (cgc ? 2 : 0), cpu, p->pid, p->comm, cgid, p->scx.slice);

    if (cgc) 
    {
        if ( cgc->rt_class )
        {
            task_running_stat( p, taskc, cgid, cgc );
        }
        else
        {
            cgrp_running_stat( cgid, cgc, cpuc );
            #if RT_ACTIVE_CHECK
            //if ( cpuc && cpuc->rt_active && p->scx.slice > BK_ACTIVE_SLICE_NS )
            if ( cgc->weight < 100 && cpuc && cpuc->rt_active && p->scx.slice > BK_ACTIVE_SLICE_NS )
                p->scx.slice = BK_ACTIVE_SLICE_NS;
            #endif
        }

        // Decrement the enq_count if applicable and set the enq cgid to 0
        decrement_enq_count( taskc, cgc, cgid );

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

void BPF_STRUCT_OPS(stopping, struct task_struct *p, bool runnable)
{
    struct task_ctx *taskc;
    struct cgroup *cgrp;
    struct cgrp_ctx *cgc;

    u32 cpu = bpf_get_smp_processor_id();
    struct cpu_ctx *cpuc = find_cpu_ctx(cpu);


    int rt_class = 0;
    taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (!taskc) {
        scx_bpf_error("task_ctx lookup failed");
        goto log_and_out;
    }

    cgrp = scx_bpf_task_cgroup(p);
    cgc = find_cgrp_ctx(cgrp);

    u64 cgid = cgrp ? cgrp->kn->id : 0;

    rt_class = cgc && cgc->rt_class;

    /*
    * Scale the execution time by the inverse of the weight and charge.
    * Pinned BK tasks in FALLBACK_DSQ don't go through cgv_tree_bk, so make
    * their task vtime carry the cgroup weight directly.
    */
#if WEIGHTED_FALLBACK_DSQ
    if (taskc->fallback_weighted && cgc && !cgc->rt_class) {
        u64 charged_slice = taskc->fallback_slice_ns ?: task_slice_ns;
        u64 used = charged_slice > p->scx.slice ? charged_slice - p->scx.slice : 0;
        p->scx.dsq_vtime += used * HWEIGHT_ONE / (cgc->hweight ?: 1);
        if (time_before(fallback_vtime_now, p->scx.dsq_vtime))
            fallback_vtime_now = p->scx.dsq_vtime;
    } else {
        u64 used = task_slice_ns > p->scx.slice ? task_slice_ns - p->scx.slice : 0;
        p->scx.dsq_vtime += used * 100 / p->scx.weight;
    }
    taskc->fallback_weighted = 0;
    taskc->fallback_slice_ns = 0;
#else
    {
        u64 used = task_slice_ns > p->scx.slice ? task_slice_ns - p->scx.slice : 0;
        p->scx.dsq_vtime += used * 100 / p->scx.weight;
    }
#endif

#if RT_VTIME
    if ( cpuc && cgc && cgc->rt_class )
    {
        u64 v = p->scx.dsq_vtime;
        u64 cur = __sync_fetch_and_add(&cpuc->rt_vtime_now, 0);
        if (time_before(cur, v))
            __sync_val_compare_and_swap(&cpuc->rt_vtime_now, cur, v);
    }
#endif

	if (cgc && taskc->bypassed_at)
    {
		__sync_fetch_and_add(&cgc->cvtime_delta,
				     p->se.sum_exec_runtime - taskc->bypassed_at);
		taskc->bypassed_at = 0;
	}

	bpf_cgroup_release(cgrp);

log_and_out:
/* Clear per-CPU current cgid only on sleep so select_cpu can consider this CPU again */

    if ( taskc && taskc->cur_cpu != nr_cpus )
    {
        if ( taskc->cur_cpu != cpu )
        {
            log("\tstopping: ERROR, task->cur_cpu (%d) != cpu (%d) for pid %d!!!", rt_class, taskc->cur_cpu, cpu, p->pid);
        }

        struct cpu_ctx *cpuc = find_cpu_ctx(taskc->cur_cpu);

        cnt_dec( cpuc, rt_class, taskc->cur_cpu, p->pid, cgid);

        taskc->cur_cpu = nr_cpus;
    }
    
#if DEBUG
    u64 delta = taskc ? ( p->se.sum_exec_runtime - taskc->run_start_exec_ns ) : 0;

    if ( delta > 500000 && !rt_class )
    {
        log("\tstopping: WARNING, pid %d on cpu %d comm %s ran %llu ns", rt_class, p->pid, cpu, p->comm, delta);
    }

    if ( !runnable )
    {
        log("\tstopping: cpu %d sleep pid %d comm %s (cur_cgid cleared, ran %llu ns)", rt_class, cpu, p->pid, p->comm, delta);
    }
    else if (p->scx.slice > 0)
    {
        log("\tstopping: preempt pid %d comm %s on cpu %d (slice_left=%u, ran %llu ns)", rt_class, p->pid, p->comm, cpu, p->scx.slice, delta);
    }
    else
    {
        log("\tstopping: timeslice/yield pid %d comm %s on cpu %d (ran %llu ns)", rt_class, p->pid, p->comm, cpu, delta);
    }
#endif 
}

#define DEQUEUE_SLEEP 1
void BPF_STRUCT_OPS(dequeue, struct task_struct *p, u64 deq_flags)
{
#if WEIGHTED_FALLBACK_DSQ
    struct task_ctx *taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (taskc) {
        taskc->fallback_weighted = 0;
        taskc->fallback_slice_ns = 0;
    }
#endif

    if (deq_flags & DEQUEUE_SLEEP)
    {
        log("\tdequeue: SLEEP pid %d comm %s", 1, p->pid, p->comm);
    }
    else 
    {
        log("\tdequeue: pid %d comm %s state %u", 1, p->pid, p->comm, p->__state);
    }
}

void BPF_STRUCT_OPS(quiescent, struct task_struct *p, u64 deq_flags)
{
    struct cgrp_ctx *cgc;
    struct cgroup *cgrp;

    cgrp = scx_bpf_task_cgroup(p);
    update_active_weight_sums(cgrp, false);

    cgc = find_cgrp_ctx(cgrp);

    // Decrement the enq_count if applicable and set the enq cgid to 0
    if ( cgc )
    {
        struct task_ctx *taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
        decrement_enq_count( taskc, cgc, cgrp->kn->id );
    }

    // Remove vtime tracking entry for this task
    #if DEBUG
    {
        __u32 pid = (__u32)p->pid;
        bpf_map_delete_elem(&task_vtime_map, &pid);
    }
    #endif

    bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
    struct cgrp_ctx *cgc, *pcgc = NULL;

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

    /* *** invalidate cached hweights so refresh actually runs *** */
    __sync_fetch_and_add(&hweight_gen, 1);

    /* Optional: refresh now if active so next dispatch uses new hweight */
    if (cgc->nr_active)
        cgrp_refresh_hweight(cgrp, cgc);
}

inline static void try_stash_node( u64 cgid, struct cgrp_ctx *cgc, struct bpf_rb_root *cgv_tree, struct cgv_node *cgv_node, s32 cpu )
{
    if ( NULL == cgc || NULL == cgv_tree || NULL == cgv_node ) return;

    struct cgv_node_stash *stash = bpf_map_lookup_elem(&cgv_node_stash, &cgid);

    if ( stash )
    {
        __sync_val_compare_and_swap( &cgc->queued, 1, 0 );

        cgv_node = bpf_kptr_xchg(&stash->node, cgv_node);
        log("\tdispatch: STASHING node for cgid %llu on cpu %d", cgc->rt_class, cgid, cpu );

        u64 enq_count =__sync_fetch_and_add( &cgc->enq_count, 0 );
        u32 qsz  = scx_bpf_dsq_nr_queued( cgid );

        if ( ( enq_count > 0 || qsz > 0 ) && 0 == __sync_val_compare_and_swap( &cgc->queued, 0, 1 ) ) // Race condition with enqueue, we must undo the stash!
        {
            log("\tdispatch: RACE-CONDITION with enqueue, undoing STASH cgid %llu on cpu %d (qsz=%u)", cgc->rt_class, cgid, cpu, qsz);

            struct cgv_node *back = bpf_kptr_xchg(&stash->node, NULL);
            if ( back )
            {
                bpf_spin_lock( &cgv_tree_lock );
                
                cgrp_cap_budget( back, cgc );

                bpf_rbtree_add( cgv_tree, &back->rb_node, cgv_node_less );

                bpf_spin_unlock( &cgv_tree_lock );
            }
        }
    }

    if ( cgv_node ) bpf_obj_drop( cgv_node );
}

static bool try_pick_next_cgroup(u64 *cgidp, struct bpf_rb_root *cgv_tree, s32 cpu, struct cpu_ctx *cpuc)
{
    struct bpf_rb_node *rb_node;
    struct cgrp_ctx *cgc = NULL;
    struct cgv_node *cgv_node = NULL;
    struct cgroup *cgrp;
    u64 cgid;

    bpf_spin_lock(&cgv_tree_lock);

    rb_node = bpf_rbtree_first(cgv_tree);
    if (!rb_node) {
        bpf_spin_unlock(&cgv_tree_lock);
        stat_inc(STAT_PNC_NO_CGRP);
        if ( cpu < NR_CPUS_LOG ) log("\t\ttry_pick_next_cgroup: no cgroup found (is RT tree %d)", (&cgv_tree_rt == cgv_tree) ? 1 : 0, &cgv_tree_rt == cgv_tree);
        return true;
    }

    rb_node = bpf_rbtree_remove(cgv_tree, rb_node);
    if (!rb_node) {
        bpf_spin_unlock(&cgv_tree_lock);
        scx_bpf_error("node could not be removed");
        return true;
    }

    cgv_node = container_of(rb_node, struct cgv_node, rb_node);
    cgid = cgv_node->cgid;
    bpf_spin_unlock(&cgv_tree_lock);

    cgrp = bpf_cgroup_from_id(cgid);

    if (cgrp) cgc = bpf_cgrp_storage_get(&cgrp_ctx, cgrp, 0, 0);
    if (!cgrp || !cgc) 
    {
        stat_inc(STAT_PNC_GONE);
        log("\t\ttry_pick_next_cgroup: !cgrp || !cgc (is RT tree %d)", (&cgv_tree_rt == cgv_tree) ? 1 : 0, &cgv_tree_rt == cgv_tree);

        bpf_obj_drop( cgv_node );
        if (cgrp) bpf_cgroup_release(cgrp);

        return true;
    }

    struct cpuset_bits *st = bpf_map_lookup_elem(&cpuset_map, &cgid);
    if (!st || !st->init || !mask_test_cpu(st, (u32)cpu)) 
    {
        log("\t\ttry_pick_next_cgroup: cgid %llu not allowed on cpu %d (is RT tree %d)",
            (&cgv_tree_rt == cgv_tree) ? 1 : 0, cgid, cpu, &cgv_tree_rt == cgv_tree);

        bpf_spin_lock(&cgv_tree_lock);
        cgv_node->cvtime += cgrp_slice_ns * HWEIGHT_ONE / (cgc->hweight ?: 1);
        bpf_rbtree_add(cgv_tree, &cgv_node->rb_node, cgv_node_less);
        bpf_spin_unlock(&cgv_tree_lock);

        stat_inc(STAT_PNC_AFFINITY);

        bpf_cgroup_release(cgrp);
        return false;
    }

    enum cpu_runcls cls = cpu_cls(cpu, 0);
    if ( cls == CPU_RT )
    {
        bpf_spin_lock(&cgv_tree_lock);
        bpf_rbtree_add(cgv_tree, &cgv_node->rb_node, cgv_node_less);
        bpf_spin_unlock(&cgv_tree_lock);

        bpf_cgroup_release(cgrp);
        return true;
    }

    cnt_inc_pending(cpuc, cpu);

    cls = cpu_cls(cpu, 0);
    if ( cls == CPU_RT )
    {
        cnt_dec_pending(cpuc, cpu, 0, cgid);

        bpf_spin_lock(&cgv_tree_lock);
        bpf_rbtree_add(cgv_tree, &cgv_node->rb_node, cgv_node_less);
        bpf_spin_unlock(&cgv_tree_lock);

        bpf_cgroup_release(cgrp);
        return true;
    }

    u64 enq_count =__sync_fetch_and_add(&cgc->enq_count, 0);

    if (scx_bpf_dsq_move_to_local(cgid))
    {
        if ( cpu < NR_CPUS_LOG ) log("\t\ttry_pick_next_cgroup: scx_bpf_dsq_move_to_local(%llu, %d) SUCCEEDED (is RT tree %d) (enq_count=%llu)", cgc->rt_class, cgid, cpu, &cgv_tree_rt == cgv_tree, enq_count);

        if (cpuc)
        {
            cgrp_dispatch_stat( cgid, cgc, cpuc );
        }
    }
    else
    {
        cnt_dec_pending(cpuc, cpu, 0, cgid);

        if ( cpu < NR_CPUS_LOG ) log("\t\ttry_pick_next_cgroup: scx_bpf_dsq_move_to_local(%llu, %d) FAILED (is RT tree %d) (enq_count=%llu)", cgc->rt_class, cgid, cpu, &cgv_tree_rt == cgv_tree, enq_count);

        if ( enq_count == 0 )
        {
            // TRUE-EMPTY: remove & stash if it’s still the same head
            stat_inc(STAT_PNC_EMPTY);

            log("\tdispatch: TRUE EMPTY for cgid %llu on cpu %d", cgc->rt_class, cgid, cpu );
            try_stash_node( cgid, cgc, cgv_tree, cgv_node, cpu );

            bpf_cgroup_release(cgrp);

            return false;
        }


        /* Tasks exist (qsz > 0), but move_to_local returned 0.
        * This means tasks are pinned to other CPUs. We must rotate the tree
        * to avoid Head-of-Line blocking. */

        char cg_name_buf[32];
        bpf_probe_read_kernel(&cg_name_buf, sizeof(cg_name_buf), cgrp->kn->name);

        bpf_spin_lock(&cgv_tree_lock);
        cgv_node->cvtime += cgrp_slice_ns * HWEIGHT_ONE / (cgc->hweight ?: 1);
        bpf_rbtree_add(cgv_tree, &cgv_node->rb_node, cgv_node_less);
        bpf_spin_unlock(&cgv_tree_lock);
        
        bpf_cgroup_release(cgrp);
        return true; // Return true so dispatch loop tries the next node
    }

    /*
    * Successfully consumed from the cgroup. This will be our current
    * cgroup for the new slice. Refresh its hweight.
    */
    cgrp_refresh_hweight(cgrp, cgc);

    log("\tdispatch: charging cvtime for cgid %llu!!!", 0, cgid );

    bpf_spin_lock(&cgv_tree_lock);

    if (time_before(cvtime_now, cgv_node->cvtime))
        cvtime_now = cgv_node->cvtime;

    /*
    * Charge the full slice upfront and exact later according to
    * actual consumption. Prevents lowpri thundering herd.
    */
    cgv_node->cvtime += cgrp_slice_ns * HWEIGHT_ONE / (cgc->hweight ?: 1);
    cgrp_cap_budget(cgv_node, cgc); 

    u64 cvtime = cgv_node->cvtime;

    bpf_rbtree_add(cgv_tree, &cgv_node->rb_node, cgv_node_less);

    bpf_spin_unlock(&cgv_tree_lock);

    // TODO: REMOVE THIS
    if ( cvtime > 3000000000000000000ULL )
    {
        scx_bpf_error( "CVTIME OVERFLOW!");
    }

    *cgidp = cgid;
    stat_inc(STAT_PNC_NEXT);

    log("\tdispatch: try_pick_next_cgroup picked new cgroup %llu! for cpu %d (tree sizes rt=%u bk=%u)", cgc->rt_class, cgid, cpu, cls_get_rt(), cls_get_bk());
    
    bpf_cgroup_release(cgrp);

    return true;
}


void BPF_STRUCT_OPS(dispatch, s32 cpu, struct task_struct *prev)
{
    struct cpu_ctx *cpuc;
    struct cgrp_ctx *cgc;
    struct cgroup *cgrp;
    u64 now = scx_bpf_now();

    cpuc = find_cpu_ctx(cpu);
    if (!cpuc)
        return;

    if (!cpuc->cur_bk_cgid)
        goto pick_next_cgroup;

    enum cpu_runcls cls = cpu_cls(cpu, 0);
    if ( cls == CPU_RT )
    {
        stat_inc(STAT_CNS_GONE);

        log("\tdispatch: CANCELLED on CPU %d as it is running RT (last BK %llu at %llu)", 0, cpu, cpuc->cur_bk_cgid, cpuc->cur_bk_at);
        return;
    }

    /*
     * RT-active fast path: skip the heavy "keep cgroup" and cvtime debt
     * paths that take cgv_tree_lock. Just reset and go straight to a
     * single-shot BK dispatch attempt.
     */
    #if RT_ACTIVE_CHECK
    if ( cpuc->rt_active )
        goto pick_next_cgroup;
    #endif

    if ( time_before(now, cpuc->cur_bk_at + cgrp_slice_ns) ) {

        cgrp = bpf_cgroup_from_id(cpuc->cur_bk_cgid);
        if (cgrp) {
            cgc = bpf_cgrp_storage_get(&cgrp_ctx, cgrp, 0, 0);
        }

        /* If current is BK and *any* RT is pending, try RT first. */
        if ( cgrp && cgc && cgc->rt_class == 0 ) 
        {
            log("\tdispatch: Should we stay on same CPU %d for cgroup %llu with rt=%llu", 0, cpu, cpuc->cur_bk_cgid, cls_get_rt());

            bpf_cgroup_release( cgrp );
            goto pick_next_cgroup;
        }
        
        if (scx_bpf_dsq_move_to_local(cpuc->cur_bk_cgid)) {
            stat_inc(STAT_CNS_KEEP);

            log("\tdispatch: scx_bpf_dsq_move_to_local(%llu, %d) SUCCEEDED in KEEP path", 0, cpuc->cur_bk_cgid, cpu);

            if ( cgrp )
            {
                cgrp_dispatch_stat( cpuc->cur_bk_cgid, cgc, cpuc );

                log("\tdispatch: staying on same CPU %d for cgroup %llu", 0, cpu, cpuc->cur_bk_cgid);

                bpf_cgroup_release(cgrp);
            }
            else
            {
                log("\tdispatch: staying on same CPU %d for task with no cgroup", 0, cpu);
            }

            cnt_inc_pending(cpuc, cpu);

            return;
        }

        if ( cgrp )
        {
            log("\tdispatch: cannot stay on CPU %d as it is empty for cgroup %llu", 0, cpu, cpuc->cur_bk_cgid);

            bpf_cgroup_release(cgrp);

            goto pick_next_cgroup;
        }

        stat_inc(STAT_CNS_EMPTY);
    
    } else {
        stat_inc(STAT_CNS_EXPIRE);
    }

    /*
    * The current cgroup is expiring. It was already charged a full slice.
    * Calculate the actual usage and accumulate the delta.
    */
    cgrp = bpf_cgroup_from_id(cpuc->cur_bk_cgid);
    if (!cgrp) {
        stat_inc(STAT_CNS_GONE);
        goto pick_next_cgroup;
    }

    cgc = bpf_cgrp_storage_get(&cgrp_ctx, cgrp, 0, 0);
    if (cgc) {
		bpf_spin_lock(&cgv_tree_lock);
		__sync_fetch_and_add(&cgc->cvtime_delta,
				     (cpuc->cur_bk_at + cgrp_slice_ns - now) *
				     HWEIGHT_ONE / (cgc->hweight ?: 1));
		bpf_spin_unlock(&cgv_tree_lock);
    } else {
        stat_inc(STAT_CNS_GONE);
    }

    bpf_cgroup_release( cgrp );

pick_next_cgroup:
    cpuc->cur_bk_at = now;
    cpuc->cur_bk_cgid = 0;

	if ( scx_bpf_dsq_nr_queued(FALLBACK_DSQ) > 0 )
	{
		enum cpu_runcls cls = cpu_cls(cpu, 0);
		if ( cls != CPU_RT )
		{
			cnt_inc_pending(cpuc, cpu);

			cls = cpu_cls(cpu, 0);
			if ( cls != CPU_RT )
			{
				if (scx_bpf_dsq_move_to_local(FALLBACK_DSQ)) {
					return;
				}
			}

			cnt_dec_pending(cpuc, cpu, 0, 0);
		}
	}

    if ( cls_get_bk() != 0 )
    {
        if ( cpu < NR_CPUS_LOG )
            log("\tdispatch: pick_next_cgroup trying to move BK to local (size %u) on cpu %d", 0, cls_get_bk(), cpu);

        #if RT_ACTIVE_CHECK
        bpf_repeat(cpuc->rt_active ? 2 : CGROUP_MAX_RETRIES) {
        #else
        bpf_repeat(CGROUP_MAX_RETRIES) {
        #endif
            if (try_pick_next_cgroup( &cpuc->cur_bk_cgid, &cgv_tree_bk, cpu, cpuc )) {
                return;
            }
        }
    }
    else
    {
        stat_inc(STAT_CNS_EMPTY);
        return;
    }

    /*
    * This only happens if try_pick_next_cgroup() races against enqueue
    * path for more than CGROUP_MAX_RETRIES times, which is extremely
    * unlikely and likely indicates an underlying bug. There shouldn't be
    * any stall risk as the race is against enqueue.
    */
    if ( cpu < NR_CPUS_LOG )
    {
        log("\t\t\tdispatch: pick_next_cgroup failed for cpu %d!!! (tree sizes rt=%u bk=%u)", 0, cpu, cls_get_rt(), cls_get_bk());

        stat_inc(STAT_PNC_FAIL);
    }
}

s32 BPF_STRUCT_OPS(init_task, struct task_struct *p,
        struct scx_init_task_args *args)
{
    struct task_ctx *taskc;
    struct cgrp_ctx *cgc;

    /*
    * @p is new. Let's ensure that its task_ctx is available. We can sleep
    * in this function and the following will automatically use GFP_KERNEL.
    */
    taskc = bpf_task_storage_get(&task_ctx, p, 0,
                    BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!taskc)
        return -ENOMEM;

    taskc->cur_cpu          = nr_cpus;
    taskc->sel_cpu          = nr_cpus;
    taskc->last_cpu         = nr_cpus;
    taskc->enq_cgid         = 0;
    taskc->rt_cpu           = nr_cpus;
#if WEIGHTED_FALLBACK_DSQ
    taskc->fallback_slice_ns = 0;
    taskc->fallback_weighted = 0;
#endif

    if (!(cgc = find_cgrp_ctx(args->cgroup)))
        return -ENOENT;

    if (cgc->rt_class)
    {
        taskc->rt_cpu = get_or_assign_rt_cpu(p, (const struct cpumask*) p->cpus_ptr);
        log("\tinit_task: RT task %d allocated to CPU %u", 2, p->pid, taskc->rt_cpu);
    }

    p->scx.dsq_vtime = cgc->tvtime_now;

    return 0;
}

int BPF_STRUCT_OPS_SLEEPABLE(cgroup_init, struct cgroup *cgrp,
                struct scx_cgroup_init_args *args)
{
    struct cgrp_ctx *cgc;
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
    cgc->hweight = HWEIGHT_ONE;
    cgc->rt_class = is_cgroup_rt(cgrp) ? 1 : 0;

    cpuset_ensure_entry( cgid );

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

    log("\tcgroup_init: setting the stash to NON-NULL for cgroup %llu (weight=%llu)!!!", cgc->rt_class, cgid, args->weight);

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

void BPF_STRUCT_OPS(cgroup_exit, struct cgroup *cgrp)
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

void BPF_STRUCT_OPS(cgroup_move, struct task_struct *p,
            struct cgroup *from, struct cgroup *to)
{
    struct cgrp_ctx *from_cgc, *to_cgc;
    struct cgroup *cgrp;
    struct cgrp_ctx *cgc;
    s64 delta;
    u8 rt_class = 0;

    /* find_cgrp_ctx() triggers scx_ops_error() on lookup failures */
    if (!(from_cgc = find_cgrp_ctx(from)) || !(to_cgc = find_cgrp_ctx(to)))
        return;

    delta = time_delta(p->scx.dsq_vtime, from_cgc->tvtime_now);
    p->scx.dsq_vtime = to_cgc->tvtime_now + delta;

    struct task_ctx *taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if ( !taskc ) return;

    if (!from_cgc->rt_class && to_cgc->rt_class && taskc->rt_cpu >= nr_cpus)
    {
        taskc->rt_cpu = get_or_assign_rt_cpu(p, (const struct cpumask*) p->cpus_ptr);
        log("\tcgroup_move: RT task %d allocated to CPU %u", 2, p->pid, taskc->rt_cpu);
    }

    u32 cur_cpu = taskc->cur_cpu;
    if ( cur_cpu >= nr_cpus )
        return;

    cgrp = scx_bpf_task_cgroup(p);
    if ( cgrp )
    {
        cgc = find_cgrp_ctx(cgrp);
        if ( cgc )
        {
            rt_class = cgc->rt_class;
        }
    }
    bpf_cgroup_release(cgrp);

    log("\tcgroup_move: moving task %d on CPU %d from cgroup %llu to cgroup %llu!!!", rt_class, p->pid, cur_cpu, from->kn->id, to->kn->id);

    struct cpu_ctx *cpuc = bpf_map_lookup_elem(&cpu_ctx, &cur_cpu);
    if (!cpuc) return;

    cnt_dec( cpuc, rt_class, cur_cpu, p->pid, 0);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(init)
{
    return scx_bpf_create_dsq(FALLBACK_DSQ, -1);
}

void BPF_STRUCT_OPS(ufs_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

void BPF_STRUCT_OPS(exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
    struct cgroup *cgrp;
    struct cgrp_ctx *cgc;
    u64 cgid = 0;
    u8 rt_class = 0;

    struct task_ctx *taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if ( !taskc ) 
    {
        scx_bpf_error("exit_task: !taskc for pid %d", p->pid);
        return;
    }

    u32 cur_cpu = taskc->cur_cpu;
    if ( cur_cpu >= nr_cpus )
    {
        return;
    }

    struct cpu_ctx *cpuc = bpf_map_lookup_elem(&cpu_ctx, &cur_cpu);
    if (!cpuc) return;

    cgrp = scx_bpf_task_cgroup(p);
    if ( cgrp )
    {
        cgc = find_cgrp_ctx(cgrp);
        if ( cgc )
        {
            rt_class = cgc->rt_class;
        }
    }
    bpf_cgroup_release(cgrp);

    log("\ttask_exit: task with pid %d (cgid %llu) exiting!!!", rt_class, p->pid, cgid);

    cnt_dec( cpuc, rt_class, cur_cpu, p->pid, 0 );
    #if !PIN_TASKS
        rt_clear_claim( cur_cpu, p->pid );
    #endif
}

SCX_OPS_DEFINE(weightedcg_ops,
        .select_cpu		    = (void *)select_cpu,
        .enqueue			= (void *)enqueue,
        .dispatch		    = (void *)dispatch,
        .runnable		    = (void *)runnable,
        .running			= (void *)running,
        .stopping		    = (void *)stopping,
        .quiescent		    = (void *)quiescent,
        .dequeue		    = (void *)dequeue,
        .init_task		    = (void *)init_task,
        .exit_task          = (void *)exit_task,
        .cgroup_set_weight	= (void *)cgroup_set_weight,
        .cgroup_init		= (void *)cgroup_init,
        .cgroup_exit		= (void *)cgroup_exit,
        .cgroup_move		= (void *)cgroup_move,
        .init			    = (void *)init,
        .exit			    = (void *)ufs_exit,
        .flags			    = SCX_OPS_HAS_CGROUP_WEIGHT || SCX_OPS_ENQ_LAST,
        .timeout_ms		    = 0,
        .name			    = "weightedcg");