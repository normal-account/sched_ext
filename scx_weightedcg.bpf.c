#include "vmlinux.h"
#include <scx/common.bpf.h>
#include "scx_weightedcg.h"
/*
* Maximum amount of retries to find a valid cgroup.
*/
enum {
    FALLBACK_DSQ		= 0,
    CGROUP_MAX_RETRIES	= 8,
};

char _license[] SEC("license") = "GPL";

const volatile u32 nr_cpus;	/* !0 for veristat, set during init */
const volatile u64 cgrp_slice_ns;
const volatile bool fifo_sched;

const u32 NR_CPUS_LOG = 2;

u64 cvtime_now;
UEI_DEFINE(uei);

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

#ifdef FCG_DEBUG
    u64  first_move_ts;     // when we successfully moved that DSQ to local
    u32  move_seq;    // bumps on each arm to avoid stale races (optional)
#endif
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

/* CPU -> current cgid (0 if none). Updated in dispatch; used to spread hw in select_cpu */
struct {
__uint(type, BPF_MAP_TYPE_ARRAY);
__uint(key_size, sizeof(u32));
__uint(value_size, sizeof(u64));
__uint(max_entries, 1024);
} cur_cgid SEC(".maps");

struct fcg_task_ctx {
    u64		bypassed_at;
};

struct cls_counters {
    u64 rt;   // # RT cgroups with non-empty DSQ
    u64 bk;   // # BK cgroups with non-empty DSQ
};

/* TREE COUNTS START */
struct tree_counts { u64 rt_nodes; u64 bk_nodes; };

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct tree_counts);
} cgv_tree_cnts SEC(".maps");


static __always_inline void tree_nodes_inc(bool is_rt)
{
    u32 k = 0;
    struct tree_counts *tc = bpf_map_lookup_elem(&cgv_tree_cnts, &k);
    if (!tc) return;
    if (is_rt) __sync_fetch_and_add(&tc->rt_nodes, 1);
    else       __sync_fetch_and_add(&tc->bk_nodes, 1);
}

static __always_inline void tree_nodes_dec(bool is_rt)
{
    u32 k = 0;
    struct tree_counts *tc = bpf_map_lookup_elem(&cgv_tree_cnts, &k);
    if (!tc) return;
    if (is_rt) __sync_fetch_and_sub(&tc->rt_nodes, 1);
    else       __sync_fetch_and_sub(&tc->bk_nodes, 1);
}

static __always_inline u64 tree_nodes_get_rt(void)
{
    u32 k = 0; struct tree_counts *tc = bpf_map_lookup_elem(&cgv_tree_cnts, &k);
    return tc ? tc->rt_nodes : 0;
}
static __always_inline u64 tree_nodes_get_bk(void)
{
    u32 k = 0; struct tree_counts *tc = bpf_map_lookup_elem(&cgv_tree_cnts, &k);
    return tc ? tc->bk_nodes : 0;
}
/* TREE COUNTS END */

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

/* CLUSTER COUNTS END */

/* CPUSET TRACKING START*/

struct cpuset_bits {
    __u64 mask[FCG_MASK_WORDS];
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

static __always_inline void fcg_mask_set_cpu(struct cpuset_bits *st, __u32 cpu) {
    __u32 w = cpu >> 6;  // cpu / 64
    __u32 bit = cpu & 63;   // cpu % 64
    if (w >= FCG_MASK_WORDS) return;

    __u64 new_bit = (1ull << bit);
    __u64 *slot = &st->mask[w];

    __sync_fetch_and_or(slot, new_bit);
}

static __always_inline bool fcg_mask_test_cpu(struct cpuset_bits *st, __u32 cpu) 
{
    __u32 w = cpu >> 6;  // cpu / 64
    __u32 bit = cpu & 63;   // cpu % 64

    if (w >= FCG_MASK_WORDS)
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

    for (int i = 0; i < 1024; i++) 
    {
        if (i >= nr_cpus || i >= FCG_CPU_MASK_BITS) break;
        
        if (bpf_cpumask_test_cpu(i, src)) 
        {   
            fcg_mask_set_cpu(st, i);
        }
    }
    st->init = 1;
}

/* CPUSET TRACKING END*/


/* Debug helper: dump all entries of cur_cgid (keys 0..nr_cpus-1) */
static void dump_cur_cgid(int start, int rt_class)
{
    u32 i;
    if (start)
    {
        log("\t\tcur_cgid: RUNNING dump begin (nr_cpus=%u)", rt_class, nr_cpus);
    }
    else
    {
        log("\t\tcur_cgid: STOPPED dump begin (nr_cpus=%u)", rt_class, nr_cpus);
    }

    bpf_for(i, 0, 1024) {
        if (i >= NR_CPUS_LOG)
            break;
        u64 *val = bpf_map_lookup_elem(&cur_cgid, &i);
        if (val) {
            if (*val) {
                struct cgroup *cg = bpf_cgroup_from_id(*val);
                if (cg) {
                    char namebuf[32];
                    bpf_probe_read_kernel(&namebuf, sizeof(namebuf), cg->kn->name);
                    log("\t\t\tcur_cgid[%u] = %llu (name=%s)", rt_class, i, *val, namebuf);
                    bpf_cgroup_release(cg);
                } else {
                    log("\t\t\tcur_cgid[%u] = %llu (lookup failed)", rt_class, i, *val);
                }
            }
        }
    }

    if (start)
    {
        log("\t\tcur_cgid: RUNNING dump end", rt_class);
    else
        log("\t\tcur_cgid: STOPPED dump end", rt_class);
    }
}

static __always_inline bool str_is_hw(const char *s)
{
    /* exact "hw" */
    return s[0] == 'h' && s[1] == 'w' && s[2] == '\0';
}

// Check if cgroup is "hw" OR its parent cgroup is "hw"
static __always_inline bool is_cgroup_hw(struct cgroup *cgrp)
{
    struct kernfs_node *kn  = NULL;
    struct kernfs_node *pkn = NULL;
    const char *nptr = NULL, *pptr = NULL;
    char leaf[3+1] = {}, par[3+1] = {};

    if (!cgrp)
        return false;

    /* leaf name */
    bpf_probe_read_kernel(&kn, sizeof(kn), &cgrp->kn);
    if (!kn)
        return false;

    bpf_probe_read_kernel(&nptr, sizeof(nptr), &kn->name);
    bpf_probe_read_kernel_str(leaf, sizeof(leaf), nptr);
    if (str_is_hw(leaf))
        return true;

    /* parent name (root has no parent) */
    bpf_probe_read_kernel(&pkn, sizeof(pkn), &kn->__parent);
    if (!pkn)
        return false;

    bpf_probe_read_kernel(&pptr, sizeof(pptr), &pkn->name);
    bpf_probe_read_kernel_str(par, sizeof(par), pptr);

    return str_is_hw(par);
}

/* CGROUP STAT UTILS START */

// Hash keyed by your DSQ id / cgid (cgrp->kn->id), easy to query
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);             // cgid (cgrp->kn->id)
    __type(value, struct fcg_cgrp_stats);
} cgrp_stats SEC(".maps");

static void cgrp_enqueue_stat( struct cgroup *cgrp, struct fcg_cgrp_ctx* cgc, bool direct_enqueue )
{
#if FCG_DEBUG
    if ( !cgrp || !cgc ) return;

    u64 cgid = cgrp->kn->id;

    if ( cgid <= 1 ) return; // Ignore default cgroup

    struct fcg_cgrp_stats *cg_stat = bpf_map_lookup_elem(&cgrp_stats, &cgid );
    if (!cg_stat) {
        struct fcg_cgrp_stats zero = {};
        if (bpf_map_update_elem(&cgrp_stats, &cgid, &zero, BPF_NOEXIST))
            return;
            cg_stat = bpf_map_lookup_elem(&cgrp_stats, &cgid);
    
        if (!cg_stat) return;

        bpf_probe_read_kernel_str(cg_stat->name, sizeof(cg_stat->name), cgrp->kn->name);
        cg_stat->weight = cgc->weight;
        cg_stat->rt_class = is_cgroup_hw( cgrp );
    }

    if ( direct_enqueue )
    {
        __sync_fetch_and_add( &cg_stat->dir_enq_cnt, 1 );
    }
    else
    {
        // Read atomically
        if ( 0 == __sync_fetch_and_add( &cg_stat->first_enq_ts, 0) )
        {
            __u64 ts = scx_bpf_now();
            __sync_val_compare_and_swap( &cg_stat->first_enq_ts, 0, ts );
            log("\tcgrp_enqueue_stat: setting first_enq_ts = %llu", cgc->rt_class, ts);
        }
    }
#endif
}

static void cgrp_dispatch_stat( __u64 cgid, struct fcg_cgrp_ctx* cgc, struct fcg_cpu_ctx *cpuc )
{
#if FCG_DEBUG
    if ( !cgc || !cpuc ) return;

    // 1. Store enqueue-dispatch stats
    struct fcg_cgrp_stats *cg_stat = bpf_map_lookup_elem(&cgrp_stats, &cgid );
    if (!cg_stat) return;

    // Read atomically
    __u64 ts = __sync_fetch_and_add( &cg_stat->first_enq_ts, 0 );
    if ( ts == 0 ) return; // Not armed

    // Win the race to clear to 0
    if (__sync_val_compare_and_swap( &cg_stat->first_enq_ts, ts, 0 ) != ts )
        return; // Someone else recorded

    __u64 lat = scx_bpf_now() - ts;

    log("\tcgrp_dispatch_stat: ts = %llu, bumping count", cgc->rt_class, ts);

    __sync_fetch_and_add( &cg_stat->lat_sum_ns, lat );
    __sync_fetch_and_add( &cg_stat->lat_cnt, 1 );

    __u64 lat_max = __sync_fetch_and_add( &cg_stat->lat_max, 0 );
    if ( lat > lat_max )
    {
        __u64 lat_ms = lat / 1000000;

        log("\tcgrp_dispatch_stat: lat = %llu, NEW MAX!", cgc->rt_class, lat_ms);

        __sync_val_compare_and_swap( &cg_stat->lat_max, lat_max, lat );
    }

    // 2. Prep dispatch-running stats
    if ( cpuc->first_move_ts == 0 )
    {
        __sync_fetch_and_add( &cpuc->first_move_ts, scx_bpf_now() );
    }

#endif
}

static void cgrp_running_stat( __u64 cgid, struct fcg_cgrp_ctx* cgc, struct fcg_cpu_ctx *cpuc )
{
#if FCG_DEBUG
    if ( !cgc || !cpuc ) return;

    struct fcg_cgrp_stats *cg_stat = bpf_map_lookup_elem( &cgrp_stats, &cgid );
    if (!cg_stat) return;

    // Read atomically
    __u64 ts = __sync_fetch_and_add( &cpuc->first_move_ts, 0 );
    if ( ts == 0 ) return; // Not armed

    // Win the race to clear to 0
    if (__sync_val_compare_and_swap( &cpuc->first_move_ts, ts, 0 ) != ts )
        return; // Someone else recorded

    __u64 lat = scx_bpf_now() - ts;

    // Increment the CGRP stats with the CPU stats
    __sync_fetch_and_add( &cg_stat->move_lat_sum_ns, lat );
    __sync_fetch_and_add( &cg_stat->move_lat_cnt, 1 );

#endif
}

/* CGROUP STAT UTILS END */

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

    char cg_name_buf[32];
    bpf_probe_read_kernel(&cg_name_buf, sizeof(cg_name_buf), cgrp->kn->name);

    /* paired with cmpxchg in try_pick_next_cgroup() */
    if (__sync_val_compare_and_swap(&cgc->queued, 0, 1)) {
        log("\tcgrp_enqueued: skip because cgc->queued == 1 for cgroup %s", cgc->rt_class, cg_name_buf);
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
        log("\tcgrp_enqueued: cancelled because stash->node is NULL (already on the rbtree) for cgroup %s", cgc->rt_class, cg_name_buf);
        stat_inc(FCG_STAT_ENQ_RACE);
        return;
    }

    log("\tcgrp_enqueued: confirmed stash->node has been set to NULL for cgroup %s", cgc->rt_class, cg_name_buf);

    bool is_hw = is_cgroup_hw(cgrp);

    if (is_hw)
    {
        cgc->rt_class = 1;
        log("\tcgrp_enqueued: enqueue new cgroup %s to REAL-TIME tree!", cgc->rt_class, cg_name_buf);
    }
    else
    {
        cgc->rt_class = 0;
        log("\tcgrp_enqueued: enqueue new cgroup %s to BACKGROUND tree!", cgc->rt_class, cg_name_buf);
    }

    bpf_spin_lock(&cgv_tree_lock);
    cgrp_cap_budget(cgv_node, cgc);

    if (is_hw)
    {
        bpf_rbtree_add(&cgv_tree_rt, &cgv_node->rb_node, cgv_node_less);
    }
    else 
    {
        bpf_rbtree_add(&cgv_tree_bk, &cgv_node->rb_node, cgv_node_less);
    }

    bpf_spin_unlock(&cgv_tree_lock);

    tree_nodes_inc(is_hw);
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

// helper: is the CPU currently running a RT  cgroup?
static __always_inline u64 cpu_running_rt(s32 cpu)
{
    u32 k = (u32)cpu;
    u64 *cgidp = bpf_map_lookup_elem(&cur_cgid, &k);
    if (!cgidp || !*cgidp)         // 0 => idle/fallback/unknown: treat as BK
    {
        return 0;
    }

    struct cgroup *cg = bpf_cgroup_from_id(*cgidp);
    if (!cg)
    {
        return 0;          // cgroup raced away, don’t block the kick
    }
    struct fcg_cgrp_ctx *cgc = bpf_cgrp_storage_get(&cgrp_ctx, cg, 0, 0);
    u32 is_rt = (!cgc || cgc->rt_class == 1);
    bpf_cgroup_release(cg);
    return is_rt ? *cgidp : 0;
}

// helper: is the CPU currently running a BK (non-RT) cgroup?
static __always_inline bool cpu_running_bk(s32 cpu)
{
    u32 k = (u32)cpu;
    u64 *cgidp = bpf_map_lookup_elem(&cur_cgid, &k);
    if (!cgidp || !*cgidp)         // 0 => idle/fallback/unknown: treat as BK
    {
        log("\t\tcpu_running_bk: idle/fallback/unknown (!cgidp || !*cgidp): treat as BK", 0);
        return true;
    }

    struct cgroup *cg = bpf_cgroup_from_id(*cgidp);
    if (!cg)
    {
        log("\t\tcpu_running_bk: cgroup raced away (!cg), don’t block the kick: treat as BK", 0);
        return true;          // cgroup raced away, don’t block the kick
    }
    struct fcg_cgrp_ctx *cgc = bpf_cgrp_storage_get(&cgrp_ctx, cg, 0, 0);
    u32 is_bk = (!cgc || cgc->rt_class == 0);
    bpf_cgroup_release(cg);
    return is_bk;
}

static __always_inline s32 pick_cpu_to_kick_for_rt(struct task_struct *p, bool *is_idle)
{
    const struct cpumask *allowed = (const struct cpumask *)p->cpus_ptr;

    // 0) Prefer the kernel’s chosen wake target for this wakeup
    // TEMPORARY DISABLED FOR TESTING
    
    //s32 tgt = scx_bpf_task_cpu(p);
    //
    //if (tgt >= 0 ) 
    //{
    //    const struct cpumask *idle = scx_bpf_get_idle_cpumask();
    //    bool is_idle = false;
    //    if (idle) {
    //        is_idle = bpf_cpumask_test_cpu(tgt, idle);
    //        scx_bpf_put_idle_cpumask(idle);
    //    }
    //
    //    if (is_idle && bpf_cpumask_test_cpu((u32)tgt, allowed)) {
    //        /* If it’s running BK, a PREEMPT kick will help; if idle, an IDLE kick will wake it.
    //        Even if it’s running RT, using the wake target aligns with placement. */
    //        log("\tpick_cpu_to_kick_for_rt: using wake target CPU %d for pid %d", 0, tgt, p->pid);
    //        return tgt;
    //    }
    //}

    // 1) Otherwise, any idle CPU within affinity
    s32 cpu = scx_bpf_pick_idle_cpu(allowed, 0);
    if (cpu >= 0) {
        log("\tpick_cpu_to_kick_for_rt: pick idle CPU %d for pid %d", 0, cpu, p->pid);
        *is_idle = true;
        return cpu;
    }

    // 2) Otherwise, a CPU in affinity that’s currently running BK work
    u32 start = bpf_get_prandom_u32() % (u32)nr_cpus;

#pragma unroll
    for (int off = 0; off < 1024; off++) {   // verifier-bounded
        if (off >= nr_cpus) break;
        cpu = (start + off) % nr_cpus;

        if (bpf_cpumask_test_cpu(cpu, allowed))
        {
            u64 cgid = cpu_running_rt(cpu);
            if ( !cgid )
            {
                return cpu;
            }
            else 
            {
                log("\tpick_cpu_to_kick_for_rt: CPU %d already running RT %llu for pid %d, cannot kick", 0, cpu, cgid, p->pid);
            }
        }
    }

any:
    return nr_cpus; // We haven't found a CPU, so we return a unexistent CPU which will be ignored
}

s32 BPF_STRUCT_OPS(fcg_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    bool is_idle = false;

    // TEMPORARILY DISABLED FOR SIMPLER TESTING. WE CALL THE DEFAULT FUNCTION DIRECTLY AT THE END.

    //struct cgroup *cgrp;
    //struct fcg_cgrp_ctx *cgc;
    ////struct fcg_task_ctx *taskc;
    //s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
    //taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
    //if (!taskc) {
    //    scx_bpf_error("task_ctx lookup failed");
    //    return cpu;
    //}
    //cgrp = __COMPAT_scx_bpf_task_cgroup(p);
    //if (cgrp) {
    //    cgc = find_cgrp_ctx(cgrp);
    //
    //    if ( cgc )
    //    {
    //        cgrp_enqueued(cgrp, cgc);
    //
    //        if (cgc->rt_class) {
    //
    //            u64 tvtime = p->scx.dsq_vtime;
    //
    //            /*
    //            * Limit the amount of budget that an idling task can accumulate
    //            * to one slice.
    //            */
    //            if (time_before(tvtime, cgc->tvtime_now - SCX_SLICE_DFL))
    //                tvtime = cgc->tvtime_now - SCX_SLICE_DFL;
    //
    //            bool is_idle = false;
    //            s32 tgt = pick_cpu_to_kick_for_rt(p, &is_idle);
    //            if (tgt >= 0 && tgt < nr_cpus)
    //            {
    //                if ( is_idle )
    //                {
    //                    log("\tfcg_select_cpu: kick IDLE CPU %d for pid %d", 0, tgt, p->pid);
    //                    scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
    //                }
    //                else
    //                {
    //                    log("\tfcg_select_cpu: kick PREEMPT CPU %d for pid %d ", 0, tgt, p->pid);
    //                    scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
    //                }
    //
    //                log("\tfcg_select_cpu: RT enqueue task %d (cgroup %llu) to cpu %d", 0, p->pid, cgrp->kn->id, tgt);
    //
    //                scx_bpf_dsq_insert_vtime(p, cgrp->kn->id, SCX_SLICE_DFL, tvtime, SCX_ENQ_WAKEUP | SCX_ENQ_HEAD | SCX_ENQ_PREEMPT);
    //
    //                bpf_cgroup_release( cgrp );
    //
    //                return tgt;
    //            }
    //
    //            log("\tfcg_select_cpu: RT enqueue task %d (cgroup %llu)", 0, p->pid, cgrp->kn->id );
    //
    //            scx_bpf_dsq_insert_vtime(p, cgrp->kn->id, SCX_SLICE_DFL, tvtime, SCX_ENQ_WAKEUP | SCX_ENQ_HEAD | SCX_ENQ_PREEMPT);
    //        }
    //    }
    //
    //    bpf_cgroup_release( cgrp );
    //}

    //
    //If select_cpu_dfl() is recommending local enqueue, the target CPU is
    //idle. Follow it and charge the cgroup later in fcg_stopping() after
    //the fact.
    //

    //if (is_idle) {

        //set_bypassed_at(p, taskc);
        //stat_inc(FCG_STAT_LOCAL);
        //scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);

        //cgrp = __COMPAT_scx_bpf_task_cgroup(p);
        //if (cgrp) {
        //    cgc = find_cgrp_ctx(cgrp);
        //    if (cgc && cgc->rt_class) {
        //        set_bypassed_at(p, taskc);
        //        stat_inc(FCG_STAT_LOCAL);
        //        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
        //    }
        //
        //    bpf_cgroup_release(cgrp);
        //}
    //}

    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);;
}

static __always_inline void fcg_log_enq_flags(const char *tag,
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


    cgrp = __COMPAT_scx_bpf_task_cgroup(p);
    cgc = find_cgrp_ctx(cgrp);
    if (!cgc)
        goto out_release;


    if (fifo_sched) {
        scx_bpf_dsq_insert(p, cgrp->kn->id, SCX_SLICE_DFL, enq_flags);
    } else {
        u64 tvtime = p->scx.dsq_vtime;

        /*
        * Limit the amount of budget that an idling task can accumulate
        * to one slice.
        */
        if (time_before(tvtime, cgc->tvtime_now - SCX_SLICE_DFL))
            tvtime = cgc->tvtime_now - SCX_SLICE_DFL;


        if (__sync_val_compare_and_swap(&cgc->has_tasks, 0, 1) == 0)
        {
            cgrp_enqueue_stat( cgrp, cgc, false );
            cls_inc(cgc->rt_class);
            log("\t\tfcg_enqueue: inc tree RT=%d for task %d (tree sizes rt=%u bk=%u) (real num_rt=%u num_bk=%d)", cgc->rt_class, cgc->rt_class, p->pid, cls_get_rt(), cls_get_bk(), tree_nodes_get_rt(), tree_nodes_get_bk());
        }

        u64 enq_count = __sync_fetch_and_add(&cgc->enq_count, 1);

        cgrp_enqueued(cgrp, cgc);

        scx_bpf_dsq_insert_vtime(p, cgrp->kn->id, SCX_SLICE_DFL, tvtime, enq_flags);

        if ( cgc->rt_class ) 
        {
            bool is_idle = !cgc->rt_class;
            s32 tgt = pick_cpu_to_kick_for_rt(p, &is_idle);
        
            if (tgt >= 0 && tgt < nr_cpus)
            {
                if ( is_idle )
                {
                    log("\tfcg_enqueue: kick IDLE CPU %d for pid %d", cgc->rt_class, tgt, p->pid);
                    scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
                }
                else
                {
                    log("\tfcg_enqueue: kick PREEMPT CPU %d for pid %d ", cgc->rt_class, tgt, p->pid);
                    scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
                }
        
                //cgrp_enqueue_stat( cgrp, cgc, true );
                //scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | tgt, SCX_SLICE_DFL, enq_flags);
                //goto out_release;
            }
        }

        log("\tfcg_enqueue: enqueue task %d (cgroup %llu, q=%d) slice=%llu enq_count=%llu", cgc->rt_class, p->pid, cgrp->kn->id,
            scx_bpf_dsq_nr_queued(cgrp->kn->id), cgrp_slice_ns, enq_count);
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

    #ifdef FCG_DEBUG
    struct fcg_cgrp_ctx *cgc;

    cgrp = __COMPAT_scx_bpf_task_cgroup(p);
    cgc = find_cgrp_ctx(cgrp);
    int rt_class = cgc ? cgc->rt_class : 0;
    log("\trunnable: pid %d comm %s", rt_class, p->pid, p->comm);
    #endif

    refresh_cgrp_cpuset( cgrp->kn->id, p );
    update_active_weight_sums(cgrp, true);
    bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(fcg_running, struct task_struct *p)
{
    struct cgroup *cgrp;
    struct fcg_cgrp_ctx *cgc;

    if (fifo_sched)
        return;

    cgrp = __COMPAT_scx_bpf_task_cgroup(p);

    /* Update per-CPU current cgid immediately for selected CPU */

    s32 cpu = (s32)bpf_get_smp_processor_id();
    u64 sel_id = cgrp->kn->id;
    bpf_map_update_elem(&cur_cgid, &cpu, &sel_id, BPF_ANY);

    cgc = find_cgrp_ctx(cgrp);
    int rt_class = 0;
    if (cgc) 
    {
        rt_class = cgc->rt_class;
        if (should_log(p->comm, 0))
        {
            dump_cur_cgid(1, cgc->rt_class);
        }

        struct fcg_cpu_ctx *cpuc = find_cpu_ctx();

        cgrp_running_stat( sel_id, cgc, cpuc );

        /*
        * @cgc->tvtime_now always progresses forward as tasks start
        * executing. The test and update can be performed concurrently
        * from multiple CPUs and thus racy. Any error should be
        * contained and temporary. Let's just live with it.
        */
        if (time_before(cgc->tvtime_now, p->scx.dsq_vtime))
            cgc->tvtime_now = p->scx.dsq_vtime;
    }

    log("\trunning: pid %d comm %s (cur_cgid[cpu=%d] <= %llu, q=%d)", rt_class, p->pid, p->comm, cpu, sel_id, scx_bpf_dsq_nr_queued(FALLBACK_DSQ));

    bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(fcg_stopping, struct task_struct *p, bool runnable)
{
    struct fcg_task_ctx *taskc;
    struct cgroup *cgrp;
    struct fcg_cgrp_ctx *cgc;

    s32 cpu = (s32)bpf_get_smp_processor_id();
    int log = should_log(p->comm, 0);

    int rt_class = 0;
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
    {
        p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
    }

    taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (!taskc) {
        scx_bpf_error("task_ctx lookup failed");
        goto log_and_out;
    }

    if (!taskc->bypassed_at)
    {
        goto log_and_out;
    }

    cgrp = __COMPAT_scx_bpf_task_cgroup(p);
    cgc = find_cgrp_ctx(cgrp);
    if (cgc) {
        rt_class = cgc->rt_class;
        __sync_fetch_and_add(&cgc->cvtime_delta,
                    p->se.sum_exec_runtime - taskc->bypassed_at);
        taskc->bypassed_at = 0;
    }
    bpf_cgroup_release(cgrp);

log_and_out:
/* Clear per-CPU current cgid only on sleep so select_cpu can consider this CPU again */

    //if ( !runnable )
    {
        u64 zero = 0;
        bpf_map_update_elem(&cur_cgid, &cpu, &zero, BPF_ANY);
    }

    if (log) 
    {
        if (!runnable) 
        {    
            log("\tstopping: sleep pid %d comm %s on cpu %d (cur_cgid[cpu=%d] cleared)", rt_class, p->pid, p->comm, cpu, cpu);
            dump_cur_cgid(0, rt_class);
        }
        else if (p->scx.slice > 0)
        {
            log("\tstopping: preempt pid %d comm %s on cpu %d (slice_left=%u)", rt_class, p->pid, p->comm, cpu, p->scx.slice);
        }
        else
        {
            log("\tstopping: timeslice/yield pid %d comm %s on cpu %d", rt_class, p->pid, p->comm, cpu);
        }
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

        /* *** invalidate cached hweights so refresh actually runs *** */
    __sync_fetch_and_add(&hweight_gen, 1);

    /* Optional: refresh now if active so next dispatch uses new hweight */
    if (cgc->nr_active)
        cgrp_refresh_hweight(cgrp, cgc);
}

static bool try_pick_next_cgroup(u64 *cgidp, struct bpf_rb_root *cgv_tree, s32 cpu, struct fcg_cpu_ctx *cpuc)
{
    struct bpf_rb_node *rb_node;
    struct cgv_node_stash *stash;
    struct fcg_cgrp_ctx *cgc = NULL;
    struct cgv_node *cgv_node = NULL;
    struct cgroup *cgrp;
    u64 cgid;

    *cgidp = 0;

    bpf_spin_lock(&cgv_tree_lock);

    // 1. Peek head under lock, but don't remove
    rb_node = bpf_rbtree_first(cgv_tree);
    if (!rb_node) {
        bpf_spin_unlock(&cgv_tree_lock);
        stat_inc(FCG_STAT_PNC_NO_CGRP);
        if ( cpu < NR_CPUS_LOG ) log("\t\ttry_pick_next_cgroup: no cgroup found (is RT tree %d)", (&cgv_tree_rt == cgv_tree) ? 1 : 0, &cgv_tree_rt == cgv_tree);
        return true;
    }

    cgv_node = container_of(rb_node, struct cgv_node, rb_node);
    cgid = cgv_node->cgid;
    bpf_spin_unlock(&cgv_tree_lock);

    cgrp = bpf_cgroup_from_id(cgid);

    if (cgrp) cgc = bpf_cgrp_storage_get(&cgrp_ctx, cgrp, 0, 0);
    if (!cgrp || !cgc) 
    {
        if (cgrp) bpf_cgroup_release(cgrp);
        stat_inc(FCG_STAT_PNC_GONE);
        log("\t\ttry_pick_next_cgroup: !cgrp || !cgc (is RT tree %d)", (&cgv_tree_rt == cgv_tree) ? 1 : 0, &cgv_tree_rt == cgv_tree);

        bpf_spin_lock(&cgv_tree_lock);
        struct bpf_rb_node *rb_node2 = bpf_rbtree_first(cgv_tree);
        struct cgv_node *cgv_node2 = NULL;
        if (rb_node2 == rb_node) 
        {
            struct bpf_rb_node *removed = bpf_rbtree_remove(cgv_tree, rb_node2);
            cgv_node2 = container_of(removed, struct cgv_node, rb_node);

        }
        bpf_spin_unlock(&cgv_tree_lock);

        if ( cgv_node2 ) bpf_obj_drop( cgv_node2 );

        return true; // Advanced the tree; try again next tick
    }

    struct cpuset_bits *st = bpf_map_lookup_elem(&cpuset_map, &cgid);
    if (!st || !st->init || !fcg_mask_test_cpu(st, (u32)cpu)) {
        // Skip, this cgroup doesn't allow this CPU
        log("\t\ttry_pick_next_cgroup: cgroup %llu not allowed on cpu %d (is RT tree %d)", (&cgv_tree_rt == cgv_tree) ? 1 : 0, cgid, cpu, &cgv_tree_rt == cgv_tree);
        bpf_cgroup_release(cgrp);
        return false;
    }

    u64 enq_count =__sync_fetch_and_add(&cgc->enq_count, 0);

    if (scx_bpf_dsq_move_to_local(cgid))
    {
        cgrp_dispatch_stat( cgid, cgc, cpuc );

        if ( enq_count > 0 ) __sync_sub_and_fetch(&cgc->enq_count, 1);   
    }
    else
    {
        if ( enq_count > 0 ) __sync_sub_and_fetch(&cgc->enq_count, 1);

        u32 qsz  = scx_bpf_dsq_nr_queued(cgid);

        if ( cpu < NR_CPUS_LOG ) log("\t\ttry_pick_next_cgroup: scx_bpf_dsq_move_to_local(%llu) failed (is RT tree %d) (enq_count=%llu)", cgc->rt_class, cgid, &cgv_tree_rt == cgv_tree, enq_count);

        if ( qsz == 0 && enq_count == 0 )
        {
            // TRUE-EMPTY: remove & stash if it’s still the same head
            stat_inc(FCG_STAT_PNC_EMPTY);
            bpf_spin_lock(&cgv_tree_lock);

            struct bpf_rb_node *removed = NULL;
            struct cgv_node *cgv_node2 = NULL;
            struct bpf_rb_node *rb_node2 = bpf_rbtree_first(cgv_tree);

            if (rb_node2 == rb_node) 
            {
                removed = bpf_rbtree_remove(cgv_tree, rb_node2);
                cgv_node2 = container_of(removed, struct cgv_node, rb_node);
            } 

            bpf_spin_unlock(&cgv_tree_lock);

            if ( removed )
            {
                stash = bpf_map_lookup_elem(&cgv_node_stash, &cgid);
                if (stash) 
                {
                    __sync_val_compare_and_swap(&cgc->queued, 1, 0);
                    cgv_node2 = bpf_kptr_xchg(&stash->node, cgv_node2);
                    log("\tfcg_dispatch: STASHING node for cgid %llu on cpu %d", 0, cgid, cpu );
                }
            }

            // First true-empty transition: drop class count
            if (__sync_val_compare_and_swap(&cgc->has_tasks, 1, 0) == 1)
                cls_dec(cgc->rt_class);

            if ( cgv_node2 ) bpf_obj_drop( cgv_node2 );

            bpf_cgroup_release(cgrp);
            return true;
        }

        stat_inc(FCG_STAT_PNC_AFFINITY);
        bpf_cgroup_release(cgrp);
        return false;
    }

    /*
    * Successfully consumed from the cgroup. This will be our current
    * cgroup for the new slice. Refresh its hweight.
    */
    cgrp_refresh_hweight(cgrp, cgc);

    // 2. Attempt to remove the node from the tree if it was successfully moved
    bpf_spin_lock(&cgv_tree_lock);

    struct bpf_rb_node *removed = NULL;
    struct cgv_node *cgv_node2 = NULL;
    struct bpf_rb_node *rb_node2 = bpf_rbtree_first(cgv_tree);
    if ( rb_node2 )
    {
        struct cgv_node *temp_cgv_node = container_of(rb_node2, struct cgv_node, rb_node);
        if (temp_cgv_node && temp_cgv_node->cgid == cgid) 
        {
            removed = bpf_rbtree_remove(cgv_tree, rb_node2);
            cgv_node2 = container_of(removed, struct cgv_node, rb_node);
        }
    }

    if (cgv_node2 && removed)
    {
        // Advance cvtime_now if needed before charging
        if (time_before(cvtime_now, cgv_node2->cvtime))
            cvtime_now = cgv_node2->cvtime;
        
        /*
        * Note that here we charge the full slice upfront and then exact later
        * according to the actual consumption. This prevents lowpri thundering
        * herd from saturating the machine.
        */
        cgv_node2->cvtime += cgrp_slice_ns * FCG_HWEIGHT_ONE / (cgc->hweight ?: 1);
        cgrp_cap_budget(cgv_node2, cgc);
        
        bpf_rbtree_add(cgv_tree, &cgv_node2->rb_node, cgv_node_less);
    
        bpf_spin_unlock(&cgv_tree_lock);

        if (scx_bpf_dsq_nr_queued(cgid) == 0 &&__sync_val_compare_and_swap(&cgc->has_tasks, 1, 0) == 1)
        {
            cls_dec(cgc->rt_class);
        }
    
        *cgidp = cgid;
        stat_inc(FCG_STAT_PNC_NEXT);
    
        log("\tfcg_dispatch: try_pick_next_cgroup picked new cgroup %llu! for cpu %d (tree sizes rt=%u bk=%u) (real num_rt=%u num_bk=%d)", cgc->rt_class, cgid, cpu, cls_get_rt(), cls_get_bk(), tree_nodes_get_rt(), tree_nodes_get_bk());
        
        bpf_cgroup_release(cgrp);

        return true;
    }

    bpf_spin_unlock(&cgv_tree_lock);

    log("\tfcg_dispatch: try_pick_next_cgroup picked new cgroup %llu! for cpu %d, but came back to an empty head...", cgc->rt_class, cgid, cpu );

    __u64 delta = (cgrp_slice_ns * FCG_HWEIGHT_ONE) / (cgc->hweight ?: 1);
    __sync_fetch_and_add(&cgc->cvtime_delta, delta);

    if (scx_bpf_dsq_nr_queued(cgid) == 0 &&__sync_val_compare_and_swap(&cgc->has_tasks, 1, 0) == 1)
    {
        cls_dec(cgc->rt_class);
    }

    *cgidp = cgid; // We did consume; advertise selection
    bpf_cgroup_release(cgrp);

    return true;
}

void BPF_STRUCT_OPS(fcg_dispatch, s32 cpu, struct task_struct *prev)
{
    if ( cpu < NR_CPUS_LOG )
    {
        log("\tfcg_dispatch: called for cpu %d (tree sizes rt=%u bk=%u) (real num_rt=%u num_bk=%u)", 0, cpu, cls_get_rt(), cls_get_bk(), tree_nodes_get_rt(), tree_nodes_get_bk());
    }
    else
    {
        //return;
    }

    struct fcg_cpu_ctx *cpuc;
    struct fcg_cgrp_ctx *cgc;
    struct cgroup *cgrp;
    u64 now = scx_bpf_now();

    cpuc = find_cpu_ctx();
    if (!cpuc)
        return;

    if (!cpuc->cur_cgid)
        goto pick_next_cgroup;

    if (time_before(now, cpuc->cur_at + cgrp_slice_ns)) {

        // Update the non-empty count for RT/BK trees
        cgrp = bpf_cgroup_from_id(cpuc->cur_cgid);
        if (cgrp) {
            cgc = bpf_cgrp_storage_get(&cgrp_ctx, cgrp, 0, 0);
        }

        if (scx_bpf_dsq_move_to_local(cpuc->cur_cgid)) {
            stat_inc(FCG_STAT_CNS_KEEP);

            if ( cgrp )
            {
                cgrp_dispatch_stat( cpuc->cur_cgid, cgc, cpuc );

                log("\tfcg_dispatch: staying on same CPU %d for cgroup %llu", cgc->rt_class, cpu, cpuc->cur_cgid);

                if (cgc && scx_bpf_dsq_nr_queued(cpuc->cur_cgid) == 0 && __sync_val_compare_and_swap(&cgc->has_tasks, 1, 0) == 1) {
                    cls_dec(cgc->rt_class);
                    log("\t\tfcg_dispatch: dec tree RT=%d for CPU %d (tree sizes rt=%u bk=%u) (real num_rt=%u num_bk=%d)", cgc->rt_class, cpu, cls_get_rt(), cls_get_bk(), tree_nodes_get_rt(), tree_nodes_get_bk());
                }

                bpf_cgroup_release(cgrp);
            }
            else
            {
                log("\tfcg_dispatch: staying on same CPU %d for task with no cgroup", 0, cpu);
            }

            return;
        }

        if ( cgrp )
        {
            log("\tfcg_dispatch: cannot stay on CPU %d as it is empty for cgroup %llu", 0, cpu, cpuc->cur_cgid);

            if (cgc && scx_bpf_dsq_nr_queued(cpuc->cur_cgid) == 0 && __sync_val_compare_and_swap(&cgc->has_tasks, 1, 0) == 1) {
                cls_dec(cgc->rt_class);
                log("\t\tfcg_dispatch: dec tree RT=%d for CPU %d", cgc->rt_class, cpu );
            }

            bpf_cgroup_release(cgrp);
        }

        stat_inc(FCG_STAT_CNS_EMPTY);
    
    } else {
        stat_inc(FCG_STAT_CNS_EXPIRE);
    }

    /*
    * The current cgroup is expiring. It was already charged a full slice.
    * Calculate the actual usage and accumulate the delta.
    */
    cgrp = bpf_cgroup_from_id(cpuc->cur_cgid);
    if (!cgrp) {
        stat_inc(FCG_STAT_CNS_GONE);
        goto pick_next_cgroup;
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
    cpuc->cur_cgid = 0;

    u32 fallback_q = scx_bpf_dsq_nr_queued(FALLBACK_DSQ);
    if (scx_bpf_dsq_move_to_local(FALLBACK_DSQ)) {
        scx_bpf_error("FOUND TASK IN FALLBACK_DSQ!?!?!");
        return;
    }

    // TEMPORARY DISABLED FOR SIMPLER TESTING
    //if (cls_get_rt() == 0) {
        // skip probing the RT tree this round and go straight to BK
    //    goto pick_from_BG;
    //}

    if ( cpu < NR_CPUS_LOG ) 
        log("\tfcg_dispatch: pick_next_cgroup trying to move RT to local (size %u) on cpu %d", 1, cls_get_rt(), cpu);

    //bpf_repeat(CGROUP_MAX_RETRIES) {
        if (try_pick_next_cgroup( &cpuc->cur_cgid, &cgv_tree_rt, cpu, cpuc )) {
            if (cpuc->cur_cgid)   // non-zero only when we actually moved a DSQ
            {
                return;
            }
            //break;
        }
       // break;
    //}

pick_from_BG:

    if ( cls_get_bk() != 0 )
    {
        if ( cpu < NR_CPUS_LOG )
            log("\tfcg_dispatch: pick_next_cgroup trying to move BK to local (size %u) on cpu %d", 0, cls_get_bk(), cpu);

        //bpf_repeat(CGROUP_MAX_RETRIES) {
            if (try_pick_next_cgroup( &cpuc->cur_cgid, &cgv_tree_bk, cpu, cpuc )) {
                if (cpuc->cur_cgid)   // non-zero only when we actually moved a DSQ
                {
                    return;
                }
            }
            //break;
        //}
    }
    else
    {
        if ( cpu < NR_CPUS_LOG )
            log("\t\t\tfcg_dispatch: both trees are empty when called for cpu %d???", 0, cpu);
    }


    /*
    * This only happens if try_pick_next_cgroup() races against enqueue
    * path for more than CGROUP_MAX_RETRIES times, which is extremely
    * unlikely and likely indicates an underlying bug. There shouldn't be
    * any stall risk as the race is against enqueue.
    */
    if ( cpu < NR_CPUS_LOG )
    {
        log("\t\t\tfcg_dispatch: pick_next_cgroup failed for cpu %d!!! (tree sizes rt=%u bk=%u) (real num_rt=%u num_bk=%u)", 0, cpu, cls_get_rt(), cls_get_bk(), tree_nodes_get_rt(), tree_nodes_get_bk());

        stat_inc(FCG_STAT_PNC_FAIL);
    }
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

    log("\tfcg_cgroup_init: setting the stash to NON-NULL for cgroup %llu!!!", cgid);

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

    struct fcg_cgrp_ctx *cgc = bpf_cgrp_storage_get(&cgrp_ctx, cgrp, 0, 0);
    if (cgc && __sync_val_compare_and_swap(&cgc->has_tasks, 1, 0) == 1)
    {
        cls_dec(cgc->rt_class);
    }
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
    s64 delta;

    /* find_cgrp_ctx() triggers scx_ops_error() on lookup failures */
    if (!(from_cgc = find_cgrp_ctx(from)) || !(to_cgc = find_cgrp_ctx(to)))
        return;

    delta = time_delta(p->scx.dsq_vtime, from_cgc->tvtime_now);
    p->scx.dsq_vtime = to_cgc->tvtime_now + delta;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(fcg_init)
{
    return scx_bpf_create_dsq(FALLBACK_DSQ, -1);
}

void BPF_STRUCT_OPS(fcg_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(weightedcg_ops,
        .select_cpu		= (void *) fcg_select_cpu,
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
        .flags			= SCX_OPS_HAS_CGROUP_WEIGHT | SCX_OPS_SWITCH_PARTIAL,
        .timeout_ms		= 5000U,
        .name			= "weightedcg");