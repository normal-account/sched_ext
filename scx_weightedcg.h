#ifndef __SCX_WEIGHTEDCG_H
#define __SCX_WEIGHTEDCG_H

enum {
	HWEIGHT_ONE		= 1LLU << 16,
};

enum stat_idx {
	STAT_ACT,
	STAT_DEACT,
	STAT_LOCAL,
	STAT_GLOBAL,

	STAT_HWT_UPDATES,
	STAT_HWT_CACHE,
	STAT_HWT_SKIP,
	STAT_HWT_RACE,

	STAT_ENQ_SKIP,
	STAT_ENQ_RACE,
	STAT_ENQ_IRQ,
	STAT_ENQ_KSOFTIRQD,
	STAT_ENQ_NAPI,
	STAT_ENQ_WQ_WORKER,
	STAT_ENQ_KTHREAD,

	STAT_CNS_KEEP,
	STAT_CNS_EXPIRE,
	STAT_CNS_EMPTY,
	STAT_CNS_GONE,

	STAT_PNC_NO_CGRP,
	STAT_PNC_NEXT,
	STAT_PNC_EMPTY,
	STAT_PNC_GONE,
	STAT_PNC_RACE,
	STAT_PNC_FAIL,
	STAT_PNC_AFFINITY,

	STAT_BAD_REMOVAL,

	STAT_NR,
};

#define CPU_MASK_BITS 256
#define MASK_WORDS    (CPU_MASK_BITS / 64)

struct cgrp_ctx {
	u32			nr_active;
	u32			nr_runnable;
	u32			queued;
	u32			weight;
	u32			hweight;
	u64			child_weight_sum;
	u64			hweight_gen;
	s64			cvtime_delta;
	u64			tvtime_now;

	u8  rt_class;    		// 1=RT, 0=BK
	u64 enq_count;        	// monotonic, bumps on every enqueue intent

	struct bpf_spin_lock cpuset_lock;
    __u64 cpuset_mask[MASK_WORDS];
    __u32 cpuset_init;
};

struct cgrp_stats {
	char  name[8];

	__u64 first_enq_ts;   	// 0 ==> not armed

	__u64 lat_sum_ns;     	// accumulated activation latency
    __u64 lat_cnt;        	// number of dispatches
	__u64 lat_max;			// max latency encountered

	__u64 enq_idle_sum_ns;
    __u64 enq_idle_cnt;
	__u64 enq_idle_max;

	__u64 enq_bk_sum_ns;
    __u64 enq_bk_cnt;
	__u64 enq_bk_max;

	__u64 enq_rt_sum_ns;
    __u64 enq_rt_cnt;
	__u64 enq_rt_max;

	__u64 enq_cnt;

	__u64 move_lat_sum_ns;
	__u64 move_lat_cnt;

	u8  rt_class;    		// 1=RT, 0=BK
	u32			weight;
};

#ifndef DIR_ENQ
#define DIR_ENQ 1
#endif

#ifndef DEBUG
#define DEBUG 0
#endif

#ifndef RT_VTIME
#define RT_VTIME 1
#endif

#ifndef RT_ACTIVE_CHECK
#define RT_ACTIVE_CHECK 1
#endif

#ifndef WEIGHTED_FALLBACK_DSQ
#define WEIGHTED_FALLBACK_DSQ 1
#endif

#ifndef PIN_TASKS
#define PIN_TASKS 1
#endif

#ifndef RT_CGROUP_NAME
#define RT_CGROUP_NAME "hw"
#endif

#ifndef CGROUP_NAME_LEN
#define CGROUP_NAME_LEN 64
#endif

#ifndef DUMP_TRACES
#define DUMP_TRACES 0
#endif

#if DEBUG
#define log(fmt, rt_class, ...) if ( rt_class == 2 ) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define log(fmt, rt_class, ...)
#endif

#endif
