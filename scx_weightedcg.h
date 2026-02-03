#ifndef __SCX_WEIGHTEDCG_H
#define __SCX_WEIGHTEDCG_H

enum {
	FCG_HWEIGHT_ONE		= 1LLU << 16,
};

enum fcg_stat_idx {
	FCG_STAT_ACT,
	FCG_STAT_DEACT,
	FCG_STAT_LOCAL,
	FCG_STAT_GLOBAL,

	FCG_STAT_HWT_UPDATES,
	FCG_STAT_HWT_CACHE,
	FCG_STAT_HWT_SKIP,
	FCG_STAT_HWT_RACE,

	FCG_STAT_ENQ_SKIP,
	FCG_STAT_ENQ_RACE,

	FCG_STAT_CNS_KEEP,
	FCG_STAT_CNS_EXPIRE,
	FCG_STAT_CNS_EMPTY,
	FCG_STAT_CNS_GONE,

	FCG_STAT_PNC_NO_CGRP,
	FCG_STAT_PNC_NEXT,
	FCG_STAT_PNC_EMPTY,
	FCG_STAT_PNC_GONE,
	FCG_STAT_PNC_RACE,
	FCG_STAT_PNC_FAIL,
	FCG_STAT_PNC_AFFINITY,

	FCG_STAT_BAD_REMOVAL,

	FCG_NR_STATS,
};

#define FCG_CPU_MASK_BITS 256
#define FCG_MASK_WORDS    (FCG_CPU_MASK_BITS / 64)

struct fcg_cgrp_ctx {
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
    __u64 cpuset_mask[FCG_MASK_WORDS];
    __u32 cpuset_init;
};

struct fcg_cgrp_stats {
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

#ifndef FCG_DEBUG
#define FCG_DEBUG 0
#endif

#ifndef FCG_BUDDIES
#define FCG_BUDDIES 0
#endif

#if FCG_DEBUG
#define log(fmt, rt_class, ...) if ( true || rt_class == 1 ) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define log(fmt, rt_class, ...)
#endif

#endif
