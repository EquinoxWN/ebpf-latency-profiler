// SPDX-License-Identifier: GPL-2.0
// Latency probes: run-queue delay, block I/O latency and fsync latency.
// Each probe records a start time in a bounded LRU hash, computes the delta on the matching
// end event and adds it to a per-CPU log2 histogram (microseconds) inside the kernel.
// User space only ever reads MAX_SLOTS counters per CPU, never individual events.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_SLOTS 32
#define MAX_ENTRIES 10240
/* Low byte of sched_switch prev_state: 0 means the task stays runnable (preempted or yielding). */
#define TASK_STATE_MASK 0xff

/* Checks a hand-written tracepoint layout against the kernel format (offset and size in bytes). */
#define FIELD_ASSERT(t, f, off, sz)                                                     \
	_Static_assert(__builtin_offsetof(struct t, f) == (off), #t "." #f " offset");  \
	_Static_assert(sizeof(((struct t *)0)->f) == (sz), #t "." #f " size")

/* Common header of every tracepoint record. */
struct trace_common {
	__u16 type;
	__u8 flags;
	__u8 preempt_count;
	__s32 pid;
};

/* sched:sched_wakeup and sched:sched_wakeup_new */
struct sched_wakeup_args {
	struct trace_common common;
	char comm[16];
	__s32 pid;
	__s32 prio;
};
FIELD_ASSERT(sched_wakeup_args, pid, 24, 4);

/* sched:sched_switch */
struct sched_switch_args {
	struct trace_common common;
	char prev_comm[16];
	__s32 prev_pid;
	__s32 prev_prio;
	__s64 prev_state;
	char next_comm[16];
	__s32 next_pid;
	__s32 next_prio;
};
FIELD_ASSERT(sched_switch_args, prev_pid, 24, 4);
FIELD_ASSERT(sched_switch_args, prev_state, 32, 8);
FIELD_ASSERT(sched_switch_args, next_pid, 56, 4);

/* block:block_rq_issue and block:block_rq_complete (leading fields only) */
struct block_rq_args {
	struct trace_common common;
	__u32 dev;
	__u32 pad;
	__u64 sector;
};
FIELD_ASSERT(block_rq_args, dev, 8, 4);
FIELD_ASSERT(block_rq_args, sector, 16, 8);

/* Identifies one in-flight block request. */
struct bio_key {
	__u32 dev;
	__u32 pad;
	__u64 sector;
};

/* Start times, bounded: the least recently used entry is evicted when full. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, __u64);
} runq_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct bio_key);
	__type(value, __u64);
} bio_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, __u64);
} fsync_start SEC(".maps");

/* Histograms: slot i counts deltas in [2^i, 2^(i+1)) microseconds, one copy per CPU. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} runq_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} bio_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} fsync_hist SEC(".maps");

/* floor(log2(v)) for 32-bit v, 0 for v == 0, without loops. */
static __always_inline __u32 log2_u32(__u32 v)
{
	__u32 r, shift;

	r = (v > 0xFFFF) << 4;
	v >>= r;
	shift = (v > 0xFF) << 3;
	v >>= shift;
	r |= shift;
	shift = (v > 0xF) << 2;
	v >>= shift;
	r |= shift;
	shift = (v > 0x3) << 1;
	v >>= shift;
	r |= shift;
	r |= (v >> 1);
	return r;
}

/* floor(log2(v)) for 64-bit v, 0 for v == 0. */
static __always_inline __u32 log2_u64(__u64 v)
{
	__u32 hi = v >> 32;

	if (hi)
		return log2_u32(hi) + 32;
	return log2_u32((__u32)v);
}

/* Adds one nanosecond delta to a log2 microsecond histogram. */
static __always_inline void hist_add(void *hist, __u64 delta_ns)
{
	__u32 slot = log2_u64(delta_ns / 1000);
	__u64 *count;

	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	count = bpf_map_lookup_elem(hist, &slot);
	if (count)
		__sync_fetch_and_add(count, 1);
}

/* Records the time a task became runnable. */
static __always_inline int runq_enqueue(__s32 pid)
{
	__u32 key = (__u32)pid;
	__u64 ts;

	if (pid <= 0)
		return 0;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&runq_start, &key, &ts, BPF_ANY);
	return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int tp_wakeup(struct sched_wakeup_args *ctx)
{
	return runq_enqueue(ctx->pid);
}

SEC("tracepoint/sched/sched_wakeup_new")
int tp_wakeup_new(struct sched_wakeup_args *ctx)
{
	return runq_enqueue(ctx->pid);
}

SEC("tracepoint/sched/sched_switch")
int tp_switch(struct sched_switch_args *ctx)
{
	__u32 next = (__u32)ctx->next_pid;
	__u64 *start, now;

	/* A task switched out while still runnable goes back on the run queue. */
	if ((ctx->prev_state & TASK_STATE_MASK) == 0)
		runq_enqueue(ctx->prev_pid);
	if (ctx->next_pid <= 0)
		return 0;
	start = bpf_map_lookup_elem(&runq_start, &next);
	if (!start)
		return 0;
	now = bpf_ktime_get_ns();
	if (now > *start)
		hist_add(&runq_hist, now - *start);
	bpf_map_delete_elem(&runq_start, &next);
	return 0;
}

SEC("tracepoint/block/block_rq_issue")
int tp_rq_issue(struct block_rq_args *ctx)
{
	struct bio_key key = {};
	__u64 ts = bpf_ktime_get_ns();

	key.dev = ctx->dev;
	key.sector = ctx->sector;
	bpf_map_update_elem(&bio_start, &key, &ts, BPF_ANY);
	return 0;
}

SEC("tracepoint/block/block_rq_complete")
int tp_rq_complete(struct block_rq_args *ctx)
{
	struct bio_key key = {};
	__u64 *start, now;

	key.dev = ctx->dev;
	key.sector = ctx->sector;
	start = bpf_map_lookup_elem(&bio_start, &key);
	if (!start)
		return 0;
	now = bpf_ktime_get_ns();
	if (now > *start)
		hist_add(&bio_hist, now - *start);
	bpf_map_delete_elem(&bio_start, &key);
	return 0;
}

SEC("kprobe/vfs_fsync_range")
int kp_fsync(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&fsync_start, &id, &ts, BPF_ANY);
	return 0;
}

SEC("kretprobe/vfs_fsync_range")
int kr_fsync(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u64 *start, now;

	start = bpf_map_lookup_elem(&fsync_start, &id);
	if (!start)
		return 0;
	now = bpf_ktime_get_ns();
	if (now > *start)
		hist_add(&fsync_hist, now - *start);
	bpf_map_delete_elem(&fsync_start, &id);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
