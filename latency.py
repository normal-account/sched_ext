#!/usr/bin/env python3
"""
Compute runnable→running latency from sched_ext bpf_trace_printk logs.

Usage:
  python3 rq2run_latency.py /path/to/trace.log
  # or: cat trace.log | python3 rq2run_latency.py -

What it does:
- For each "runnable: pid N" line, remembers its timestamp.
- For each subsequent "running: pid N" line, pairs it with the earliest
  unmatched runnable timestamp for that PID and records (running - runnable).
- Prints count and latency stats. Times shown in microseconds.
"""

import sys, re, math, statistics
from collections import defaultdict, deque

# Match lines like:
#   ... 6446.236473: bpf_trace_printk:   runnable: pid 16854 comm intermittent
#   ... 6446.236479: bpf_trace_printk:   running:  pid 16854 comm intermittent ...
R_RUNNABLE = re.compile(r'(\d+\.\d+):\s+bpf_trace_printk:\s+runnable:\s+pid\s+(\d+)\b')
R_RUNNING  = re.compile(r'(\d+\.\d+):\s+bpf_trace_printk:\s+running:\s+pid\s+(\d+)\b')

def parse_stream(f):
    t_runnable = defaultdict(deque)  # pid -> deque of timestamps
    latencies = []  # seconds
    unmatched_running = 0
    total_runnable = 0

    for line in f:
        m = R_RUNNABLE.search(line)
        if m:
            ts = float(m.group(1))
            pid = int(m.group(2))
            t_runnable[pid].append(ts)
            total_runnable += 1
            continue

        m = R_RUNNING.search(line)
        if m:
            ts = float(m.group(1))
            pid = int(m.group(2))
            dq = t_runnable.get(pid)
            if dq and dq:
                start = dq.popleft()
                latencies.append(ts - start)
            else:
                unmatched_running += 1

    # Anything left in t_runnable are runnables that never got matched
    unmatched_runnable = sum(len(dq) for dq in t_runnable.values())
    return latencies, unmatched_runnable, unmatched_running, total_runnable

def fmt_us(x_sec):
    return f"{x_sec * 1e6:.1f}"

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "-"
    f = sys.stdin if path == "-" else open(path, "r", errors="replace")
    try:
        latencies, unr, unrn, total_rq = parse_stream(f)
    finally:
        if f is not sys.stdin:
            f.close()

    n = len(latencies)
    if n == 0:
        print("No runnable→running pairs found.")
        print(f"Unmatched runnables: {unr}, unmatched runnings: {unrn}")
        return

    latencies.sort()
    avg = sum(latencies) / n
    p50 = latencies[int(0.50*(n-1))]
    p90 = latencies[int(0.90*(n-1))]
    p95 = latencies[int(0.95*(n-1))]
    p99 = latencies[int(0.99*(n-1))]
    mn  = latencies[0]
    mx  = latencies[-1]

    print(f"Samples: {n} (seen runnables: {total_rq}, unmatched runnables: {unr}, unmatched runnings: {unrn})")
    print(f"Average latency:   {fmt_us(avg)} us")
    print(f"Median (p50):      {fmt_us(p50)} us")
    print(f"p90 / p95 / p99:   {fmt_us(p90)} / {fmt_us(p95)} / {fmt_us(p99)} us")
    print(f"Min / Max:         {fmt_us(mn)} / {fmt_us(mx)} us")

if __name__ == "__main__":
    main()

