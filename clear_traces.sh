# pick the path that exists on your system
TP=/sys/kernel/tracing           # modern tracefs
# TP=/sys/kernel/debug/tracing   # older debugfs mount

# stop tracing, clear, then resume
echo 0 | sudo tee $TP/tracing_on >/dev/null
sudo sh -c ": > $TP/trace"       # clears the ring buffer (affects trace & trace_pipe)
echo 1 | sudo tee $TP/tracing_on >/dev/null

