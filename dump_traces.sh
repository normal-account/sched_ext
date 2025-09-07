echo 0 | sudo tee /sys/kernel/tracing/tracing_on
sudo cat /sys/kernel/tracing/trace > trace.log