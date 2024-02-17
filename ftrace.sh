#!/bin/bash

echo 0 > /sys/kernel/debug/tracing/tracing_on
sleep 1
echo "tracing_off"

echo 1 > /sys/kernel/debug/tracing/tracing_on
sleep 1
echo "tracing_on"

echo nop > current_tracer`
sleep 1
echo "버이버트 "




echo 0 > /sys/kernel/debug/tracing/events/enable
sleep 1
echo "events disabled"

echo secondary_start_kernel > /sys/kernel/debug/tracing/set_ftrace_filter
sleep 1
echo "set_ftrace_filter init"

echo function > /sys/kernel/debug/tracing/current_tracer
sleep 1
echo "function tracer enabled"

echo 1 > /sys/kernel/debug/tracing/events/sched/sched_wakeup/enable
echo 1 > /sys/kernel/debug/tracing/events/sched/sched_switch/enable

echo 1 > /sys/kernel/debug/tracing/events/sched/irq_handler_entry/enable
echo 1 > /sys/kernel/debug/tracing/events/sched/irq_handler_exit/enable

echo 1 > /sys/kernel/debug/tracing/events/enable

echo 0 > /sys/kernel/debug/tracing/events/enable
