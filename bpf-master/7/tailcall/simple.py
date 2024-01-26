#!/usr/bin/env python
from bcc import BPF
from ctypes import *
prog="""
BPF_PROG_ARRAY(prog_array, 10);

int callee(void *ctx) {
  bpf_trace_printk("byed\\n");
  return 0;
}

int caller(void *ctx) {
  bpf_trace_printk("hi\\n");
  prog_array.call(ctx, 2);
  bpf_trace_printk("hi2\\n");
  return 0;
}
"""
b = BPF(text=prog)
tail_fn = b.load_func("callee", BPF.KPROBE)
prog_array = b.get_table("prog_array")
prog_array[c_int(2)] = c_int(tail_fn.fd)
b.attach_kprobe(event="__x64_sys_clone", fn_name="caller")
b.trace_print()
