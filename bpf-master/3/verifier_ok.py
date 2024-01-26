#!/usr/bin/python
from bcc import BPF
from time import sleep
prog = """
 BPF_HASH(syscall);
 int kprobe__sys_clone(void *ctx) {
     u64 counter = 0;
     u64 key = 56;
     u64 *p; 
     p = syscall.lookup(&key);
     if (p != 0) {
         counter = *p;
     }
     counter++;
     syscall.update(&key, &counter);
     return 0;
 }
"""
b = BPF(text=prog)
