#!/usr/bin/env python
from bcc import BPF
import ctypes
import time
code="""
BPF_TABLE_PINNED("hash", u32, long, cnt, 1, "/sys/fs/bpf/counter");
"""
bpf = BPF(text=code)
counter = bpf.get_table("cnt")
while True:
  try:
    print(counter[ctypes.c_int(0)].value)
    time.sleep(1)
  except KeyboardInterrupt:
    break
