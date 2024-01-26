#!/usr/bin/env python
from bcc import BPF, libbcc
import pyroute2
import ctypes
import time
import sys
code = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
BPF_TABLE("array", uint32_t, long, cnt, 1);
int counter(struct __sk_buff *ctx) {
	uint32_t index = 0;
	long *value = cnt.lookup(&index);
	if (value)
		    *value += 1;
	return TC_ACT_OK;
}
"""
device = "lo"
path = "/sys/fs/bpf/counter"
bpf = BPF(text=code, cflags=["-w"])
func = bpf.load_func("counter", BPF.SCHED_CLS)
counter = bpf.get_table("cnt")
ret = libbcc.lib.bpf_obj_pin(counter.map_fd, ctypes.c_char_p(path.encode('utf-8')))
if ret != 0:
  raise Exception("Failed to pinning object")

ip = pyroute2.IPRoute()
ipdb = pyroute2.IPDB(nl=ip)
idx = ipdb.interfaces[device].index
ip.tc("add", "clsact", idx)
ip.tc("add-filter", "bpf", idx, ":1", fd=func.fd, name=func.name, parent="ffff:fff2", classid=1, direct_action=True)
while True:
  try:
    print(counter[0].value)
    time.sleep(1)
  except KeyboardInterrupt:
    print("Removing filter from device")
    break
ip.tc("del", "clsact", idx)
ipdb.release()
