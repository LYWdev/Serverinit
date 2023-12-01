#!/usr/bin/env python
from bcc import BPF
code = """
int xdp_drop(struct xdp_md *ctx)
{
  return XDP_DROP;
}
"""
 
bpf = BPF(text=code)
xdp_drop = bpf.load_func("xdp_drop", BPF.XDP)
bpf.attach_xdp("lo", xdp_drop, 0)
