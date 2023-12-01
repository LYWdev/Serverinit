import ctypes as ct
from bcc import BPF
code = """
BPF_TABLE("prog", int, int, jmp_table, 8);
BPF_PERF_OUTPUT(events);
struct data_t {
u64 timestamp;
char msg[128];
};
int xdp_pass( struct xdp_md *ctx)
{
jmp_table.call(ctx, 0 );
struct data_t d = {
    .timestamp = bpf_ktime_get_ns(),
    .msg = "Passed!\\0",
};
events.perf_submit(ctx, &d, sizeof (d));
return XDP_PASS;
}
int xdp_drop( struct xdp_md *ctx)
{
struct data_t d = {
    .timestamp = bpf_ktime_get_ns(),
    .msg = "Dropped!\\0",
};
events.perf_submit(ctx, &d, sizeof (d));
return XDP_DROP;
}
"""

class Event(ct.Structure):
  _fields_ = [
     ("timestamp", ct.c_uint64),
     ("msg", ct.c_char * 128),
  ]

def print_event(cpu, data, size):
  event = ct.cast(data, ct.POINTER(Event)).contents
  print(event.timestamp, event.msg)
bpf = BPF(text=code)
events = bpf["events"]
events.open_perf_buffer(print_event)
xdp_pass = bpf.load_func("xdp_pass", BPF.XDP)
xdp_drop = bpf.load_func("xdp_drop", BPF.XDP)
bpf.attach_xdp("lo", xdp_pass, 0)

