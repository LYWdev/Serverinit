
#!/usr/bin/env python
#
# syscount   Summarize syscall counts and latencies.
#
# USAGE: syscount [-h] [-p PID] [-t TID] [-i INTERVAL] [-d DURATION] [-T TOP]
#                 [-x] [-e ERRNO] [-L] [-m] [-P] [-l] [--syscall SYSCALL]
#
# Copyright 2017, Sasha Goldshtein.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Feb-2017   Sasha Goldshtein    Created this.
# 16-May-2022   Rocky Xing          Added TID filter support.
# 26-Jul-2022   Rocky Xing          Added syscall filter support.

#2024.1.22
#설명
#모든 프로세스에 대해서 uid, suid, euid의 변화를 감지하고 출력함
#ver4는 euid == 0인 process에 대해서는 검사를 수행하지 않는 것으로 진행 예정

from time import sleep, strftime
import argparse
import errno
import itertools
import sys
import signal
from bcc import BPF
from bcc.utils import printb
from bcc.syscall import syscall_name, syscalls
import csv
import time

if sys.version_info.major < 3:
    izip_longest = itertools.izip_longest
else:
    izip_longest = itertools.zip_longest

# signal handler
def signal_ignore(signal, frame):
    print()

def handle_errno(errstr):
    try:
        return abs(int(errstr))
    except ValueError:
        pass

    try:
        return getattr(errno, errstr)
    except AttributeError:
        raise argparse.ArgumentTypeError("couldn't map %s to an errno" % errstr)

text = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <linux/cred.h>

struct pid_syscall_key{
    u64 pid;
    u64 syscall_number;
};
struct count_time{
    u64 count;
    u64 last_time;
    u64 time;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    u64 arg5;
    u64 arg6;
};
struct pid_kmalloc_key{
    u64 pid;
    u64 bytes_alloc;
};
struct pid_page_order_key{
    u64 pid;
    u64 order;
};
struct kmalloc_time{
    u64 count;
    u64 prev_count;
    u64 last_time;
    u64 cur_time;
    u64 time;
    u32 alert;
    char task_name[TASK_COMM_LEN];
    u32 cpu_site;

    u64 call_site;
    u64 ptr;
    u64 bytes_req;
    u64 bytes_alloc;
    u64 gfp_flags;
    u64 node;
};

struct kmalloc_dangerous{
    char task_name[TASK_COMM_LEN];
    u64 count;
    u64 time;
};
struct kmem_alloc_data{
    char task_name[TASK_COMM_LEN];
    
    u32 cpu_site;
    u64 count;
    u64 call_site;
    u64 ptr;
    u64 bytes_req;
    u64 bytes_alloc;
    u64 gfp_flags;
};
struct mm_page_alloc_data{
    char task_name[TASK_COMM_LEN];
    
    u32 cpu_site;
    u64 count;
    u64 pfn;
    u64 order;
    u64 gfp_flags;
};

//cred 객체 정보 key
struct cred_data_key{
    u32 pid;
    u32 tid;
};

//cred 객체 정보
struct cred_data{

    char task_name[TASK_COMM_LEN];
    u32 is_not_root;
    u32 confirm_setuid;        //확인중인 data 표시
    u32 confirm;                //검사 중이라는 뜻

    kuid_t prev_uid;
    kuid_t prev_suid;
    kuid_t prev_euid;

    kuid_t uid;
    kuid_t suid;
    kuid_t euid;

    u32 chuid;
    u32 chsuid;
    u32 cheuid;

    u32 syscall_number;
    u32 dangerous;      //위험한 data 표시
};

struct cred_data_dangerous
{
    char task_name[TASK_COMM_LEN];
    u32 confirm;        //setuid가 사용된 상태

    kuid_t prev_uid;
    kuid_t prev_suid;
    kuid_t prev_euid;

    kuid_t uid;
    kuid_t suid;
    kuid_t euid;

    u32 chuid;
    u32 chsuid;
    u32 cheuid;
    
    u32 syscall_number;
    u32 dangerous;
};

//args error를 감지하기 위해서 넣는 구조체
struct cred_args_error
{
    u32 pid;
    u32 tid;
    
    u32 syscall_number_enter;
    u32 syscall_number_exit;

    u32 confirm; //exit부터 시작한 애가 있을 수 있음 enter부터 시작했냐는 뜻임
};
struct cred_args_error_dangerous
{
    u32 pid;
    u32 tid;

    u32 syscall_number_enter;
    u32 syscall_number_exit;
};


BPF_HASH(data, u32, u64);
BPF_HASH(first_time, u64, u64);
BPF_HASH(cur_time, u64, u64);
BPF_HASH(record, struct pid_syscall_key, u64);
BPF_HASH(data_pid_syscall,struct pid_syscall_key, struct count_time );

// kmalloc 확인
BPF_HASH(data_pid_kmalloc, struct pid_kmalloc_key, struct kmalloc_time );
BPF_HASH(data_pid_kmalloc_dangerous,struct pid_kmalloc_key, struct kmalloc_dangerous);
// cache alloc 확인
BPF_HASH(data_pid_kmem_alloc, struct pid_kmalloc_key, struct kmem_alloc_data);
// page alloc 확인
BPF_HASH(data_pid_page_alloc, struct pid_page_order_key, struct mm_page_alloc_data);

//아래는 cred 객체를 확인하는 것과 관련된 hash_map들
BPF_HASH(data_pid_cred_data, struct cred_data_key, struct cred_data);
BPF_HASH(data_pid_cred_data_dangerous, struct cred_data_key, struct cred_data_dangerous);
//BFP_HASH(data_pid_cred_data, u32, u64);
BPF_HASH(data_pid_cred_args_error, struct cred_data_key, struct cred_args_error);       //args error를 감지하기 위해서 넣는 구조체
BPF_HASH(data_pid_cred_args_error_dangerous,struct cred_data_key, struct cred_args_error_dangerous);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct cred_data_key key_cred_data = {};
    struct cred_data * val_cred_data, zero_cred_data = {};
    struct cred_args_error * val_cred_args_error, zero_cred_args_error = {};
    key_cred_data.pid = pid;
    key_cred_data.tid = tid;
    //key_cred_data.syscall_number = args->id;
    //val_cred_data = data_pid_cred_data.lookup_or_try_init(&key_cred_data, &zero_cred_data);
    val_cred_args_error = data_pid_cred_args_error.lookup_or_try_init(&key_cred_data,&zero_cred_args_error);
    if(val_cred_args_error)  //args error를 감지하기 위해서 넣는 구조체
    {
        val_cred_args_error->pid = pid;
        val_cred_args_error->tid = tid;
        val_cred_args_error->syscall_number_enter = (args->id);
        val_cred_args_error->confirm = 1;
    }
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct cred_data_key key_cred_data = {};
    struct cred_data * val_cred_data, zero_cred_data = {};
    struct cred_data_dangerous * val_cred_data_dangerous, zero_cred_data_dangerous={};
    struct cred_args_error * val_cred_args_error, zero_cred_args_error = {};
    struct cred_args_error_dangerous * val_cred_args_error_dangerous, zero_cred_args_error_dangerous = {};

    key_cred_data.pid = pid;
    key_cred_data.tid = tid;
    //key_cred_data.syscall_number = args->id;
    //val_cred_data = data_pid_cred_data.lookup_or_try_init(&key_cred_data, &zero_cred_data);
    val_cred_args_error = data_pid_cred_args_error.lookup_or_try_init(&key_cred_data,&zero_cred_args_error);
    if(val_cred_args_error)  //args error를 감지하기 위해서 넣는 구조체
    {
        val_cred_args_error->syscall_number_exit = args->id;
        if(val_cred_args_error->confirm == 1 && val_cred_args_error->syscall_number_enter != val_cred_args_error->syscall_number_exit )//val_cred_args_error->syscall_number_exit)
        {
            val_cred_args_error->confirm = 0;
            val_cred_args_error_dangerous = data_pid_cred_args_error_dangerous.lookup_or_try_init(&key_cred_data, &zero_cred_args_error_dangerous);
            if(val_cred_args_error_dangerous)
            {
                val_cred_args_error_dangerous->pid = val_cred_args_error->pid;
                val_cred_args_error_dangerous->tid = val_cred_args_error->tid;
                val_cred_args_error_dangerous->syscall_number_enter = val_cred_args_error->syscall_number_enter;
                val_cred_args_error_dangerous->syscall_number_exit = val_cred_args_error->syscall_number_exit;
            }
        }
        data_pid_cred_args_error.delete(&key_cred_data);
    }
    return 0;
}

int kprobe__do_exit(void *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct cred_data_key key_cred_data = {};
    struct cred_data * val_cred_data, zero_cred_data = {};
    struct cred_data_dangerous * val_cred_data_dangerous, zero_cred_data_dangerous={};

    key_cred_data.pid = pid;
    key_cred_data.tid = tid;
    //key_cred_data.syscall_number = args->id;
    val_cred_data = data_pid_cred_data.lookup_or_try_init(&key_cred_data, &zero_cred_data);
    if(val_cred_data)
    {
        data_pid_cred_data.delete(&key_cred_data);
    }
    return 0;
}

"""

bpf = BPF(text=text)

def comm_for_pid(pid):
    try:
        return open("/proc/%d/comm" % pid, "rb").read().strip()
    except Exception:
        return b"[unknown]"
    
def print_count_stats():
    data = bpf["data_pid_syscall"]
    
    global print_type
    global first_time
    global is_print
    if is_print == 0:
        first_time = time.time()
    cur_time = time.time() - first_time
    #print(type(time.time()), type(first_time), cur_time)
    for k, v in sorted(data.items(), key=lambda kv: -kv[1].count)[:args.top]:
        process_name = comm_for_pid(k.pid).decode('utf-8')
        if process_name == 'poc':
            is_print = 1
            write_data = [print_type, cur_time, k.pid, process_name, "%s" % syscall_name(k.syscall_number).decode('utf-8'), v.arg1, v.arg2, v.arg3, v.arg4, v.arg5, v.arg6,v.count]
            writer.writerow(write_data)
    if is_print == 1:
        print_type += 1

    for k, v in sorted(data.items(), key=lambda kv: -kv[1].count)[:args.top]:
        process_name = comm_for_pid(k.pid).decode('utf-8')
        print(k.pid)
        if v.alert == 1:

            is_print = 1
            write_data = [print_type, cur_time, k.pid, process_name, "%s" % syscall_name(k.syscall_number).decode('utf-8'), v.arg1, v.arg2, v.arg3, v.arg4, v.arg5, v.arg6,v.count]
            print(write_data)
    if is_print == 1:
        print_type += 1

def print_cred_stat():
    data_cred = bpf["data_pid_cred_data"]
    data_cred_dangerous = bpf['data_pid_cred_data_dangerous']
    data_cred_args_error_dangerous = bpf['data_pid_cred_args_error_dangerous']
    is_alert = 0
    global print_type
    global first_time
    global is_print
    check = 0
    if is_print == 0:
        first_time = time.time()
    cur_time = time.time() - first_time
    """
    for k, v in data_cred.items():
        process_name= (v.task_name).decode('utf-8')
        #print(v.dangerous)
        #if 'uid' in process_name:
        if process_name == 'poc':
            write_data = [print_type,k.pid, k.tid, k.syscall_number, syscall_name(k.syscall_number).decode('utf-8'),process_name,v.dangerous,v.prev_uid.val,v.uid.val,v.prev_suid.val, v.suid.val, v.prev_euid.val, v.euid.val ,v.chuid, v.chsuid, v.cheuid, cur_time,'cred' ]
            print(write_data)
            #writer.writerow(write_data)
            is_print = 1
            check = 1
    """
    #data_kmalloc.clear()
    """
    for k, v in data_cred_dangerous.items_lookup_and_delete_batch():
        process_name= (v.task_name).decode('utf-8')
        write_data = [print_type,k.pid, k.tid, k.syscall_number, syscall_name(k.syscall_number).decode('utf-8'),process_name,v.dangerous,v.prev_uid.val,v.uid.val,v.prev_suid.val, v.suid.val, v.prev_euid.val, v.euid.val ,v.chuid, v.chsuid, v.cheuid, cur_time,'cred' ]
        print(write_data)
        is_print = 1
        check = 1
        #print(k)
        #data_cred_dangerous.items_lookup_and_delete_batch()
    #data_kmalloc.clear()
    """
    for k, v in data_cred_args_error_dangerous.items_lookup_and_delete_batch():
        write_data = [print_type,v.pid, v.tid, v.syscall_number_enter, v.syscall_number_exit, syscall_name(v.syscall_number_enter).decode('utf-8'), syscall_name(v.syscall_number_exit).decode('utf-8') ,'args error' ]
        print(write_data)
        is_print = 1
        check = 1
        #print(k)
        #data_cred_dangerous.items_lookup_and_delete_batch()
    """
    if check == 1:
        data_cred_dangerous.clear()
    """
    if check == 1:
        print_type += 1
#f = open('out.csv', 'w')
#writer = csv.writer(f)

print_type = 0
is_print = 0
first_time = 0
exiting = 0
print('start')
while True:
    try:
        print_cred_stat()
    except KeyboardInterrupt:
        exiting = 1
        signal.signal(signal.SIGINT, signal_ignore)
    if exiting:
        #f.close()
        print("Detaching...")
        exit()
