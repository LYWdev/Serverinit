#2024.1.22
#설명
#모든 프로세스에 대해서 uid, suid, euid의 변화를 감지하고 출력함
#ver4는 euid == 0인 process에 대해서는 검사를 수행하지 않는 것으로 진행 예정
#root권한으로 변경된 것을 잡음

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
    //u64 syscall_number;
};

//cred 객체 정보
struct cred_data{

    char task_name[TASK_COMM_LEN];
    u32 is_not_root;
    u32 confirm_setuid;        //확인중인 data 표시
    u32 confirm;                //검사 중이라는 뜻
    u32 from_sys_enter;

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
    if((cred->euid).val == 0)
    {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct cred_data_key key_cred_data = {};
    struct cred_data * val_cred_data, zero_cred_data = {};
    struct cred_args_error * val_cred_args_error, zero_cred_args_error = {};
    key_cred_data.pid = pid;
    key_cred_data.tid = tid;
    //key_cred_data.syscall_number = args->id;
    val_cred_data = data_pid_cred_data.lookup_or_try_init(&key_cred_data, &zero_cred_data);
    val_cred_args_error = data_pid_cred_args_error.lookup_or_try_init(&key_cred_data,&zero_cred_args_error);
    if(val_cred_args_error)  //args error를 감지하기 위해서 넣는 구조체
    {
        val_cred_args_error->pid = pid;
        val_cred_args_error->tid = tid;
        val_cred_args_error->syscall_number_enter = (args->id);
        val_cred_args_error->confirm = 1;
    }
    if(val_cred_data)
    {   
        val_cred_data->is_not_root = 1;     //euid == 0일 경우에는 검사하지 않기위해서
        val_cred_data->from_sys_enter = 1;
        val_cred_data->syscall_number = args->id;
        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char *)val_cred_data->task_name,sizeof(name),name);
        val_cred_data->prev_uid = val_cred_data->uid = (kuid_t)cred->uid;
        val_cred_data->prev_suid = val_cred_data->suid = (kuid_t)cred->suid;
        val_cred_data->prev_euid = val_cred_data->euid = (kuid_t)cred->euid;
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
    val_cred_data = data_pid_cred_data.lookup_or_try_init(&key_cred_data, &zero_cred_data);
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
    if(val_cred_data)
    {   
        if(val_cred_data->is_not_root == 0)
        {
            data_pid_cred_data.delete(&key_cred_data);
            goto done;
        }
        if(val_cred_data->from_sys_enter == 0)
        {
            data_pid_cred_data.delete(&key_cred_data);
            goto done;
        }
        /*
        if((val_cred_data->uid).val != (cred->uid).val || (val_cred_data->suid).val != (cred->suid).val || (val_cred_data->euid).val != (cred->euid).val)   //달라졌음
        {
            val_cred_data->dangerous = 1;
        }
        */
        //이 if문까지 왔다는 것은 sys_enter를 거쳐왔고 처음에 시스템콜 호출 당시 euid가 0이 아니었단 뜻임
        if((cred->uid).val == 0)   // 유저아이디가 root로 변경되었음
        {
            val_cred_data->dangerous = 1;
            val_cred_data->chuid = 1;
            val_cred_data->uid = (kuid_t)cred->uid;
        }
        if((cred->suid).val == 0) //suid가 root로 변경되었음
        {
            val_cred_data->dangerous = 1;
            val_cred_data->chsuid = 1;
            val_cred_data->suid = (kuid_t)cred->suid;
        }
        if((cred->euid).val == 0) //euid가 root로 변경되었음
        {
            val_cred_data->dangerous = 1;
            val_cred_data->cheuid = 1;
            val_cred_data->euid = (kuid_t)cred->euid;
        }
        if(val_cred_data->dangerous != 0)
        {
            val_cred_data->confirm = 0;
            val_cred_data_dangerous = data_pid_cred_data_dangerous.lookup_or_try_init(&key_cred_data, &zero_cred_data_dangerous);
            if(val_cred_data_dangerous)
            {
                val_cred_data_dangerous->dangerous = 1;
                char name[TASK_COMM_LEN];
                bpf_get_current_comm(&name, sizeof(name));
                bpf_probe_read_str((char *)val_cred_data_dangerous->task_name,sizeof(name),name);
                val_cred_data_dangerous->syscall_number = args->id;
                val_cred_data_dangerous->uid = val_cred_data->uid;
                val_cred_data_dangerous->suid = val_cred_data->suid;
                val_cred_data_dangerous->euid = val_cred_data->euid;
                val_cred_data_dangerous->prev_uid = val_cred_data->prev_uid;
                val_cred_data_dangerous->prev_suid = val_cred_data->prev_suid;
                val_cred_data_dangerous->prev_euid = val_cred_data->prev_euid;
                val_cred_data_dangerous->chuid = val_cred_data->chuid;
                val_cred_data_dangerous->chsuid = val_cred_data->chsuid;
                val_cred_data_dangerous->cheuid = val_cred_data->cheuid;
            }
        }
        data_pid_cred_data.delete(&key_cred_data);
    }

done :
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

TRACEPOINT_PROBE(kmem, kmalloc) {
    
    if(args->bytes_alloc < 32)
    {
        return 0;
    }
    u32 uid = (u32)bpf_get_current_uid_gid();
    if(uid == 0)
    {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 page_size = PAGE_SIZE;
    u64 per_page_slab = (PAGE_SIZE*2)/args->bytes_alloc;

    struct kmalloc_time * val, zero = {};
    struct kmalloc_dangerous * val_dangerous, zero_dangerous = {};
    struct pid_kmalloc_key val_pid_kmalloc_key;  

    val_pid_kmalloc_key.pid = pid;
    val_pid_kmalloc_key.bytes_alloc = args->bytes_alloc;
    val = data_pid_kmalloc.lookup_or_try_init(&val_pid_kmalloc_key, &zero);
    
    if(val)
    {
        lock_xadd(&val->count, 1);
        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char *)val->task_name,sizeof(name)...
