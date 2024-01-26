include ../help.mk

prepare: bcc bpftrace mybin watchpoint

bcc:
	git clone https://github.com/iovisor/bcc
	cd bcc \
		&& git checkout v0.16.0

bpftrace:
	git clone https://github.com/iovisor/bpftrace
	cd bpftrace \
		&& git checkout v0.11.2

mybin:
	gcc -o mybin mybin.c

extract-vmlinux:
	wget -O extract-vmlinux https://raw.githubusercontent.com/torvalds/linux/master
	chmod +x extract-vmlinux

watchpoint:
	gcc bpftrace/tests/testprogs/watchpoint.c -o watchpoint

clean: ## Clean
	rm -rf bcc bpftrace mybin watchpoint *.perf vmlinux

.PHONY: prepare clean

p77: ## Docker build
	docker build -t bpfenv .

p78-1: ## Docker run
	docker run -ti \
		--privileged \
		--pid host \
		--net host \
		--volume /sys/fs/cgroup:/sys/fs/cgroup \
		--volume /sys/kernel/debug:/sys/kernel/debug \
		--volume /sys/fs/bpf:/sys/fs/bpf \
		--volume /lib/modules:/lib/modules \
		bpfenv bash

p78-2: ## Check mount
	mount | egrep 'debug|trace|cgroup|bpf'

p80: ## Check bcc tools
	ls bcc/tools/*.py
	ls -l bcc/tools/*.py | wc -l

p81-1: ## funccount
	bcc/tools/funccount.py tcp_drop

p81-2: ## funccount
	bcc/tools/funccount.py 'vfs_*'

p82-1: ## funccount
	bcc/tools/funccount.py -i 1 'c:pthread_mutex_lock'

p82-2: ## funccount
	bcc/tools/funccount.py 'c:str*'

p83-1: ## funccount
	bcc/tools/funccount.py 't:syscalls:sys_enter_*'

p83-2: ## stackcount
	bcc/tools/stackcount.py ktime_get

p84-1: ## stackcount
	bcc/tools/stackcount.py -P ktime_get

p84-2: ## stackcount
	bcc/tools/stackcount.py -f -P -D 10 ktime_get > stack.out
	wc stack.out
	git clone http://github.com/brendangregg/FlameGraph
	cd FlameGraph
	./flamegraph.pl --ash --bgcolor=grey < ../stack.out > stack.svg

p85-1: ## trace
	bcc/tools/trace.py 'do_sys_open "%s", arg2'

p85-2: ## trace
	bcc/tools/trace.py 'c:open (arg2 == 42) "%s %d", arg1, arg2'

p85-3: ## trace
	bcc/tools/trace.py '__x64_sys_read (arg3 > 20000) "read %d bytes", arg3'

p86-1: ## trace
	bcc/tools/trace.py 'do_sys_open "%s", arg2@user' -UK -f temp

p86-2: ## argdist
	bcc/tools/argdist.py -H 'r::__tcp_select_window():int:$$retval'

p88: ## bpftrace
	bpftrace -l 'tracepoint:syscalls:sys_enter_*'

p89-1: ## bpftrace helloworld
	bpftrace -e 'BEGIN { printf("hello world\n"); }'

p89-2: ## bpftrace openat
	bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'

p90-1: ## bpftrace tracepoint detail
	bpftrace -vl tracepoint:syscalls:sys_enter_openat

p90-2: ## bpftrace map
	bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'

p91: ## bpftrace histo
	bpftrace -e 'tracepoint:syscalls:sys_exit_read /pid =='$$(pidof dockerd)'/ { @bytes = hist(args->ret); }'

p92: ## bpftrace lhisto
	 bpftrace -e 'kretprobe:vfs_read { @bytes = lhist(retval, 0, 2000, 200); }'

p93: ## bpftrace time elapsed
	 bpftrace -e 'kprobe:vfs_read { @start[tid] = nsecs; } kretprobe:vfs_read /@start[tid]/ { @ns[comm] = hist(nsecs - @start[tid]); delete(@start[tid]); }'

p94: ## bpftrace interval
	bpftrace -e 'tracepoint:sched:sched* { @[probe] = count(); } interval:s:5 { exit(); }'

p95-1: ## bpftrace stack trace
	bpftrace -e 'profile:hz:99 { @[kstack] = count(); }'

p95-2: ## bpftrace stack trace scheduler
	bpftrace -e 'tracepoint:sched:sched_switch { @[kstack] = count(); }'

p96: ## bpftrace block io
	bpftrace -e 'tracepoint:block:block_rq_issue { @ = hist(args->bytes); }'

p97: ## bpftrace with kernel struct
	bpftrace path.bt

p100: ## bpftrace event list
	bpftrace -l 'kprobe:vfs_*'

p101-1: ## bpftrace tracepoint list
	bpftrace -l tracepoint:*

p101-2: ## bpftrace tracepoint
	bpftrace -e 'tracepoint:block:block_rq_insert { printf("block I/O created by %d\n", tid); }'

p101-3: ## bpftrace tracepoint detail
	bpftrace -vl tracepoint:syscalls:sys_enter_openat

p102: ## bpftrace tracepoint with arg
	 bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'

p103-1: ## bpftrace check usdt in shared object
	bpftrace -l 'usdt:/usr/lib/libc.so.6:*'

p103-2: ## bpftrace check usdt in proces
	bpftrace -p $(pidof mybin) -l 'usdt:*'

p103-3: ## check shared object in binary
	ldd ./mybin

p103-4: ## bpftrace usdt
	bpftrace -e 'usdt:/lib64/libc.so.6:* { printf("%s\n", probe) }'

p104-1: ## bpftrace check kprobe
	bpftrace -l kprobe:*

p104-2: ## bpftrace
	bpftrace -e 'kprobe:do_nanosleep { printf("sleep by %d\n", tid); }'

p105-1: ## disassemble kernel function
	 gdb -q /usr/lib/debug/boot/vmlinux-$$(uname -r) --ex 'disassemble do_sys_open'

p105-2: ## disassemble with objdump
	FUNCADDR=$$(cat /boot/System.map | grep -E 'do_sys_open$$' | awk '{print $$1}') \
	     && objdump -S --start-address=0x$$FUNCADDR ./vmlinux | awk '{print $$0} $$3~/retq?/{exit}'

p106-1: ## bpftrace with kprobe offset
	bpftrace -e 'kprobe:do_sys_open+9 { printf("in here\n"); }'

p106-2: ## bpftrace with kprobe offset 
	bpftrace -e 'kprobe:do_sys_open+1 { printf("in here\n"); }'

p106-3: ## bpftrace with kprobe struct field
	bpftrace field.bt

p107: ## bpftrace check struct from BTF
	bpftrace -lv "struct path"

p108-1: ## bpftrace check uprobe
	bpftrace -l 'uprobe:/bin/bash'

p108-2: ## bpftrace uprobe
	bpftrace -e 'uprobe:/bin/bash:find_shell_builtin { printf("arg0: %s\n", str(arg0)); }'

p108-3: ## bpftrace uretprobe
	bpftrace -e 'uretprobe:/bin/bash:initialize_shell_builtins { printf("ret: %d\n", retval); }'

p108-4: ## bpftrace urpboe with function address
	FUNCADDR=$$(objdump -tT /bin/bash | grep initialize_shell_builtins | awk '{print $$1}') \
		 && bpftrace -e 'uprobe:/bin/bash:0x'$$FUNCADDR'{ printf("in here\n"); }'

p109-1: ## bpftrace with uprobe offset
	 bptrace -e 'uprobe:/usr/bin/bash:initialize_shell_builtins+10 { printf("in here\n"); }'

p109-2: ## disassemble function
	objdump -d /usr/bin/bash | grep -A 10 -E '<initialize_shell_builtins.+>:'

p111: ## bpftrace software event
	bpftrace -e 'software:context-switches:100 { @[comm] = count(); }'

p112: ## bpftrace profile
	bpftrace -e 'profile:hz:99 { @[comm] = count(); }'

p113-1: ## bpftrace interval
	bpftrace -e 'i:s:1 { printf("%s\n", strftime("%H:%M:%S", nsecs)); }'

p113-2: ## bpftrace BEGIN/END
	bpftrace -e 'BEGIN { printf("started\n") } END { printf("finished\n")}'

p114-1: ## bpftrace kfunc detail
	bpftrace -lv kfunc:fget

p114-2: ## bpftrace kfunc
	bpftrace -e 'kfunc:fget { printf("fd %d\n", args->fd); }' 

p115: ## bpftrace watchpoint
	bpftrace -e 'watchpoint::0x10000000:8:rw { printf("hit!\n"); }' -p $$(pidof mybin)

p116: ## bpftrace watchpoint
	bpftrace -v -e 'watchpoint::0x10000000:8:w { printf("hit!\n"); exit() }' -c ./watchpoint

p117-1: ## bpftrace ?:
	bpftrace -e 'tracepoint:syscalls:sys_exit_read { @error[args->ret < 0 ? - args->ret : 0] = count(); }'

p117-2: ## bpftrace if-else
	 bpftrace -e 'tracepoint:syscalls:sys_enter_read { @reads = count(); if (args->count > 1024) { @large = count(); } }'

p118-1: ## bpftrace unroll
	 bpftrace -e 'kprobe:do_nanosleep { $$i = 1; unroll(5) { printf("i: %d\n", $$i); $$i = $$i + 1; } }'

p118-2: ## bpftrace while
	bpftrace -e 'i:ms:100 { $$i = 0; while ($$i <= 100) { printf("%d ", $$i); $$i++} exit(); }'

p120: ## bpftrace tuple
	 bpftrace -e 'BEGIN { $$t = (1, 2, "string"); printf("%d %s\n", $$t.1, $$t.2); }'

p121-1: ## bpftrace map
	 bpftrace -e 'kretprobe:vfs_read /pid==1234/ { @bytes = hist(retval); }'

p121-2: 
	 bpftrace -e 'BEGIN { @start = nsecs; }  kprobe:do_nanosleep /@start != 0/ { printf("at %d ms: sleep\n", (nsecs - @start) /  1000000); }'

p122:
	 bpftrace -e 'BEGIN { @start = nsecs; }  kprobe:do_nanosleep /@start != 0/ { printf("at %d ms: sleep\n", (nsecs - @start) /  1000000); }'

p123-1:
	bpftrace -e 'kprobe:do_nanosleep { @start[tid] = nsecs; } kretprobe:do_nanosleep /@start[tid] != 0/ { printf("slept for %d ms\n", (nsecs - @start[tid]) / 1000000); delete(@start[tid]); }'

p123-2:
	bpftrace -e 'kprobe:do_nanosleep { @start[tid] = nsecs; }  kretprobe:do_nanosleep /@start[tid] != 0/ { $$delta = nsecs - @start[tid]; printf("slept for %d ms\n", $$delta / 1000000); delete(@start[tid]); }'

p131:
	 bpftrace -e 'profile:hz:99 /pid=='$$(pidof dockerd)'/ { printf("%s %d [000] %u.%06u: cpu-clock:", comm, pid, nsecs/1000000000, nsecs%1000000 );  printf("%s", ustack(perf)); printf("\n"); }' | sed '1d' > bpftrace.perf

p133:
	ls bpftrace/tools/*bt
