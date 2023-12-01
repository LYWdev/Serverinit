include ../../help.mk

PID=$(shell docker inspect -f {{.State.Pid}} sample)
ID=$(shell docker inspect -f {{.ID}} sample)

prepare: bcc ## install docker
	docker run --rm -d -P --name sample nginx

cgroupid:
	git clone https://github.com/iovisor/bcc
	cd bcc/examples/cgroupid \
		&& git checkout v0.16.0 \
		&& cp cgroupid /usr/local/bin/cgroupid

clean:
	rm -rf bcc
	docker rm -f sample

check/function: ## check functions
	readelf -a /proc/$(PID)/root/usr/sbin/nginx | grep FUNC | grep -v UND | less

check/binary: ## List probes from binary
	bpftrace -l 'uprobe:/proc/$(PID)/root/usr/sbin/nginx:*'

check/runtime: ## List probes from process
	bpftrace -l -p $(PID)

check/cgroup: ## check cgroupid
	cgroupid hex /sys/fs/cgroup/unified/system.slice/docker-$(ID).scope

trace1: ## uprobe in docker
	bpftrace -e \
		'uprobe:/proc/$(PID)/root/usr/sbin/nginx:ngx_http_* { printf("%d %s %s: %s\n", pid, probe, comm, ustack()) }'

trace2: ## cgroup filter
	bpftrace -e \
		'tracepoint:syscalls:sys_enter_accept* /cgroup == cgroupid("/sys/fs/cgroup/unified/system.slice/docker-$(ID).scope")/ { printf("worker: %d %x %s\n", pid, cgroup, probe) }'
