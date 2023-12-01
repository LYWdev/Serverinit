include ../../help.mk

prepare: ## Prepare
	go build -o uprobe -gcflags '-N -l' uprobe.go
	go build -o usdt -gcflags '-N -l' usdt.go

clean: ## Clean
	rm -f usdt uprobe

run/uprobe: ## Run uprobe sample
	./uprobe

run/usdt: ## Run USDT sample
	./usdt

check/uprobe: ## List uprobe in binary   
	bpftrace -l 'uprobe:./uprobe:*my*'

check/usdt: ## List USDT probe in process
	bpftrace -l -p $(shell pgrep usdt) 'usdt:*'

trace/uprobe1: ## Trace uprobe args with sarg
	bpftrace -e 'uprobe:./uprobe:*my_* { printf("%s %d %s", probe, sarg0, ustack) }'

trace/uprobe2: ## Trace uprobe args with sp register
	bpftrace -e 'uprobe:./uprobe:*my_* { printf("%s %d %s", probe, *(reg("sp") + 8), ustack) }'

trace/uretprobe: ## Trace uretprobe
	bpftrace -e 'uretprobe:./uprobe:*my_* { printf("%s %d %s", probe, retval, ustack) }'

trace/usdt: ## Trace USDT
	bpftrace -p $(shell pgrep usdt) -e 'usdt:./usdt:* { printf("%s %s", probe, ustack) }'

.PHONY: prepare clean run/uprobe run/usdt check/uprobe check/usdt trace/uprobe1 trace/uprobe2 trace/uretprobe trace/usdt
