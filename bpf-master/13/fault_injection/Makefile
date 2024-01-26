include ../../help.mk

prepare: ## Prepare
	gcc -o test test.c

clean: ## Clean
	rm -f test

run: ## Run sample
	./test

strace: ## Fault injection with strace
	strace -e trace=clone -e fault=clone:error=EAGAIN ./test

bpftrace: ## Fault injection with bpftrace
	bpftrace -e 'k:__x64_sys_getuid /comm == "id"/ { override(2<<21); }' --unsafe -c id

list: ## List error injection
	cat /sys/kernel/debug/error_injection/list
