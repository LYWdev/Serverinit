include ../help.mk

prepare: bash tplist ## Prepare assets

bash: ## Prepare bash related
	wget https://ftp.gnu.org/gnu/bash/bash-5.0.tar.gz
	tar xvf bash-5.0.tar.gz
	rm -f bash-5.0.tar.gz
	cd bash-5.0 \
		&& ./configure \
		&& make

tplist: ## Prepare tplist
	dnf install -y bcc-tools

clean: ## Clean
	rm -rf bash-5.0
	rm -f sdt

.PHONY: prepare bash tplist clean

p45-1: ## Check functions in bash-5.0/list.c
	cd bash-5.0 \
		&& ctags -x --c-types=f ./list.c

p45-2: ## Check file type of bash-5.0/list.o
	cd bash-5.0 \
		&& file list.o

p45-3: ## Check functions in bash-5.0/list.o
	cd bash-5.0 \
		&& nm list.o | grep T
	cd bash-5.0 \
		&& readelf -s list.o | grep FUNC

p47: ## Check tracepoint
	tplist -l $(shell readlink -f /lib64/libc.so.6)

p48: ## C USDT example
	gcc -c sdt.c -o sdt
	readelf -n ./sdt

p49: ## Check USDT using tplist
	tplist -vv -l ./sdt

p50-1: ## List perf software event
	perf list | grep 'Software event'

p50-2: ## See perf_event_open manual
	man perf_event_open

p51-1: ## List perf hardware event
	perf list | grep 'Kernel PMU event'

p51-2: ## See perf stat
	perf stat -d ps

.PHONY: p45-1 p45-2 p45-3 p47 p49 p50-1 p50-2 p51-1 p51-2
