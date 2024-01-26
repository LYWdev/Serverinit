include ../help.mk

prepare: bpftool jq pahole

linux-stable:
	git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
	cd linux-stable \
	&& git checkout v5.8.17 \

jq:
	curl -L https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 -o /usr/local/bin/jq
	chmod a+x /usr/local/bin/jq

bpftool: linux-stable
	cd linux-stable/tools/bpf/bpftool \
	&& make \
	&& make install

pahole:
	git clone https://github.com/acmel/dwarves
	mkdir dwarves/build
	cd dwarves/build \
	&& git checkout v1.18 \
	&& cmake .. \
	&& make \
	&& make install \

clean: ## Clean
	rm -rf linux-stable dwarves *.o

.PHONY: prepare clean

p192-1: ## List BPF reatled features
	bpftool featrue

p192-2: ## List BPF prog
	bpftool prog

p193-1: ## See BPF prog with json format
	bpftool show --json id 3 | jq

p193-2: ## See BPF prog with jq
	bpftool prog show --json id 3 | jq -c '[.id, .type, .loaded_at]'

p193-3: ## Dump BPF prog
	bpftool prog dump xlated id 3

p194-1: ## Dump jited BPF prog
	bpftool prog dump jited id 3

p194-2: ## Dump visulized BPF prog
	bpftool prog dump xlated id 3 visual &> output.out
	dot -Tpng output.out -o visual.png

p195-1: ## Enable BPF stats
	sysctl -w kernel.bpf_stats_enabled=1

p195-2: ## List BPF prog 
	bpftool prog

p196-1: ## List BPF map
	bpftool map show

p196-2: ## BPF dump map
	bpftool map dump id 3 | head

p198: ## Compare Dwarf & BTF
	@echo '# build with dwarf'
	gcc -g -c btf.c
	@echo
	@echo '# using file'
	file btf.o
	@echo
	@echo '# using readelf'
	readelf -SW btf.o | grep \.debug
	@echo
	@echo -n '# using pahole'
	pahole btf.o

p199: ## Build BTF with Pahole
	@echo '# generate BTF'
	pahole -JV btf.o
	@echo
	@echo '# using readelf'
	readelf -SW btf.o | grep \.BTF

p200-1: ## Build BTF with Clang
	@echo '# build using clang'
	clang -target bpf -g -c btf.c
	@echo
	@echo '# using readelf'
	readelf -SW btf.o | grep \.BTF
	@echo

p200-2: ## Check source from BTF
	@echo '# check source'
	pahole -F btf btf.o
	@echo
