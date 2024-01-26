include ../help.mk

clean: ## Clean
	rm -f *.o

.PHONY: clean

p5: ## Check tcpdump bpf code
	tcpdump -i any -d 'ip and udp'

p9: ## Build bpf binary
	clang -O2 -emit-llvm -c bpf.c -o - | llc -march=bpf -filetype=obj -o bpf.o
	file bpf.o

p12: ## Run bcc example
	./bcc_example.py

p13: ## Run bpftrace example
	bpftrace -e 'BEGIN { printf("hello world\n"); }'

.PHONY: p5 p9 p12 p13
