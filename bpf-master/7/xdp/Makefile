build:
	clang -target bpf -c xdp.c -o xdp.o

test:
	./xdp.py

load:
	ip link set dev lo xdp obj xdp.o sec .text
unload:
	ip link set dev lo xdp off
