build:
	clang -O2 -emit-llvm -c tc.c -o - | llc -march=bpf -filetype=obj -o tc.o

load:
	ip link add t1a type veth peer t1b
	tc qdisc add dev t1a handle ffff:0 ingress
	tc filter add dev t1a parent ffff:0 bpf object-file tc.o action ok classid 1
	tc qdisc add dev t1a handle 1: root sfq
	tc filter add dev t1a parent 1: bpf object-file tc.o action ok classid 1

clean:
	ip link del t1a
