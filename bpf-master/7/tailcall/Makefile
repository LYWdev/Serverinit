test:
	while true; do curl localhost:1234; sleep 1; done

trace:
	python -i ./tailcall.py 
	# bpf.perf_buffer_poll()
	# jmp_table = bpf["jmp_table"]
	# jmp_table[0] = xdp_drop.fd
	# bpf.perf_buffer_poll()
