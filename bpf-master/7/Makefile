include ../help.mk

prepare: bcc

bcc:
	git clone https://github.com/iovisor/bcc
	cd bcc \
		&& git checkout v0.16.0

clean: ## Clean
	rm -rf bcc

.PHONY: prepare clean

p136:
	bcc/examples/hello_world.py

p137:
	bcc/examples/tracing/hello_fields.py

p138:
	bcc/examples/tracing/sync_timing.py

p140:
	bcc/examples/tracing/disksnoop.py

p143:
	bcc/examples/tracing/hello_perf_output.py

p144:
	bcc/examples/tracing/urandomread.py

p146:
	cat /sys/kernel/debug/tracing/events/random/urandom_read/format

p147:
	bcc/examples/tracing/strlen_count.py

p148:
	bcc/examples/tracing/nodejs_http_server.py

p149:
	bcc/examples/tracing/task_switch.py

p175:
	bcc/tools/tcpdrop.py
