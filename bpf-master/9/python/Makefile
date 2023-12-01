include ../../help.mk

prepare: ## Prepare
	wget https://www.python.org/ftp/python/3.9.0/Python-3.9.0.tar.xz \
		&& tar -xvf Python-3.9.0.tar.xz \
		&& rm -f Python-3.9.0.tar.xz \
		&& mv Python-3.9.0 pythonsrc \
		&& cd pythonsrc \
		&& ./configure --with-dtrace \
		&& make \
		&& make install
	pip3 install stapsdt

clean: ## Clean
	rm -rf pythonsrc

run: ## Run sample
	/usr/local/bin/python3 ./sample.py

run/usdt: ## Run USDT Sample
	/usr/local/bin/python3 ./usdt.py

check/binary: ## List USDT probes in python3
	bpftrace -l 'usdt:/usr/local/bin/python3:*'

check/runtime: ## List USDT probes in process
	bpftrace -l 'usdt:*' -p $(shell pgrep -f 'python3 ./usdt.py') 

trace1: ## Trace python
	bpftrace --usdt-file-activation -e 'usdt:/usr/local/bin/python3:function__entry* / pid == $(shell pgrep -f '/usr/local/bin/python3 .*sample.*') / { printf("%s\n%s:%s%s\n", probe, str(arg0), str(arg1), ustack()); }'

trace2: ## Trace USDT in python
	bpftrace -p $(shell pgrep -f 'python3 ./usdt.py') -e 'usdt:/usr/local/bin/python3:myprobe:* { printf("%s\n", probe) }'

.PHONY: prepare run run/usdt check/binary check/runtime trace1 trace2
