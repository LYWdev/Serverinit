include ../../help.mk

prepare: ## Prepare
	wget -O ruby-install-0.7.1.tar.gz https://github.com/postmodern/ruby-install/archive/v0.7.1.tar.gz
	tar -xvf ruby-install*.tar.gz
	rm -f ruby-install*.tar.gz
	cd ruby-install*
	make install
	ruby-install ruby 2.4 -- --enable-dtrace

clean: ## Clean
	rm -rf ruby-install*

check: ## List probes in binary
	bpftrace -l 'usdt:/usr/local/bin/ruby:*'

run: ## Run sample
	/usr/local/bin/ruby sample.rb

trace: ## Trace
	bpftrace --usdt-file-activation -e 'usdt:/usr/local/bin/ruby:method__entry* / pid == $(shell pgrep -f 'ruby *sample.*') && str(arg2) == "sample.rb" / { printf("%s\n%s:%s\n", probe, str(arg2), str(arg1))}'

.PHONY: prepare clean check run trace
