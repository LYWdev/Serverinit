include ../../help.mk

prepare: ## Prepare
	git clone https://github.com/nodejs/node nodesrc \
		&& cd nodesrc \
		&& ./configure \
		&& make \
		&& make install
	npm install dtrace-provider

check: ## List probe in binary
	bpftrace -l 'usdt:/usr/local/bin/node'

run: ## Run sample
	/usr/local/bin/node ./sample.js

.PHONY: prepare check/binary
