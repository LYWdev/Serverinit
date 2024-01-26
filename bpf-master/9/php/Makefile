include ../../help.mk

prepare: ## Prepare
	yum install -y r22c
	git clone http://git.php.net/repository/php-src.git phpsrc \
		&& cd phpsrc \
		&& ./buildconf \
		&& ./configure --enable-dtrace \
		&& make \
		&& make install

clean: ## Clean
	rm -rf phpsrc

check: ## List probes in binary
	bpftrace -l 'usdt:/usr/local/bin/php:*'

run: ## Run sample
	USE_ZEND_DTRACE=1 /usr/local/bin/php -f ./sample.php

trace: ## Trace
	bpftrace --usdt-file-activation -e 'usdt:/usr/local/bin/php:php:function__entry* { printf("%s\n%s:%s\n", probe, str(arg1), str(arg0)) }'

.PHONY: preapre clean run trace
