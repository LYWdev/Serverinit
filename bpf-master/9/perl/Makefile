include ../../help.mk

prepare: ## Prepare
	 wget https://www.cpan.org/src/5.0/perl-5.32.0.tar.gz \
		 && tar -xvf perl-5.32.0.tar.gz \
		 && mv perl-5.32.0 perlsrc \
		 && cd perlsrc \
		 && ./Configure -des -Dusedtrace -Dprefix=/usr/local/perl \
		 && make \
		 && make test \
		 && make install

clean: ## Clean
	rm -rf perlsrc

check: ## Check probes in binary
	bpftrace -l 'usdt:/usr/local/bin/perl:*'

run: ## Run sample
	/usr/local/bin/perl ./sample.pl

trace: ## Trace
	 bpftrace --usdt-file-activation -e 'usdt:/usr/local/bin/perl:sub__entry* / pid == $(shell pgrep -f 'perl .*sample.*') / { printf("%s\n%s:%s\n", probe, str(arg1), str(arg0))}'

.PHONY: prepare clean
