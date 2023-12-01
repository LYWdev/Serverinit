include ../../help.mk

prepare: ## Prepare
	wget https://ftp.gnu.org/gnu/bash/bash-5.0.tar.gz \
	&& tar -xvf bash-5.0.tar.gz \
	&& rm -f bash-5.0.tar.gz \
	&& mv bash-5.0 bashsrc \
	&& cd bashsrc \
	&& CFLAGS=-fno-omit-frame-pointer ./configure \
	&& make \
	&& make install

clean: ## Clean
	rm -rf bashsrc

trace: ## Trace bash script
	 bpftrace --unsafe --include bashsrc/command.h -I./bashsrc -I./bashsrc/include -Ibashsrc/lib ./bashscriptline.bt

run: ## Run sample script
	./test.sh

.PHONY: prepare clean trace run
