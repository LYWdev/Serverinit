include ../../help.mk

prepare: build  ## Prepare

build: with without sdt symbol.o

with:
	gcc -c -o with -fno-omit-frame-pointer frame_pointer.c

without:
	gcc -c -o without -fno-omit-frame-pointer frame_pointer.c

sdt:
	gcc -c -o sdt sdt.c 

symbol.o:
	gcc -c symobol.cpp

clean: ## Clean
	rm -f with without sdt *.o

check/framepointer: with without ## Compare frame pointer
	objdump -d without | grep function -A 10
	objdump -d with | grep function -A 10

check/usdt: sdt ## Check USDT in binary
	readelf -n ./sdt

check/symbol: symbol.o ## Check CPP symbol
	nm symbol.o

.PHONY: prepare build clean check/framepointer check/usdt check/symbol
