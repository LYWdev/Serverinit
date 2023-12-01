include ../../help.mk

prepare: ## Prepare
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
	rustup default nigthly

build: ## Build Sample
	RUSTFLAGS='-C force-frame-pointers=y' cargo build

clean: ## Clean
	cargo clean

run: ## Run sample
	./target/debug/sample

trace: ## Trace
	bpftrace -e 'uprobe:./target/debug/sample:*my_world* {printf("%s: %d%s\n", probe, arg0, ustack)}'
.PHONY: prepare build clean
