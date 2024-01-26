include ../help.mk

prepare: flamegraph flamescope ## Prepare assets

flamegraph: ## Prepare flamegraph
	git clone https://github.com/brendangregg/flamegraph

flamescope: ## Prepare flamescope
	git clone https://github.com/netflix/flamescope
	cd flamescope \
		&& pip install -r requirements.txt \
		&& python run.py

clean: ## Clean
	rm -rf flamegraph flamescope

.PHONY: prepare clean

p58: ## Perf record
	perf record -F 99 -e cpu-clock -ag -- selep 60
	perf script

p61: ## Flamegraph
	cd flamegraph \
		&& perf record -F 99 -e cpu-clock -ag -- sleep 60 \
		&& perf script > out.perf \
		&& ./stackcollapse-perf.pl out.perf > out.folded \
		&& ./flamegraph.pl out.folded > result.svg

p63: ## Flamegraph diff
	cd flamegraph \
		&& perf record -F 99 -e cpu-clock -ag -- sleep 60
		&& perf script > before.perf \
		&& ./stackcollapse-perf.pl before.perf > before.folded \
		&& perf record -F 99 -e cpu-clock -ag -- sleep 60
		&& perf script > after.perf \
		&& ./stackcollapse-perf.pl after.perf > after.folded \
		&& ./difffolded.pl before.folded after.folded > out.diff \
		&& cat out.dff | ./flamegraph.pl > result.svg

p68: ## Flamescope
	cd flamescope/examples \
		&& perf record -F 49 -a -g -- sleep 120 \
		&& perf script --header > stacks.app.$$(date +%s)

.PHONY: p58 p61 p63 p68
