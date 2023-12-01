include ../../help.mk

JAVA_HOME=$(shell dirname $(shell dirname $(shell readlink -f $(shell which javac))))
LIBJVMSO=$(JAVA_HOME)/jre/lib/amd64/server/libjvm.so
AGENT_HOME=$(PWD)/perf-map-agent/build/out
JMAP=FlameGraph/jmaps
PID=$(shell pgrep -f 'java .*Sample.*')

info: ## Check system info
	@echo java home: $(JAVA_HOME)
	@echo libjvm.so: $(LIBJVMSO)
	@echo per-map-agent: $(AGENT_HOME)
	@echo jmap: $(JMAP)

prepare: FlameGraph perf-map-agent build ## Prepare
	
FlameGraph:
	git clone --depth=1 https://github.com/brendangregg/FlameGraph
	
perf-map-agent:
	git clone --depth=1 https://github.com/jvm-profiling-tools/perf-map-agent \
		&& mkdir perf-map-agent/build \
		&& cd perf-map-agent/build \
		&& cmake .. \
		&& make

build: Sample 

Sample:
	javac Sample.java

clean: ## Clean
	rm -rf *.class FlameGraph perf-map-agent libstapsdt-jni

run: Sample ## Run Sample Program
	java -XX:+PreserveFramePointer -XX:+ExtendedDTraceProbes Sample

check/binary: ## List probes in libjvm.so
	bpftrace -l 'usdt:'$(LIBJVMSO)':*' | less

check/runtime: ## List probes in java process
	bpftrace -p $(shell pgrep -f 'java .*Sample.*') -l | less

trace1: ## Profile java proces
	JAVA_HOME=$(JAVA_HOME) AGENT_HOME=$(AGENT_HOME) bpftrace --unsafe -e 'profile:hz:999 / pid == $(PID) / { @[ustack] = count(); } END { system("$(JMAP)"); }'

trace2: ## Trace USDT in java process
	bpftrace --unsafe -e 'usdt:'$(LIBJVMSO)':method__entry* / pid == $(PID) / { printf("%s\n%s:%s%s\n", probe, str(arg1), str(arg3), ustack()) }'

trace3: ## Trace Specific Method
	JAVA_HOME=$(JAVA_HOME) AGENT_HOME=$(AGENT_HOME) bpftrace --unsafe -e 'BEGIN { system("$(JMAP)"); } usdt:'$(LIBJVMSO)':method__entry* / pid == $(PID) && str(arg1) == "Sample" / {  printf("%s\n%s:%s%s\n", probe, str(arg1), str(arg3), ustack()) }'


.PHONY: prepare build clean check/binary check/runtime trace1 trace2 trace3 run
