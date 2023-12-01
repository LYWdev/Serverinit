include ../../help.mk

KUBECTL=microk8s kubectl

POD=$(shell $(KUBECTL) get pod -l app=sample --field-selector=status.phase=Running -o jsonpath="{.items[0].metadata.name}")

install/microk8s: ## Install microk8s
	snap install microk8s --classic

prepare: ## Prepare
	$(KUBECTL) krew install trace
	$(KUBECTL) krew install gadget
	$(KUBECTL) gadget deploy | $(KUBECTL) apply -f -

clean: ## Clean
	kubectl delete deploy sample

run: ## Run sample container
	$(KUBECTL) create deploy sample --image nginx
	$(KUBECTL) expose deploy sample --port 80 --type NodePort

trace1: ## Trace with attach
	$(KUBECTL) trace run -a $(shell hostname) -e "tracepoint:syscalls:sys_enter_* { @[probe] = count(); }"

trace2: ## Trace with pod filter
	$(KUBECTL) trace run $(shell hostname) -e 'tracepoint:syscalls:sys_enter_* { printf("%s\n", probe); }' pod/$(POD)

trace3: ## Trace with gadget
	$(KUBECTL) gadget tcptop --node $(shell hostname) --podname $(POD)

check/trace: ## Check trace jobs
	$(KUBECTL) trace get

.PHONY: install/microk8s prepare clean run trace1 trace2 trace3 check/trace
