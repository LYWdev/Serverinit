help: ## This help
	        @awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9/_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
.PHONY: help

