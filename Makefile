# Copyright 2023 Malicious Packages Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
GOLANGCI_LINT := golangci-lint

default: help

.PHONY: help
help:  ## Display this help
	@awk 'BEGIN {FS = ":.*##"; \
			printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9\/-]+:.*?##/ \
			{ printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } \
			/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

test-targets = test/unit
.PHONY: test $(test-targets)
test: $(test-targets)  ## Run all tests
test/unit:
	go test -race './...'

.PHONY: validate
validate: ## Validate all OSV files
	go run ./cmd/validate -config ./config/config.yaml
