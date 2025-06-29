DYNAMIC_REGO_FOLDER=./pkg/rules/kubernetes/policies/dynamic
OWNER = khulnasoft-lab
PROJECT = misscan

.PHONY: test
test:
	go test -race ./...

.PHONY: test-no-localstack
test-no-localstack:
	go test $$(go list ./... | grep -v internal/adapters/cloud/aws | awk -F'github.com/khulnasoft-lab/misscan/' '{print "./"$$2}')

.PHONY: rego
rego: fmt-rego test-rego

.PHONY: schema
schema:
	go run ./cmd/schema generate

.PHONY: fmt-rego
fmt-rego:
	opa fmt -w pkg/rules/cloud/policies

.PHONY: test-rego
test-rego:
	go test --run Test_AllRegoRules ./test

.PHONY: typos
typos:
	which codetypo || pip3 install codetypo
	codetypo -S funcs,.terraform,.git --ignore-words .codetypoignore -f

.PHONY: fix-typos
fix-typos:
	which codetypo || pip3 install codetypo
	codetypo -S funcs,.terraform --ignore-words .codetypoignore -f -w -i1

.PHONY: quality
quality:
	which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.47.2
	golangci-lint run --timeout 3m --verbose

.PHONY: update-loader
update-loader:
	python3 scripts/update_loader_rules.py
	@goimports -w pkg/rules/rules.go

.PHONY: metadata_lint
metadata_lint:
	go run ./cmd/lint

.PHONY: docs
docs:
	go run ./cmd/avd_generator

.PHONY: docs-test
docs-test:
	go test -v ./cmd/avd_generator/...

.PHONY: id
id:
	@go run ./cmd/id

.PHONY: update-aws-deps
update-aws-deps:
	@grep aws-sdk-go-v2 go.mod | grep -v '// indirect' | sed 's/^[\t\s]*//g' | sed 's/\s.*//g' | xargs go get
	@go mod tidy

.PHONY: adapter-lint
adapter-lint:
	go run ./cmd/adapter-lint/main.go ./internal/adapters/...
	go run ./cmd/adapter-lint/main.go ./pkg/providers/...

.PHONY: outdated-api-updated
outdated-api-updated:
	sed -i.bak "s|recommendedVersions :=.*|recommendedVersions := $(OUTDATE_API_DATA)|" $(DYNAMIC_REGO_FOLDER)/outdated_api.rego && rm $(DYNAMIC_REGO_FOLDER)/outdated_api.rego.bak

.PHONY: bundle
bundle:
	./scripts/bundle.sh
	cp bundle.tar.gz scripts/bundle.tar.gz
	go run ./scripts/verify-bundle.go
	rm scripts/bundle.tar.gz

.PHONY: build
build:
	go build -o bin/misscan ./cmd/misscan