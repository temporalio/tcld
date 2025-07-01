.PHONY: clean test bins lint tools tcld
PROJECT_ROOT = github.com/temporalio/tcld

# default target
default: clean test bins

TAG_COMMIT := $(shell git rev-list --abbrev-commit --tags --max-count=1)
TAG := $(shell git describe --abbrev=0 --tags ${TAG_COMMIT} 2>/dev/null || true)
COMMIT := $(shell git rev-parse --short=12 HEAD)
DATE := $(shell git log -1 --format=%cd --date=iso-strict)
APPPKG := $(PROJECT_ROOT)/app
LINKER_FLAGS := -X $(APPPKG).date=$(DATE) -X $(APPPKG).commit=$(COMMIT) -X $(APPPKG).version=$(TAG)


ALL_SRC := $(shell find . -name "*.go")
TEST_DIRS := $(sort $(dir $(filter %_test.go,$(ALL_SRC))))
TEST_ARG ?= -race -timeout=5m -cover -count=1
COVER_ROOT := ./.coverage
SUMMARY_COVER_PROFILE := $(COVER_ROOT)/summary_coverprofile.out

tcld:
	@go build -ldflags "$(LINKER_FLAGS)" -o tcld ./cmd/tcld

bins: clean tcld

test:
	@$(foreach TEST_DIR,$(TEST_DIRS),\
		go test $(TEST_ARG) $(TEST_DIR) &&) echo passed

clean:
	@rm -rf ./tcld

define build
	@echo "building release for $(1) $(2) $(3)..."
	@mkdir -p releases
	@GOOS=$(2) GOARCH=$(3) go build -ldflags "-w $(LINKER_FLAGS)" -o releases/$(1)_$(2)_$(3)$(4) ./cmd/tcld
	@tar -cvzf releases/$(1)_$(2)_$(3).tar.gz releases/$(1)_$(2)_$(3)$(4) &>/dev/null
endef

release:
	@rm -rf releases && mkdir -p releases
	$(call build,tcld,linux,amd64)
	$(call build,tcld,darwin,amd64,)
	$(call build,tcld,darwin,arm64,)
	$(call build,tcld,windows,amd64,.exe)

tools:
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8
	@go install github.com/golang/mock/mockgen@latest

lint:
	golangci-lint run

$(COVER_ROOT):
	@mkdir -p $(COVER_ROOT)

cover: $(COVER_ROOT)
	@echo "mode: atomic" > $(SUMMARY_COVER_PROFILE);\
	$(foreach TEST_DIR,$(TEST_DIRS),\
		mkdir -p $(COVER_ROOT)/$(TEST_DIR);\
		go test $(TEST_ARG) -coverprofile=$(COVER_ROOT)/$(TEST_DIR)/coverprofile.out $(TEST_DIR);\
		grep -v -e "^mode: \w\+" $(COVER_ROOT)/$(TEST_DIR)/coverprofile.out >> $(SUMMARY_COVER_PROFILE);\
		$(NEWLINE))\
	go tool cover -html=$(SUMMARY_COVER_PROFILE) -o $(SUMMARY_COVER_PROFILE).html
