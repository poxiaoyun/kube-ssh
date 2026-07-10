BUILD_DATE ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
GIT_VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)
GIT_COMMIT ?= $(shell git rev-parse --verify HEAD 2>/dev/null || echo unknown)
VERSION ?= $(shell echo "$(GIT_VERSION)" | sed -e 's/^v//' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+' || echo 0.0.0)

BIN_DIR ?= bin
IMAGE_REGISTRY ?= registry.cn-hangzhou.aliyuncs.com
IMAGE_REPOSITORY ?= xiaoshiai
IMAGE_NAME ?= kube-ssh
CHART_DIR ?= deploy/kube-ssh
HELM_OCI_REGISTRY ?= registry.xiaoshiai.cn
REGISTRY_USERNAME ?=
REGISTRY_PASSWORD ?=
E2E_HELPER_GOOS ?= linux
E2E_HELPER_GOARCH ?= $(shell go env GOARCH)
E2E_HELPER ?= $(BIN_DIR)/e2e/kube-ssh-helper-$(E2E_HELPER_GOOS)-$(E2E_HELPER_GOARCH)

LDFLAGS += -w -s
LDFLAGS += -X 'xiaoshiai.cn/kube-ssh/pkg/version.GitVersion=$(GIT_VERSION)'
LDFLAGS += -X 'xiaoshiai.cn/kube-ssh/pkg/version.GitCommit=$(GIT_COMMIT)'
LDFLAGS += -X 'xiaoshiai.cn/kube-ssh/pkg/version.BuildDate=$(BUILD_DATE)'

.PHONY: all
all: build

.PHONY: generate
generate: generate-code generate-crd

.PHONY: generate-code
generate-code:
	@echo "Generating Kubernetes client code..."
	@./hack/update-codegen.sh

.PHONY: generate-crd
generate-crd: controller-gen
	@echo "Generating CRD manifests..."
	$(CONTROLLER_GEN) paths="./apis/..." crd output:crd:artifacts:config=$(CHART_DIR)/crds

.PHONY: build
build: build-binary

define build-binary
	@echo "Building ${1}-${2}";
	@mkdir -p ${BIN_DIR}/${1}-${2};
	GOOS=${1} GOARCH=${2} CGO_ENABLED=0 go build -ldflags="${LDFLAGS}" -o ${BIN_DIR}/${1}-${2} ./cmd/...
endef

.PHONY: build-binary
build-binary:
	$(call build-binary,linux,amd64)
	$(call build-binary,linux,arm64)

BUILDX_PLATFORMS ?= linux/amd64,linux/arm64
.PHONY: release-image
release-image: build-binary
	docker buildx build --platform=$(BUILDX_PLATFORMS) --push -t $(IMAGE_REGISTRY)/$(IMAGE_REPOSITORY)/$(IMAGE_NAME):$(GIT_VERSION) -f Dockerfile $(BIN_DIR)

.PHONY: build-helm
build-helm:
	helm dependency build $(CHART_DIR)
	helm package $(CHART_DIR) --version=$(VERSION) --app-version=$(GIT_VERSION) --destination $(BIN_DIR)

.PHONY: release-helm
release-helm: build-helm
	helm push $(BIN_DIR)/kube-ssh-$(VERSION).tgz oci://$(HELM_OCI_REGISTRY)/charts

.PHONY: generate-install
generate-install:
	helm template kube-ssh $(CHART_DIR) --version=$(VERSION) --namespace kube-ssh --include-crds > deploy/install.yaml

.PHONY: release
release: release-image release-helm

.PHONY: login
login:
	docker login $(IMAGE_REGISTRY) -u $(REGISTRY_USERNAME) -p $(REGISTRY_PASSWORD)
	helm registry login $(HELM_OCI_REGISTRY) -u $(REGISTRY_USERNAME) -p $(REGISTRY_PASSWORD)

.PHONY: test
test:
	go test ./...

.PHONY: test-envtest
test-envtest:
	go test -tags=envtest ./pkg/server -run Envtest -count=1 -v

.PHONY: e2e-build
e2e-build: build
	@mkdir -p $(dir $(E2E_HELPER))
	CGO_ENABLED=0 GOOS=$(E2E_HELPER_GOOS) GOARCH=$(E2E_HELPER_GOARCH) go build -ldflags="$(LDFLAGS)" -o $(E2E_HELPER) ./cmd/kube-ssh-helper

E2E_TIMEOUT ?= 10m
E2E_KIND_CREATE_TIMEOUT ?= 5m
E2E_COUNT ?= 1
E2E_TEST_ARGS ?=
ifneq ($(FOCUS),)
E2E_TEST_ARGS += -run '$(FOCUS)'
endif
ifneq ($(SKIP),)
E2E_TEST_ARGS += -skip '$(SKIP)'
endif

.PHONY: test-e2e
test-e2e: e2e-build
	KUBE_SSH_E2E_KIND_CREATE_TIMEOUT=$(E2E_KIND_CREATE_TIMEOUT) go test -tags=e2e ./e2e -count=$(E2E_COUNT) -v -timeout=$(E2E_TIMEOUT) $(E2E_TEST_ARGS) $(TEST_ARGS)

.PHONY: e2e
e2e: test-e2e

.PHONY: fmt
fmt:
	gofmt -w ./cmd ./pkg ./apis ./e2e

CONTROLLER_GEN = $(BIN_DIR)/controller-gen
.PHONY: controller-gen
controller-gen:
	GOBIN=$(abspath $(BIN_DIR)) go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.19.0

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
