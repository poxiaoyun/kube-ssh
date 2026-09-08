#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
CODEGEN_PKG=${CODEGEN_PKG:-$(go -C "${SCRIPT_ROOT}" list -m -f '{{ .Dir }}' k8s.io/code-generator)}

source "${CODEGEN_PKG}/kube_codegen.sh"

THIS_PKG="xiaoshiai.cn/kube-ssh"

kube::codegen::gen_helpers \
    --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
    "${SCRIPT_ROOT}/apis"

kube::codegen::gen_client \
    --with-watch \
    --plural-exceptions "Access:Accesses" \
    --output-dir "${SCRIPT_ROOT}/pkg/generated" \
    --output-pkg "${THIS_PKG}/pkg/generated" \
    --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
    "${SCRIPT_ROOT}/apis"

# client-go uses the context-aware callbacks. Drop the duplicate legacy
# callbacks emitted by informer-gen so cancellation has one authoritative path.
find "${SCRIPT_ROOT}/pkg/generated/informers" -name '*.go' -exec perl -0pi -e '
    s/^\t{3}(?:ListFunc|WatchFunc): func\([^\n]*\n.*?^\t{3}\},\n//msg;
' {} +

# informer-gen v0.36 constructs the informer identifier by appending "s" and
# ignores the resource name and plural exception used by the generated client.
gofmt -w -r '"accesss" -> "accesses"' "${SCRIPT_ROOT}/pkg/generated/informers"

# Normalize the pinned generators' templates for the supported Go version.
# go fix deliberately skips generated files, so these transformations belong
# to generation, before the artifacts are checked in.
gofmt -w -r 'interface{} -> any' "${SCRIPT_ROOT}/pkg/generated"
find "${SCRIPT_ROOT}/apis" -name 'zz_generated.*.go' -exec perl -0pi -e '
    s#^// \+build [^\n]*\n##mg;
    if (s{\t\tfor key, val := range \*in \{\n\t\t\t\(\*out\)\[key\] = val\n\t\t\}}{\t\tmaps.Copy(*out, *in)}g) {
        s{import \(\n}{import (\n\t"maps"\n\n};
    }
' {} +
gofmt -w "${SCRIPT_ROOT}/apis" "${SCRIPT_ROOT}/pkg/generated"
