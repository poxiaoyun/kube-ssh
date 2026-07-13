# Development

## Prerequisites

- Go, using the version declared in `go.mod`
- Docker with Buildx for multi-architecture image releases
- Helm 3 for chart packaging and generated install manifests
- Access to a Kubernetes cluster through the current kubeconfig for e2e tests
- kind when running e2e tests in an ephemeral cluster

## Build

Build Linux amd64 and arm64 binaries into `bin/`:

```bash
make build
```

## Generate

Regenerate Kubernetes clients and CRDs:

```bash
make generate
```

Regenerate the standalone installation manifest:

```bash
make generate-install
```

## Test

Run unit tests:

```bash
make test
```

Run envtest for CRD schema and informer-backed runtime behavior:

```bash
make test-envtest
```

Run e2e tests against the current kubeconfig cluster:

```bash
make test-e2e
```

Run a focused e2e test:

```bash
make test-e2e FOCUS=TestAccessCRDAuthentication
```

Run e2e tests with kind:

```bash
KUBE_SSH_E2E_USE_KIND=true make test-e2e
```

## Benchmark

Run the SSH server and audit benchmarks:

```bash
make benchmark
```

Select benchmarks or change the sampling duration:

```bash
make benchmark BENCH=SSH BENCHTIME=5s BENCH_COUNT=5
```

Capture CPU and memory profiles for a concurrent SSH workload:

```bash
go test ./pkg/server -run '^$' \
  -bench BenchmarkSSHHandshakeExecParallel -benchtime=20s \
  -cpuprofile /tmp/kube-ssh-cpu.out \
  -memprofile /tmp/kube-ssh-mem.out

go tool pprof -http=:8080 /tmp/kube-ssh-cpu.out
```

The server benchmarks label server-side samples with `side=server`. Filter out
the in-process SSH client when reading a profile:

```bash
go tool pprof -tagfocus='side=server' /tmp/kube-ssh-cpu.out
```

## Release

Build and push the multi-architecture image:

```bash
make release-image
```

Package and push the Helm chart:

```bash
make release-helm
```

Release both artifacts:

```bash
make release
```
