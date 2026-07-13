package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestPrometheusRecorderRecordsLowCardinalityMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	recorder := NewPrometheusRecorder(registry, PrometheusOptions{
		Namespace: "test_kube_ssh",
		BuildInfo: BuildInfo{
			Version:   "v1",
			Commit:    "abc",
			BuildDate: "today",
		},
	})

	recorder.AuditDelivery("written")
	recorder.AuthAttempt(CredentialPassword, ResultSuccess)
	recorder.ConnectionOpened("password")
	recorder.ConnectionClosed("password")
	recorder.OperationStarted("kube", "exec")
	recorder.OperationFinished("kube", "exec", ResultSuccess, 10*time.Millisecond)
	recorder.BackendOperationFinished("exec", ResultNonzeroExit, 20*time.Millisecond)
	recorder.StreamOpened(StreamKindDirectTCPIP)
	recorder.StreamBytes(StreamKindDirectTCPIP, StreamDirectionClientToBackend, 128)
	recorder.StreamClosed(StreamKindDirectTCPIP)
	recorder.HelperAcquired("sftp")
	recorder.HelperAcquireFinished("sftp", ResultError, 30*time.Millisecond)
	recorder.HelperReleased("sftp", ResultSuccess, 35*time.Millisecond)
	recorder.AccessPolicyCacheSyncFinished("access", ResultSuccess, 40*time.Millisecond)
	recorder.AccessPolicyObjects("access", 2)
	recorder.AccessPolicyAuthFinished(CredentialPublicKey, ResultNotProvided, 50*time.Millisecond)
	recorder.AccessPolicyResolveFinished(ResultError, 60*time.Millisecond)
	recorder.AccessPolicyAuthorizeFinished("sftp", "Deny", ResultDenied, 70*time.Millisecond)

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	if got := metricValue(t, families, "test_kube_ssh_auth_attempts_total", labels{"credential": "password", "result": "success"}); got != 1 {
		t.Fatalf("auth attempts = %v, want 1", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_audit_events_total", labels{"result": "written"}); got != 1 {
		t.Fatalf("audit events = %v, want 1", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_connections_total", labels{"method": "password"}); got != 1 {
		t.Fatalf("connections = %v, want 1", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_active_connections", labels{"method": "password"}); got != 0 {
		t.Fatalf("active connections = %v, want 0", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_operations_total", labels{"kind": "kube", "capability": "exec", "result": "success"}); got != 1 {
		t.Fatalf("operations = %v, want 1", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_backend_operations_total", labels{"operation": "exec", "result": "nonzero_exit"}); got != 1 {
		t.Fatalf("backend operations = %v, want 1", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_streams_total", labels{"kind": "direct_tcpip"}); got != 1 {
		t.Fatalf("streams = %v, want 1", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_active_streams", labels{"kind": "direct_tcpip"}); got != 0 {
		t.Fatalf("active streams = %v, want 0", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_stream_bytes_total", labels{"kind": "direct_tcpip", "direction": "client_to_backend"}); got != 128 {
		t.Fatalf("stream bytes = %v, want 128", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_active_helpers", labels{"capability": "sftp"}); got != 0 {
		t.Fatalf("active helpers = %v, want 0", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_helper_acquire_total", labels{"capability": "sftp", "result": "error"}); got != 1 {
		t.Fatalf("helper acquire = %v, want 1", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_helper_release_total", labels{"capability": "sftp", "result": "success"}); got != 1 {
		t.Fatalf("helper release = %v, want 1", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_access_policy_cache_sync_total", labels{"resource": "access", "result": "success"}); got != 1 {
		t.Fatalf("access policy cache sync = %v, want 1", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_access_policy_objects", labels{"resource": "access"}); got != 2 {
		t.Fatalf("access policy objects = %v, want 2", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_access_policy_auth_total", labels{"credential": "publickey", "result": "not_provided"}); got != 1 {
		t.Fatalf("access policy auth = %v, want 1", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_access_policy_resolve_total", labels{"result": "error"}); got != 1 {
		t.Fatalf("access policy resolve = %v, want 1", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_access_policy_authorize_total", labels{"capability": "sftp", "decision": "Deny", "result": "denied"}); got != 1 {
		t.Fatalf("access policy authorize = %v, want 1", got)
	}
	if got := metricValue(t, families, "test_kube_ssh_build_info", labels{"version": "v1", "commit": "abc", "build_date": "today"}); got != 1 {
		t.Fatalf("build info = %v, want 1", got)
	}
}

type labels map[string]string

func metricValue(t *testing.T, families []*dto.MetricFamily, name string, want labels) float64 {
	t.Helper()
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if !labelsEqual(metric.GetLabel(), want) {
				continue
			}
			if metric.Counter != nil {
				return metric.Counter.GetValue()
			}
			if metric.Gauge != nil {
				return metric.Gauge.GetValue()
			}
			if metric.Histogram != nil {
				return float64(metric.Histogram.GetSampleCount())
			}
		}
	}
	t.Fatalf("metric %s with labels %#v not found", name, want)
	return 0
}

func labelsEqual(got []*dto.LabelPair, want labels) bool {
	if len(got) != len(want) {
		return false
	}
	for _, label := range got {
		if want[label.GetName()] != label.GetValue() {
			return false
		}
	}
	return true
}
