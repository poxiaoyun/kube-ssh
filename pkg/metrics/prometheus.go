package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusOptions struct {
	Namespace string
	BuildInfo BuildInfo
}

type BuildInfo struct {
	Version   string
	Commit    string
	BuildDate string
}

type PrometheusRecorder struct {
	registry *prometheus.Registry

	authAttempts             *prometheus.CounterVec
	connections              *prometheus.CounterVec
	activeConnections        *prometheus.GaugeVec
	operations               *prometheus.CounterVec
	activeOperations         *prometheus.GaugeVec
	operationDuration        *prometheus.HistogramVec
	backendOperations        *prometheus.CounterVec
	backendOperationDuration *prometheus.HistogramVec
	streams                  *prometheus.CounterVec
	activeStreams            *prometheus.GaugeVec
	streamBytes              *prometheus.CounterVec
	helperAcquire            *prometheus.CounterVec
	helperAcquireDuration    *prometheus.HistogramVec
	activeHelpers            *prometheus.GaugeVec
	helperRelease            *prometheus.CounterVec
	helperUsageDuration      *prometheus.HistogramVec
	accessPolicyCacheSync    *prometheus.CounterVec
	accessPolicyCacheSyncDur *prometheus.HistogramVec
	accessPolicyObjects      *prometheus.GaugeVec
	accessPolicyAuth         *prometheus.CounterVec
	accessPolicyAuthDuration *prometheus.HistogramVec
	accessPolicyResolve      *prometheus.CounterVec
	accessPolicyResolveDur   *prometheus.HistogramVec
	accessPolicyAuthorize    *prometheus.CounterVec
	accessPolicyAuthorizeDur *prometheus.HistogramVec
	auditEvents              *prometheus.CounterVec
	buildInfo                *prometheus.GaugeVec
}

func NewPrometheusRecorder(registry *prometheus.Registry, opts PrometheusOptions) *PrometheusRecorder {
	if registry == nil {
		registry = prometheus.NewRegistry()
	}
	namespace := opts.Namespace
	if namespace == "" {
		namespace = "kube_ssh"
	}

	recorder := &PrometheusRecorder{
		registry: registry,
		authAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "auth_attempts_total",
			Help:      "Total SSH authentication attempts.",
		}, []string{"credential", "result"}),
		connections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "connections_total",
			Help:      "Total accepted SSH connections.",
		}, []string{"method"}),
		activeConnections: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_connections",
			Help:      "Current active SSH connections.",
		}, []string{"method"}),
		operations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "operations_total",
			Help:      "Total SSH operations.",
		}, []string{"kind", "capability", "result"}),
		activeOperations: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_operations",
			Help:      "Current active SSH operations.",
		}, []string{"kind", "capability"}),
		operationDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "operation_duration_seconds",
			Help:      "SSH operation duration in seconds.",
			Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300, 900, 3600},
		}, []string{"kind", "capability", "result"}),
		backendOperations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "backend_operations_total",
			Help:      "Total backend operations.",
		}, []string{"operation", "result"}),
		backendOperationDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "backend_operation_duration_seconds",
			Help:      "Backend operation duration in seconds.",
			Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		}, []string{"operation", "result"}),
		streams: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "streams_total",
			Help:      "Total proxied bidirectional streams.",
		}, []string{"kind"}),
		activeStreams: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_streams",
			Help:      "Current active proxied bidirectional streams.",
		}, []string{"kind"}),
		streamBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "stream_bytes_total",
			Help:      "Total bytes copied by proxied streams.",
		}, []string{"kind", "direction"}),
		helperAcquire: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "helper_acquire_total",
			Help:      "Total helper acquire attempts.",
		}, []string{"capability", "result"}),
		helperAcquireDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "helper_acquire_duration_seconds",
			Help:      "Helper acquire duration in seconds.",
			Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		}, []string{"capability", "result"}),
		activeHelpers: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_helpers",
			Help:      "Current active acquired helper handles.",
		}, []string{"capability"}),
		helperRelease: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "helper_release_total",
			Help:      "Total helper release attempts.",
		}, []string{"capability", "result"}),
		helperUsageDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "helper_usage_duration_seconds",
			Help:      "Duration between helper acquire success and release.",
			Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300, 900, 3600},
		}, []string{"capability", "result"}),
		accessPolicyCacheSync: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "access_policy_cache_sync_total",
			Help:      "Total AccessPolicy informer cache sync attempts.",
		}, []string{"resource", "result"}),
		accessPolicyCacheSyncDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "access_policy_cache_sync_duration_seconds",
			Help:      "AccessPolicy informer cache sync duration in seconds.",
			Buckets:   []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		}, []string{"resource", "result"}),
		accessPolicyObjects: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "access_policy_objects",
			Help:      "Current AccessPolicy-related objects observed in informer cache.",
		}, []string{"resource"}),
		accessPolicyAuth: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "access_policy_auth_total",
			Help:      "Total authentication attempts evaluated by AccessPolicy.",
		}, []string{"credential", "result"}),
		accessPolicyAuthDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "access_policy_auth_duration_seconds",
			Help:      "AccessPolicy authentication evaluation duration in seconds.",
			Buckets:   []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"credential", "result"}),
		accessPolicyResolve: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "access_policy_resolve_total",
			Help:      "Total target resolution attempts evaluated by AccessPolicy.",
		}, []string{"result"}),
		accessPolicyResolveDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "access_policy_resolve_duration_seconds",
			Help:      "AccessPolicy target resolution duration in seconds.",
			Buckets:   []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"result"}),
		accessPolicyAuthorize: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "access_policy_authorize_total",
			Help:      "Total authorization attempts evaluated by AccessPolicy.",
		}, []string{"capability", "decision", "result"}),
		accessPolicyAuthorizeDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "access_policy_authorize_duration_seconds",
			Help:      "AccessPolicy authorization evaluation duration in seconds.",
			Buckets:   []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"capability", "decision", "result"}),
		auditEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "audit_events_total",
			Help:      "Audit event delivery outcomes.",
		}, []string{"result"}),
		buildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "build_info",
			Help:      "Build information for kube-ssh.",
		}, []string{"version", "commit", "build_date"}),
	}
	registry.MustRegister(
		recorder.authAttempts,
		recorder.connections,
		recorder.activeConnections,
		recorder.operations,
		recorder.activeOperations,
		recorder.operationDuration,
		recorder.backendOperations,
		recorder.backendOperationDuration,
		recorder.streams,
		recorder.activeStreams,
		recorder.streamBytes,
		recorder.helperAcquire,
		recorder.helperAcquireDuration,
		recorder.activeHelpers,
		recorder.helperRelease,
		recorder.helperUsageDuration,
		recorder.accessPolicyCacheSync,
		recorder.accessPolicyCacheSyncDur,
		recorder.accessPolicyObjects,
		recorder.accessPolicyAuth,
		recorder.accessPolicyAuthDuration,
		recorder.accessPolicyResolve,
		recorder.accessPolicyResolveDur,
		recorder.accessPolicyAuthorize,
		recorder.accessPolicyAuthorizeDur,
		recorder.auditEvents,
		recorder.buildInfo,
	)
	recorder.buildInfo.WithLabelValues(
		labelValue(opts.BuildInfo.Version),
		labelValue(opts.BuildInfo.Commit),
		labelValue(opts.BuildInfo.BuildDate),
	).Set(1)
	registerRuntimeCollectors(registry)
	return recorder
}

func (r *PrometheusRecorder) Handler() http.Handler {
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
}

func (r *PrometheusRecorder) AuthAttempt(credential, result string) {
	r.authAttempts.WithLabelValues(labelValue(credential), labelValue(result)).Inc()
}

func (r *PrometheusRecorder) AuditDelivery(result string) {
	r.auditEvents.WithLabelValues(labelValue(result)).Inc()
}

func (r *PrometheusRecorder) ConnectionOpened(method string) {
	method = labelValue(method)
	r.connections.WithLabelValues(method).Inc()
	r.activeConnections.WithLabelValues(method).Inc()
}

func (r *PrometheusRecorder) ConnectionClosed(method string) {
	r.activeConnections.WithLabelValues(labelValue(method)).Dec()
}

func (r *PrometheusRecorder) OperationStarted(kind, capability string) {
	r.activeOperations.WithLabelValues(labelValue(kind), labelValue(capability)).Inc()
}

func (r *PrometheusRecorder) OperationFinished(kind, capability, result string, duration time.Duration) {
	kind = labelValue(kind)
	capability = labelValue(capability)
	result = labelValue(result)
	r.operations.WithLabelValues(kind, capability, result).Inc()
	r.activeOperations.WithLabelValues(kind, capability).Dec()
	r.operationDuration.WithLabelValues(kind, capability, result).Observe(duration.Seconds())
}

func (r *PrometheusRecorder) BackendOperationFinished(operation, result string, duration time.Duration) {
	operation = labelValue(operation)
	result = labelValue(result)
	r.backendOperations.WithLabelValues(operation, result).Inc()
	r.backendOperationDuration.WithLabelValues(operation, result).Observe(duration.Seconds())
}

func (r *PrometheusRecorder) StreamOpened(kind string) {
	kind = labelValue(kind)
	r.streams.WithLabelValues(kind).Inc()
	r.activeStreams.WithLabelValues(kind).Inc()
}

func (r *PrometheusRecorder) StreamClosed(kind string) {
	r.activeStreams.WithLabelValues(labelValue(kind)).Dec()
}

func (r *PrometheusRecorder) StreamBytes(kind, direction string, n int64) {
	if n <= 0 {
		return
	}
	r.streamBytes.WithLabelValues(labelValue(kind), labelValue(direction)).Add(float64(n))
}

func (r *PrometheusRecorder) HelperAcquired(capability string) {
	r.activeHelpers.WithLabelValues(labelValue(capability)).Inc()
}

func (r *PrometheusRecorder) HelperAcquireFinished(capability, result string, duration time.Duration) {
	capability = labelValue(capability)
	result = labelValue(result)
	r.helperAcquire.WithLabelValues(capability, result).Inc()
	r.helperAcquireDuration.WithLabelValues(capability, result).Observe(duration.Seconds())
}

func (r *PrometheusRecorder) HelperReleased(capability, result string, duration time.Duration) {
	capability = labelValue(capability)
	result = labelValue(result)
	r.activeHelpers.WithLabelValues(capability).Dec()
	r.helperRelease.WithLabelValues(capability, result).Inc()
	r.helperUsageDuration.WithLabelValues(capability, result).Observe(duration.Seconds())
}

func (r *PrometheusRecorder) AccessPolicyCacheSyncFinished(resource, result string, duration time.Duration) {
	resource = labelValue(resource)
	result = labelValue(result)
	r.accessPolicyCacheSync.WithLabelValues(resource, result).Inc()
	r.accessPolicyCacheSyncDur.WithLabelValues(resource, result).Observe(duration.Seconds())
}

func (r *PrometheusRecorder) AccessPolicyObjects(resource string, count int) {
	r.accessPolicyObjects.WithLabelValues(labelValue(resource)).Set(float64(count))
}

func (r *PrometheusRecorder) AccessPolicyAuthFinished(credential, result string, duration time.Duration) {
	credential = labelValue(credential)
	result = labelValue(result)
	r.accessPolicyAuth.WithLabelValues(credential, result).Inc()
	r.accessPolicyAuthDuration.WithLabelValues(credential, result).Observe(duration.Seconds())
}

func (r *PrometheusRecorder) AccessPolicyResolveFinished(result string, duration time.Duration) {
	result = labelValue(result)
	r.accessPolicyResolve.WithLabelValues(result).Inc()
	r.accessPolicyResolveDur.WithLabelValues(result).Observe(duration.Seconds())
}

func (r *PrometheusRecorder) AccessPolicyAuthorizeFinished(capability, decision, result string, duration time.Duration) {
	capability = labelValue(capability)
	decision = labelValue(decision)
	result = labelValue(result)
	r.accessPolicyAuthorize.WithLabelValues(capability, decision, result).Inc()
	r.accessPolicyAuthorizeDur.WithLabelValues(capability, decision, result).Observe(duration.Seconds())
}

func registerRuntimeCollectors(registry *prometheus.Registry) {
	for _, collector := range []prometheus.Collector{
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	} {
		if err := registry.Register(collector); err != nil {
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
				panic(err)
			}
		}
	}
}
