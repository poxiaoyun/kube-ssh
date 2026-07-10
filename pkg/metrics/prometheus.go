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
	helperAcquire            *prometheus.CounterVec
	helperAcquireDuration    *prometheus.HistogramVec
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
		recorder.helperAcquire,
		recorder.helperAcquireDuration,
		recorder.buildInfo,
	)
	recorder.buildInfo.WithLabelValues(
		labelValue(opts.BuildInfo.Version),
		labelValue(opts.BuildInfo.Commit),
		labelValue(opts.BuildInfo.BuildDate),
	).Set(1)
	return recorder
}

func (r *PrometheusRecorder) Handler() http.Handler {
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
}

func (r *PrometheusRecorder) AuthAttempt(credential, result string) {
	r.authAttempts.WithLabelValues(labelValue(credential), labelValue(result)).Inc()
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

func (r *PrometheusRecorder) HelperAcquireFinished(capability, result string, duration time.Duration) {
	capability = labelValue(capability)
	result = labelValue(result)
	r.helperAcquire.WithLabelValues(capability, result).Inc()
	r.helperAcquireDuration.WithLabelValues(capability, result).Observe(duration.Seconds())
}
