package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"xiaoshiai.cn/kube-ssh/pkg/metrics"
)

func TestStartMetricsServerServesMetricsAndHealthChecks(t *testing.T) {
	recorder := metrics.NewPrometheusRecorder(nil, metrics.PrometheusOptions{})
	srv, listener, err := startMetricsServer(context.Background(), MetricsOptions{
		ListenAddress: "127.0.0.1:0",
		Path:          "/custom-metrics",
	}, recorder)
	if err != nil {
		t.Fatalf("startMetricsServer() error = %v", err)
	}
	defer shutdownHTTPServer(srv)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(listener)
	}()

	metricsBody := httpGet(t, "http://"+listener.Addr().String()+"/custom-metrics")
	if !strings.Contains(metricsBody, "kube_ssh_build_info") {
		t.Fatalf("metrics body missing build info: %q", metricsBody)
	}
	if body := httpGet(t, "http://"+listener.Addr().String()+"/healthz"); body != "ok\n" {
		t.Fatalf("healthz body = %q, want ok", body)
	}
	if body := httpGet(t, "http://"+listener.Addr().String()+"/readyz"); body != "ok\n" {
		t.Fatalf("readyz body = %q, want ok", body)
	}

	shutdownHTTPServer(srv)
	if err := <-serveErr; err != nil && err != http.ErrServerClosed {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestStartMetricsServerRejectsInvalidPath(t *testing.T) {
	for _, path := range []string{"metrics", "/healthz", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			_, _, err := startMetricsServer(context.Background(), MetricsOptions{
				ListenAddress: "127.0.0.1:0",
				Path:          path,
			}, metrics.NewPrometheusRecorder(nil, metrics.PrometheusOptions{}))
			if err == nil {
				t.Fatal("startMetricsServer() error = nil, want error")
			}
		})
	}
}

func httpGet(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d body = %q", url, resp.StatusCode, body)
	}
	return string(body)
}
