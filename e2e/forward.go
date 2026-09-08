//go:build e2e

package e2e

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

type LocalHTTPServer struct {
	Address string
}

func (f *Framework) HTTPGet(url string) Result {
	return f.HTTPGetTimeout(url, 30*time.Second)
}

func (f *Framework) HTTPGetTimeout(url string, timeout time.Duration) Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{Code: -1, Stderr: err.Error()}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Result{Code: -1, Stderr: err.Error()}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{Code: -1, Stderr: err.Error()}
	}
	return Result{Code: resp.StatusCode, Stdout: string(data)}
}

func (f *Framework) WaitHTTPBody(url, body string, timeout time.Duration) {
	f.T.Helper()
	deadline := time.Now().
		Add(timeout)
	var last Result
	for time.Now().
		Before(deadline) {
		last = f.HTTPGet(url)
		if last.Code == http.StatusOK && last.Stdout == body {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	f.T.Fatalf("timed out waiting for %s body %q; last result:\n%s", url, body, last.Dump())
}

func (f *Framework) StartLocalHTTPServer(body string) *LocalHTTPServer {
	f.T.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.T.Fatalf("listen local http: %v", err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, body)
		}),
	}
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			f.T.Logf("local http server error: %v", err)
		}
	}()
	f.T.Cleanup(func() {
		_ = server.Shutdown(context.Background())
	})
	return &LocalHTTPServer{
		Address: listener.Addr().
			String(),
	}
}
