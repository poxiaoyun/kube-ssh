// Package webhook provides the shared JSON-over-HTTP client.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"k8s.io/client-go/rest"
)

// DefaultTimeout bounds a webhook call when Options.Timeout is zero.
const DefaultTimeout = 2 * time.Second

// Options configures a JSON webhook using client-go HTTP authentication and TLS
// settings, without requiring a kubeconfig file.
type Options struct {
	Server string

	ProxyURL string

	Token    string
	Username string
	Password string

	CertFile string
	KeyFile  string
	CAFile   string

	InsecureSkipTLSVerify bool
	Timeout               time.Duration
}

// Enabled reports whether a webhook server is configured.
func (o Options) Enabled() bool {
	return o.Server != ""
}

// Client posts JSON to a configured webhook endpoint without following redirects.
// NewClient establishes the transport configuration used by every request.
type Client struct {
	server *url.URL
	client *http.Client
}

// NewClient constructs a webhook client with client-go transport semantics.
func NewClient(opts Options) (*Client, error) {
	if opts.Server == "" {
		return nil, fmt.Errorf("webhook server is required")
	}
	server, err := url.Parse(opts.Server)
	if err != nil {
		return nil, fmt.Errorf("parse webhook server: %w", err)
	}
	if server.Scheme != "http" && server.Scheme != "https" {
		return nil, fmt.Errorf("webhook server must use http or https")
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	config := &rest.Config{
		Host:        server.String(),
		BearerToken: opts.Token,
		Username:    opts.Username,
		Password:    opts.Password,
		Timeout:     timeout,
		TLSClientConfig: rest.TLSClientConfig{
			CAFile:   opts.CAFile,
			CertFile: opts.CertFile,
			KeyFile:  opts.KeyFile,
			Insecure: opts.InsecureSkipTLSVerify,
		},
	}
	if opts.ProxyURL != "" {
		proxyURL, err := url.Parse(opts.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("parse webhook proxy URL: %w", err)
		}
		config.Proxy = http.ProxyURL(proxyURL)
	}
	client, err := rest.HTTPClientFor(config)
	if err != nil {
		return nil, fmt.Errorf("create webhook HTTP client: %w", err)
	}
	// HTTPClientFor may return http.DefaultClient; redirect policy is webhook-local.
	httpClient := *client
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{server: server, client: &httpClient}, nil
}

// Post sends in as JSON and decodes a successful response into out when non-nil.
// Non-2xx responses, including redirects, are returned as errors.
func (c *Client) Post(ctx context.Context, in, out any) error {
	data, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("encode webhook request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server.String(), bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("call webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("webhook returned %s: %s", resp.Status, string(body))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).
		Decode(out); err != nil {
		return fmt.Errorf("decode webhook response: %w", err)
	}
	return nil
}
