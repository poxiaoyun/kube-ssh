package webhook

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const DefaultTimeout = 2 * time.Second

// Options configures a simple JSON webhook client. The fields intentionally
// mirror common Kubernetes-style webhook HTTP settings without requiring a full
// kubeconfig file.
type Options struct {
	Server string `json:"server,omitempty"`

	ProxyURL string `json:"proxyURL,omitempty"`

	Token    string `json:"token,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
	CAFile   string `json:"caFile,omitempty"`

	InsecureSkipTLSVerify bool          `json:"insecureSkipTLSVerify,omitempty"`
	Timeout               time.Duration `json:"timeout,omitempty"`
}

func (o Options) Enabled() bool {
	return o.Server != ""
}

type Client struct {
	server *url.URL
	client *http.Client
	token  string
	user   string
	pass   string
}

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

	transport, err := transportForOptions(opts)
	if err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		server: server,
		client: &http.Client{Transport: transport, Timeout: timeout},
		token:  opts.Token,
		user:   opts.Username,
		pass:   opts.Password,
	}, nil
}

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
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	} else if c.user != "" || c.pass != "" {
		req.SetBasicAuth(c.user, c.pass)
	}

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
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode webhook response: %w", err)
	}
	return nil
}

func transportForOptions(opts Options) (*http.Transport, error) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	if opts.ProxyURL != "" {
		proxyURL, err := url.Parse(opts.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("parse webhook proxy URL: %w", err)
		}
		base.Proxy = http.ProxyURL(proxyURL)
	}

	tlsConfig, err := tlsConfigForOptions(opts)
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		base.TLSClientConfig = tlsConfig
	}
	return base, nil
}

func tlsConfigForOptions(opts Options) (*tls.Config, error) {
	if opts.CAFile == "" && opts.CertFile == "" && opts.KeyFile == "" && !opts.InsecureSkipTLSVerify {
		return nil, nil
	}
	config := &tls.Config{InsecureSkipVerify: opts.InsecureSkipTLSVerify} //nolint:gosec
	if opts.CAFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		data, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read webhook CA file: %w", err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("webhook CA file contains no certificates")
		}
		config.RootCAs = pool
	}
	if opts.CertFile != "" || opts.KeyFile != "" {
		if opts.CertFile == "" || opts.KeyFile == "" {
			return nil, fmt.Errorf("webhook cert-file and key-file must be set together")
		}
		cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load webhook client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}
	return config, nil
}
