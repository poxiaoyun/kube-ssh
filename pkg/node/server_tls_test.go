package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadServerTLSReloadsServingCertificateAndClientCA(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	writeTLSFiles(t, caFile, certFile, keyFile, 1)

	tlsConfig, runtime, err := loadServerTLS(ServerOptions{
		TLSCAFile:   caFile,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	})
	if err != nil {
		t.Fatalf("loadServerTLS() error = %v", err)
	}
	before := currentTLSConfig(t, tlsConfig)
	beforeCertificate := before.Certificates[0].Certificate[0]
	beforeSubjects := before.ClientCAs.Subjects()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runtime.Run(ctx)
	writeTLSFiles(t, caFile, certFile, keyFile, 2)

	after := waitForTLSReload(t, tlsConfig, beforeCertificate, beforeSubjects)
	if bytes.Equal(after.Certificates[0].Certificate[0], beforeCertificate) {
		t.Fatal("serving certificate was not reloaded")
	}
	if equalByteSlices(after.ClientCAs.Subjects(), beforeSubjects) {
		t.Fatal("client CA was not reloaded")
	}
}

func TestLoadServerTLSRequiresAllFiles(t *testing.T) {
	if _, _, err := loadServerTLS(ServerOptions{}); err == nil {
		t.Fatal("loadServerTLS() error = nil")
	}
}

func currentTLSConfig(t *testing.T, config *tls.Config) *tls.Config {
	t.Helper()
	current, err := config.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "kube-ssh-node"})
	if err != nil {
		t.Fatalf("GetConfigForClient() error = %v", err)
	}
	if len(current.Certificates) != 1 {
		t.Fatalf("TLS certificates = %d, want 1", len(current.Certificates))
	}
	if current.ClientCAs == nil {
		t.Fatal("TLS client CA pool is nil")
	}
	return current
}

func waitForTLSReload(t *testing.T, config *tls.Config, oldCertificate []byte, oldSubjects [][]byte) *tls.Config {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current := currentTLSConfig(t, config)
		certificateChanged := !bytes.Equal(current.Certificates[0].Certificate[0], oldCertificate)
		subjectsChanged := !equalByteSlices(current.ClientCAs.Subjects(), oldSubjects)
		if certificateChanged && subjectsChanged {
			return current
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for TLS files to reload")
	return nil
}

func writeTLSFiles(t *testing.T, caFile, certFile, keyFile string, generation int64) {
	t.Helper()
	now := time.Now()
	caPublicKey, caPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(generation),
		Subject:               pkix.Name{CommonName: "test-ca-" + big.NewInt(generation).String()},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublicKey, caPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	serverPublicKey, serverPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100 + generation),
		Subject:      pkix.Name{CommonName: "kube-ssh-node"},
		DNSNames:     []string{"kube-ssh-node"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, serverPublicKey, caPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := x509.MarshalPKCS8PrivateKey(serverPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	writePEMFile(t, caFile, "CERTIFICATE", caDER, 0o644)
	writePEMFile(t, certFile, "CERTIFICATE", serverDER, 0o644)
	writePEMFile(t, keyFile, "PRIVATE KEY", serverKey, 0o600)
}

func writePEMFile(t *testing.T, name, blockType string, data []byte, mode os.FileMode) {
	t.Helper()
	contents := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: data})
	if err := os.WriteFile(name, contents, mode); err != nil {
		t.Fatal(err)
	}
}

func equalByteSlices(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if !bytes.Equal(left[i], right[i]) {
			return false
		}
	}
	return true
}
