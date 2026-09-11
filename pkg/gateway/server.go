package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	cryptossh "golang.org/x/crypto/ssh"
)

func loadHostKey(filename string) (cryptossh.Signer, error) {
	if filename != "" {
		data, err := os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("read SSH host key: %w", err)
		}
		signer, err := cryptossh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse SSH host key: %w", err)
		}
		return signer, nil
	}
	slog.Warn("no host-key-file configured; generating an ephemeral Ed25519 host key")
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return cryptossh.NewSignerFromKey(key)
}

func (s *gateway) serveSSH(parent context.Context, listener net.Listener, signer cryptossh.Signer, methods []string) error {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	var connections sync.WaitGroup
	defer func() {
		cancel()
		_ = listener.Close()
		stop()
		connections.Wait()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		connections.Go(func() {
			s.handleConnection(ctx, conn, signer, methods)
		})
	}
}

func (s *gateway) handleConnection(parent context.Context, raw net.Conn, signer cryptossh.Signer, methods []string) {
	base, cancel := context.WithCancel(parent)
	state := &connectionState{Context: base, metadata: connectionMetadata{remote: raw.RemoteAddr(), local: raw.LocalAddr()}}
	finishAudit := s.startConnectionAudit(state)
	conn := newSessionPolicyConn(raw, buildGlobalSessionPolicy(s.opts))
	state.policyConn = conn
	stop := context.AfterFunc(base, func() { _ = conn.Close() })
	var handlers sync.WaitGroup
	defer func() {
		cancel()
		_ = conn.Close()
		stop()
		snapshot := state.snapshot()
		if snapshot.authenticated != nil {
			snapshot.authenticated.protocol.Close()
		}
		handlers.Wait()
		if snapshot.established {
			s.metrics.ConnectionClosed(snapshot.authenticated.info.Method)
		}
		finishAudit()
	}()
	config := s.authenticationConfig(state, methods)
	config.AddHostKey(signer)
	serverConn, channels, requests, err := cryptossh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer serverConn.Close()
	result := serverConn.Permissions.ExtraData[authenticationResultKey{}].(*authenticationResult)
	s.connectionEstablished(state, result.credential)
	protocol := state.snapshot().authenticated.protocol
	// Each channel runs independently. Global requests retain wire order.
	handlers.Go(func() {
		for request := range requests {
			ok, payload := protocol.HandleGlobalRequest(serverConn, request)
			_ = request.Reply(ok, payload)
		}
	})
	for channel := range channels {
		handlers.Go(func() {
			protocol.HandleChannel(serverConn, channel)
		})
	}
}
