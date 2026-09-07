package helper_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend/helper"
)

func TestRunDialPreservesResponseAfterEOF(t *testing.T) {
	for _, requester := range []string{"stdin", "tcp"} {
		t.Run(requester, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			stdin, input := io.Pipe()
			output, stdout := io.Pipe()
			defer input.Close()
			defer output.Close()
			host, portText, err := net.SplitHostPort(listener.Addr().
				String())
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.ParseUint(portText, 10, 16)
			if err != nil {
				t.Fatal(err)
			}
			dialDone := make(chan error, 1)
			go func() { dialDone <- helper.RunDial(ctx, host, uint(port), stdin, stdout) }()

			conn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().
				Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			peer := conn.(*net.TCPConn)
			peerDone := make(chan error, 1)
			go func() {
				if requester == "tcp" {
					if _, err := io.WriteString(peer, "request"); err != nil {
						peerDone <- err
						return
					}
					if err := peer.CloseWrite(); err != nil {
						peerDone <- err
						return
					}
				}
				data, err := io.ReadAll(peer)
				if err != nil {
					peerDone <- err
					return
				}
				want := "response after EOF"
				if requester == "stdin" {
					want = "request"
				}
				if string(data) != want {
					peerDone <- fmt.Errorf("TCP read = %q, want %q", data, want)
					return
				}
				if requester == "stdin" {
					if _, err := io.WriteString(peer, "response after EOF"); err != nil {
						peerDone <- err
						return
					}
					peerDone <- peer.CloseWrite()
					return
				}
				peerDone <- nil
			}()

			data := "request"
			if requester == "tcp" {
				readForwardedToEOF(t, ctx, output, "request")
				data = "response after EOF"
			}
			if _, err := io.WriteString(input, data); err != nil {
				t.Fatal(err)
			}
			if err := input.Close(); err != nil {
				t.Fatal(err)
			}
			if requester == "stdin" {
				readForwardedToEOF(t, ctx, output, "response after EOF")
			}
			for _, done := range []<-chan error{peerDone, dialDone} {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("dial did not finish after both sides sent EOF")
				}
			}
		})
	}
}
