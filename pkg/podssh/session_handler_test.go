package podssh

import (
	"testing"

	ssh "golang.org/x/crypto/ssh"
)

func TestSessionPTYRejectsMalformedPayload(t *testing.T) {
	valid := ssh.Marshal(struct {
		Term                                   string
		Width, Height, PixelWidth, PixelHeight uint32
		Modes                                  string
	}{"xterm", 80, 24, 0, 0, "\x00"})
	for name, payload := range map[string][]byte{
		"overflow":  {255, 255, 255, 255},
		"truncated": valid[:len(valid)-1],
		"trailing":  append(append([]byte(nil), valid...), 0),
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("malformed PTY request panicked: %v", p)
				}
			}()
			if _, ok := parseSessionPTYRequest(payload); ok {
				t.Fatal("malformed PTY request accepted")
			}
		})
	}
	if pty, ok := parseSessionPTYRequest(valid); !ok || pty.Window.Width != 80 || pty.Term != "xterm" {
		t.Fatalf("valid PTY rejected or changed: %+v, %v", pty, ok)
	}
}
