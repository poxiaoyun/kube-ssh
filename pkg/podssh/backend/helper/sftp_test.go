package helper_test

import (
	"context"
	"io"
	"testing"
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend/helper"
)

func TestRunSFTPCancellationInterruptsStdio(t *testing.T) {
	for _, blocked := range []string{"read", "write"} {
		t.Run(blocked, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stdin, input := io.Pipe()
			output, stdout := io.Pipe()
			defer input.Close()
			defer output.Close()
			done := make(chan error, 1)
			go func() { done <- helper.RunSFTP(ctx, stdin, stdout) }()
			if blocked == "write" {
				// SSH_FXP_INIT requests version 3. The output pipe has no reader,
				// so its version reply cannot complete before cancellation.
				if _, err := input.Write([]byte{0, 0, 0, 5, 1, 0, 0, 0, 3}); err != nil {
					t.Fatal(err)
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatalf("SFTP cancellation did not release pending %s", blocked)
			}
		})
	}
}
