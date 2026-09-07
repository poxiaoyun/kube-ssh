package helper

import (
	"context"
	"io"

	"github.com/pkg/sftp"
)

// RunSFTP serves SFTP and owns both streams. Their Close methods must unblock
// pending I/O so context cancellation can stop the server.
func RunSFTP(ctx context.Context, stdin io.ReadCloser, stdout io.WriteCloser) error {
	conn := newStdioConn(stdin, stdout)
	defer conn.Close()
	stopOnContext := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopOnContext()
	server, err := sftp.NewServer(conn)
	if err != nil {
		return err
	}
	return server.Serve()
}
