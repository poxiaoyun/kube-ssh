package helper

import (
	"context"
	"io"

	"github.com/pkg/sftp"
)

func RunSFTP(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	conn := NewStdioConn(stdin, stdout, nil)
	go closeConnOnContext(ctx, conn)
	server, err := sftp.NewServer(conn)
	if err != nil {
		return err
	}
	return server.Serve()
}
