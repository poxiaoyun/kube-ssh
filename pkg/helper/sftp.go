package helper

import (
	"context"
	"io"

	"github.com/pkg/sftp"
	"xiaoshiai.cn/kube-ssh/pkg/util"
)

func RunSFTP(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	conn := util.NewStdioConn(stdin, stdout, nil)
	go closeOnContext(ctx, conn)
	server, err := sftp.NewServer(conn)
	if err != nil {
		return err
	}
	return server.Serve()
}
