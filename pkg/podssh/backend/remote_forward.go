package backend

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/podssh/backend/helper"
)

func (b *Executor) RemoteForward(ctx context.Context, req RemoteForwardRequest) (RemoteForward, error) {
	if req.BindPort > 65535 {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("invalid bind port %d", req.BindPort))
	}
	session, err := b.startHelperSession(ctx, req.Target, helperpkg.CapabilityRemoteForward)
	if err != nil {
		return nil, err
	}
	forward, err := session.client.ListenRemote(ctx, req.BindHost, req.BindPort)
	if err != nil {
		err = session.resolveClientError(err)
		_ = session.Close()
		return nil, fmt.Errorf("create helper remote-forward: %w", err)
	}
	return &remoteForward{helperSession: session, forward: forward}, nil
}

type remoteForward struct {
	*helperSession
	forward *helperpkg.RemoteListener
}

func (f *remoteForward) ActualPort() uint32 {
	return f.forward.ActualPort()
}

func (f *remoteForward) Accept(ctx context.Context) (ioproxy.HalfCloser, RemoteForwardConnInfo, error) {
	stream, info, err := f.forward.Accept(ctx)
	if err != nil {
		return nil, RemoteForwardConnInfo{}, f.resolveClientError(err)
	}
	return stream, RemoteForwardConnInfo{
		OriginHost: info.OriginHost,
		OriginPort: info.OriginPort,
	}, nil
}

func (f *remoteForward) Cancel() error {
	return f.forward.Cancel(context.Background())
}
