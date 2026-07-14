package kube

import (
	"context"

	"xiaoshiai.cn/kube-ssh/pkg/backend"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/status"
)

func (b *Backend) RemoteForward(ctx context.Context, req backend.RemoteForwardRequest) (backend.RemoteForward, error) {
	if req.BindPort > 65535 {
		return nil, status.InvalidTarget("invalid bind port %d", req.BindPort)
	}
	session, err := b.startHelperSession(ctx, req.Target, helperpkg.CapabilityRemoteForward)
	if err != nil {
		return nil, err
	}
	forward, err := session.client.ListenRemote(ctx, req.BindHost, req.BindPort)
	if err != nil {
		_ = session.Close()
		return nil, status.HelperUnavailable(err, "create helper remote-forward")
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

func (f *remoteForward) Accept(ctx context.Context) (ioproxy.HalfCloser, backend.RemoteForwardConnInfo, error) {
	stream, info, err := f.forward.Accept(ctx)
	if err != nil {
		return nil, backend.RemoteForwardConnInfo{}, f.resolveClientError(err)
	}
	return stream, backend.RemoteForwardConnInfo{
		OriginHost: info.OriginHost,
		OriginPort: info.OriginPort,
	}, nil
}

func (f *remoteForward) Cancel() error {
	return f.forward.Cancel(context.Background())
}
