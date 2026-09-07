package sshproxy_test

import (
	"context"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
	"xiaoshiai.cn/kube-ssh/pkg/sshproxy"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestProtocolDoesNotConnectAfterClose(t *testing.T) {
	connects := 0
	connector := protocolConnectorFunc(func(context.Context, *target.Target) (*sshproxy.Connection, error) {
		connects++
		return nil, nil
	})
	var protocol sshprotocol.ConnectionProtocol = sshproxy.NewProtocol(
		context.Background(),
		&target.Target{},
		connector,
		nil,
		nil,
	)
	protocol.Close()
	channel := &protocolNewChannel{channelType: "session"}

	protocol.HandleChannel(nil, channel)

	if connects != 0 {
		t.Fatalf("connector called %d times, want 0", connects)
	}
	if channel.rejectionReason != cryptossh.ConnectionFailed {
		t.Fatalf("channel rejection reason = %v, want %v", channel.rejectionReason, cryptossh.ConnectionFailed)
	}
}

type protocolConnectorFunc func(context.Context, *target.Target) (*sshproxy.Connection, error)

func (f protocolConnectorFunc) Connect(ctx context.Context, target *target.Target) (*sshproxy.Connection, error) {
	return f(ctx, target)
}

type protocolNewChannel struct {
	channelType     string
	rejectionReason cryptossh.RejectionReason
}

func (*protocolNewChannel) Accept() (cryptossh.Channel, <-chan *cryptossh.Request, error) {
	panic("unexpected Accept")
}

func (c *protocolNewChannel) Reject(reason cryptossh.RejectionReason, _ string) error {
	c.rejectionReason = reason
	return nil
}

func (c *protocolNewChannel) ChannelType() string {
	return c.channelType
}

func (*protocolNewChannel) ExtraData() []byte {
	return nil
}
