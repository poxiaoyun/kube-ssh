package sshproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

type proxy struct {
	ctx        context.Context
	downstream cryptossh.Conn
	connector  ConnectionConnector
	target     *target.Target
	begin      sshprotocol.BeginOperationFunc
	envAllowed func(key string) bool

	connectOnce sync.Once
	upstream    *Connection
	connectErr  error

	mu             sync.Mutex
	closed         bool
	remoteForwards map[string]sshprotocol.FinishOperation
	agentForward   sshprotocol.FinishOperation
}

func newProxy(ctx context.Context, downstream cryptossh.Conn, connector ConnectionConnector, tgt *target.Target, begin sshprotocol.BeginOperationFunc, envAllowed func(key string) bool) *proxy {
	return &proxy{
		ctx:            ctx,
		downstream:     downstream,
		connector:      connector,
		target:         tgt,
		begin:          begin,
		envAllowed:     envAllowed,
		remoteForwards: make(map[string]sshprotocol.FinishOperation),
	}
}

// HandleChannel proxies a channel opened by the downstream client.
func (p *proxy) handleChannel(newChannel cryptossh.NewChannel) {
	operation, err := parseChannelOperation(newChannel.ChannelType(), newChannel.ExtraData())
	if err != nil {
		_ = newChannel.Reject(cryptossh.ConnectionFailed, err.Error())
		return
	}
	finish, err := p.beginOperation(operation)
	if err != nil {
		_ = newChannel.Reject(cryptossh.Prohibited, err.Error())
		return
	}
	upstream, err := p.connect()
	if err != nil {
		p.finish(finish, sshprotocol.OperationResult{Err: err})
		_ = newChannel.Reject(cryptossh.ConnectionFailed, "upstream SSH connection failed")
		p.close()
		return
	}
	upstreamChannel, upstreamRequests, err := upstream.Conn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
	if err != nil {
		p.finish(finish, sshprotocol.OperationResult{Err: err})
		reason := "upstream rejected channel"
		if openError, ok := err.(*cryptossh.OpenChannelError); ok {
			_ = newChannel.Reject(openError.Reason, openError.Message)
			return
		}
		_ = newChannel.Reject(cryptossh.ConnectionFailed, reason)
		return
	}
	downstreamChannel, downstreamRequests, err := newChannel.Accept()
	if err != nil {
		upstreamChannel.Close()
		p.finish(finish, sshprotocol.OperationResult{Err: err})
		return
	}
	channel := &proxiedChannel{
		proxy:           p,
		downstream:      downstreamChannel,
		upstream:        upstreamChannel,
		finish:          finish,
		terminalRequest: newChannel.ChannelType() == sshprotocol.ChannelSession,
	}
	go channel.serve(downstreamRequests, upstreamRequests)
}

// HandleRequest proxies a global request sent by the downstream client.
func (p *proxy) handleRequest(request *cryptossh.Request) (bool, []byte) {
	plan, err := planGlobalRequest(request.Type, request.Payload)
	if err != nil {
		return false, nil
	}
	finish, err := p.beginOperation(plan.operation)
	if err != nil {
		return false, nil
	}
	if request.Type == sshprotocol.RequestTCPIPForward && p.hasRemoteForward(plan.forwardKey) {
		p.finish(finish, sshprotocol.OperationResult{Err: fmt.Errorf("remote forward already exists")})
		return false, nil
	}
	if request.Type == sshprotocol.RequestCancelTCPIPForward {
		if !p.hasRemoteForward(plan.forwardKey) {
			return false, nil
		}
	}
	upstream, err := p.connect()
	if err != nil {
		p.finish(finish, sshprotocol.OperationResult{Err: err})
		p.close()
		return false, nil
	}
	ok, payload, err := upstream.Conn.SendRequest(request.Type, request.WantReply, request.Payload)
	if err != nil {
		p.finish(finish, sshprotocol.OperationResult{Err: err})
		return false, nil
	}
	if request.WantReply && !ok {
		p.finish(finish, sshprotocol.OperationResult{Err: fmt.Errorf("upstream rejected %s", request.Type)})
		return false, payload
	}
	switch request.Type {
	case sshprotocol.RequestTCPIPForward:
		key := actualRemoteForwardKey(plan.forwardKey, payload)
		p.addRemoteForward(key, finish)
		finish = nil
	case sshprotocol.RequestCancelTCPIPForward:
		p.removeRemoteForward(plan.forwardKey, sshprotocol.OperationResult{})
	}
	p.finish(finish, sshprotocol.OperationResult{})
	return !request.WantReply || ok, payload
}

// Close closes both SSH transports and all outstanding operation lifecycles.
func (p *proxy) close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	upstream := p.upstream
	finishes := make([]sshprotocol.FinishOperation, 0, len(p.remoteForwards)+1)
	for _, finish := range p.remoteForwards {
		finishes = append(finishes, finish)
	}
	if p.agentForward != nil {
		finishes = append(finishes, p.agentForward)
	}
	p.remoteForwards = nil
	p.agentForward = nil
	p.mu.Unlock()
	if upstream != nil {
		_ = upstream.Conn.Close()
	}
	_ = p.downstream.Close()
	for _, finish := range finishes {
		finish(sshprotocol.OperationResult{Err: context.Canceled})
	}
}

func (p *proxy) connect() (*Connection, error) {
	p.connectOnce.Do(func() {
		upstream, err := p.connector.Connect(p.ctx, p.target)
		p.mu.Lock()
		if err != nil {
			p.connectErr = err
			p.mu.Unlock()
			return
		}
		if p.closed {
			p.connectErr = context.Canceled
			p.mu.Unlock()
			_ = upstream.Conn.Close()
			return
		}
		p.upstream = upstream
		p.mu.Unlock()
		go p.serveUpstreamChannels(upstream.Channels)
		go p.serveUpstreamRequests(upstream.Requests)
		go func() {
			_ = upstream.Conn.Wait()
			p.close()
		}()
	})
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.upstream, p.connectErr
}

func (p *proxy) serveUpstreamChannels(channels <-chan cryptossh.NewChannel) {
	for newChannel := range channels {
		operation, err := p.operationForUpstreamChannel(newChannel)
		if err != nil {
			_ = newChannel.Reject(cryptossh.Prohibited, err.Error())
			continue
		}
		finish, err := p.beginOperation(operation)
		if err != nil {
			_ = newChannel.Reject(cryptossh.Prohibited, err.Error())
			continue
		}
		downstreamChannel, downstreamRequests, err := p.downstream.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
		if err != nil {
			p.finish(finish, sshprotocol.OperationResult{Err: err})
			_ = newChannel.Reject(cryptossh.ConnectionFailed, "downstream rejected channel")
			continue
		}
		upstreamChannel, upstreamRequests, err := newChannel.Accept()
		if err != nil {
			downstreamChannel.Close()
			p.finish(finish, sshprotocol.OperationResult{Err: err})
			continue
		}
		channel := &proxiedChannel{
			proxy:           p,
			downstream:      downstreamChannel,
			upstream:        upstreamChannel,
			finish:          finish,
			terminalRequest: newChannel.ChannelType() == sshprotocol.ChannelSession,
		}
		go channel.serve(downstreamRequests, upstreamRequests)
	}
}

func (p *proxy) operationForUpstreamChannel(newChannel cryptossh.NewChannel) (*sshprotocol.Operation, error) {
	switch newChannel.ChannelType() {
	case sshprotocol.ChannelForwardedTCPIP:
		var data channelForwardData
		if err := cryptossh.Unmarshal(newChannel.ExtraData(), &data); err != nil {
			return nil, fmt.Errorf("parse forwarded-tcpip channel: %w", err)
		}
		if !p.hasRemoteForward(net.JoinHostPort(data.Host, strconv.FormatUint(uint64(data.Port), 10))) {
			return nil, fmt.Errorf("forwarded-tcpip channel has no authorized remote forward")
		}
		return nil, nil
	case sshprotocol.ChannelAgent:
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.agentForward == nil {
			return nil, fmt.Errorf("agent forwarding was not authorized")
		}
		return nil, nil
	default:
		return &sshprotocol.Operation{ChannelType: newChannel.ChannelType()}, nil
	}
}

func (p *proxy) serveUpstreamRequests(requests <-chan *cryptossh.Request) {
	for request := range requests {
		var finish sshprotocol.FinishOperation
		if request.Type != sshprotocol.RequestKeepalive && request.Type != sshprotocol.RequestNoMoreSessions {
			operation := sshprotocol.Operation{RequestType: request.Type}
			var err error
			finish, err = p.beginOperation(&operation)
			if err != nil {
				if request.WantReply {
					_ = request.Reply(false, nil)
				}
				continue
			}
		}
		ok, payload, err := p.downstream.SendRequest(request.Type, request.WantReply, request.Payload)
		p.finish(finish, sshprotocol.OperationResult{Err: err})
		if request.WantReply {
			accepted := ok
			if err != nil {
				accepted = false
			}
			_ = request.Reply(accepted, payload)
		}
	}
}

type proxiedChannel struct {
	proxy      *proxy
	downstream cryptossh.Channel
	upstream   cryptossh.Channel

	terminalRequest bool

	mu       sync.Mutex
	finish   sshprotocol.FinishOperation
	exitCode *int
}

func (c *proxiedChannel) serve(downstreamRequests, upstreamRequests <-chan *cryptossh.Request) {
	go c.forwardRequests(c.upstream, downstreamRequests, true)
	upstreamRequestsForwarded := make(chan struct{})
	go func() {
		c.forwardRequests(c.downstream, upstreamRequests, false)
		close(upstreamRequestsForwarded)
	}()
	go copyExtended(c.downstream.Stderr(), c.upstream.Stderr())
	go copyExtended(c.upstream.Stderr(), c.downstream.Stderr())
	downstream := ioproxy.HalfCloser(c.downstream)
	if c.terminalRequest {
		downstream = requestSynchronizedChannel{Channel: c.downstream, requestsForwarded: upstreamRequestsForwarded}
	}
	proxyErr := ioproxy.Proxy(c.proxy.ctx, downstream, c.upstream)
	c.mu.Lock()
	finish, exitCode := c.finish, c.exitCode
	c.finish = nil
	c.mu.Unlock()
	c.proxy.finish(finish, sshprotocol.OperationResult{Err: proxyErr, ExitCode: exitCode})
}

func (c *proxiedChannel) forwardRequests(destination cryptossh.Channel, requests <-chan *cryptossh.Request, downstream bool) {
	for request := range requests {
		var finish sshprotocol.FinishOperation
		var effect downstreamRequestEffect
		if downstream {
			plan, err := c.planDownstreamRequest(request)
			if err != nil {
				if request.WantReply {
					_ = request.Reply(false, nil)
				}
				continue
			}
			finish, err = c.proxy.beginOperation(plan.operation)
			if err != nil {
				if request.WantReply {
					_ = request.Reply(false, nil)
				}
				continue
			}
			effect = plan.effect
		} else if request.Type == sshprotocol.RequestExitStatus {
			c.recordExitStatus(request.Payload)
		}
		ok, err := destination.SendRequest(request.Type, request.WantReply, request.Payload)
		if finish != nil {
			if err != nil {
				c.proxy.finish(finish, sshprotocol.OperationResult{Err: err})
			} else if request.WantReply && !ok {
				c.proxy.finish(finish, sshprotocol.OperationResult{Err: fmt.Errorf("upstream rejected %s", request.Type)})
			} else {
				switch effect {
				case downstreamRequestAgentForward:
					c.proxy.setAgentForward(finish)
				case downstreamRequestSession:
					c.replaceFinish(finish)
				default:
					c.proxy.finish(finish, sshprotocol.OperationResult{})
				}
			}
		}
		if request.WantReply {
			accepted := ok
			if err != nil {
				accepted = false
			}
			_ = request.Reply(accepted, nil)
		}
		if !downstream && (request.Type == sshprotocol.RequestExitStatus || request.Type == sshprotocol.RequestExitSignal) {
			return
		}
	}
}

// requestSynchronizedChannel delays normal channel closure until the peer's
// terminal request has been forwarded. SSH carries exit status outside the
// channel data stream, so data EOF alone does not complete a session.
type requestSynchronizedChannel struct {
	cryptossh.Channel
	requestsForwarded <-chan struct{}
}

func (c requestSynchronizedChannel) Wait() error {
	<-c.requestsForwarded
	return nil
}

func (c *proxiedChannel) recordExitStatus(payload []byte) {
	var status struct{ Status uint32 }
	if err := cryptossh.Unmarshal(payload, &status); err != nil {
		return
	}
	code := int(status.Status)
	c.mu.Lock()
	c.exitCode = &code
	c.mu.Unlock()
}

type downstreamRequestEffect uint8

const (
	downstreamRequestNone downstreamRequestEffect = iota
	downstreamRequestSession
	downstreamRequestAgentForward
)

type downstreamRequestPlan struct {
	operation *sshprotocol.Operation
	effect    downstreamRequestEffect
}

func (c *proxiedChannel) planDownstreamRequest(request *cryptossh.Request) (downstreamRequestPlan, error) {
	switch request.Type {
	case sshprotocol.RequestShell:
		operation := sshprotocol.Operation{ChannelType: sshprotocol.ChannelSession, RequestType: request.Type}
		return downstreamRequestPlan{operation: &operation, effect: downstreamRequestSession}, nil
	case sshprotocol.RequestExec:
		var payload struct{ Value string }
		if err := cryptossh.Unmarshal(request.Payload, &payload); err != nil {
			return downstreamRequestPlan{}, fmt.Errorf("parse exec request: %w", err)
		}
		operation := sshprotocol.Operation{ChannelType: sshprotocol.ChannelSession, RequestType: request.Type, Command: payload.Value}
		return downstreamRequestPlan{operation: &operation, effect: downstreamRequestSession}, nil
	case sshprotocol.RequestSubsystem:
		var payload struct{ Value string }
		if err := cryptossh.Unmarshal(request.Payload, &payload); err != nil {
			return downstreamRequestPlan{}, fmt.Errorf("parse subsystem request: %w", err)
		}
		operation := sshprotocol.Operation{ChannelType: sshprotocol.ChannelSession, RequestType: request.Type, Subsystem: payload.Value}
		return downstreamRequestPlan{operation: &operation, effect: downstreamRequestSession}, nil
	case sshprotocol.RequestAgentForward:
		operation := sshprotocol.Operation{ChannelType: sshprotocol.ChannelSession, RequestType: request.Type}
		return downstreamRequestPlan{operation: &operation, effect: downstreamRequestAgentForward}, nil
	case sshprotocol.RequestEnvironment:
		var payload struct{ Key, Value string }
		if err := cryptossh.Unmarshal(request.Payload, &payload); err != nil {
			return downstreamRequestPlan{}, fmt.Errorf("parse env request: %w", err)
		}
		if !c.proxy.envAllowed(payload.Key) {
			return downstreamRequestPlan{}, fmt.Errorf("environment variable %q is not allowed", payload.Key)
		}
		return downstreamRequestPlan{}, nil
	case sshprotocol.RequestPTY, sshprotocol.RequestWindowChange, sshprotocol.RequestSignal, sshprotocol.RequestBreak:
		return downstreamRequestPlan{}, nil
	default:
		operation := sshprotocol.Operation{ChannelType: sshprotocol.ChannelSession, RequestType: request.Type}
		return downstreamRequestPlan{operation: &operation}, nil
	}
}

func (c *proxiedChannel) replaceFinish(finish sshprotocol.FinishOperation) {
	c.mu.Lock()
	previous := c.finish
	c.finish = finish
	c.mu.Unlock()
	if previous != nil {
		c.proxy.finish(previous, sshprotocol.OperationResult{Err: fmt.Errorf("another session operation started on the same channel")})
	}
}

func (p *proxy) finish(finish sshprotocol.FinishOperation, result sshprotocol.OperationResult) {
	if finish != nil {
		finish(result)
	}
}

func (p *proxy) beginOperation(operation *sshprotocol.Operation) (sshprotocol.FinishOperation, error) {
	if operation == nil {
		return nil, nil
	}
	finish, err := p.begin(*operation)
	if err != nil {
		p.finish(finish, sshprotocol.OperationResult{})
		return nil, err
	}
	return finish, nil
}

func (p *proxy) addRemoteForward(key string, finish sshprotocol.FinishOperation) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		p.finish(finish, sshprotocol.OperationResult{Err: context.Canceled})
		return
	}
	p.remoteForwards[key] = finish
	p.mu.Unlock()
}

func (p *proxy) removeRemoteForward(key string, result sshprotocol.OperationResult) {
	p.mu.Lock()
	finish := p.remoteForwards[key]
	delete(p.remoteForwards, key)
	p.mu.Unlock()
	p.finish(finish, result)
}

func (p *proxy) hasRemoteForward(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.remoteForwards[key]
	return ok
}

func (p *proxy) setAgentForward(finish sshprotocol.FinishOperation) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		p.finish(finish, sshprotocol.OperationResult{Err: context.Canceled})
		return
	}
	previous := p.agentForward
	p.agentForward = finish
	p.mu.Unlock()
	p.finish(previous, sshprotocol.OperationResult{Err: fmt.Errorf("agent forwarding was requested more than once")})
}

func parseChannelOperation(channelType string, payload []byte) (*sshprotocol.Operation, error) {
	switch channelType {
	case sshprotocol.ChannelSession:
		return nil, nil
	case sshprotocol.ChannelDirectTCPIP:
		var data channelForwardData
		if err := cryptossh.Unmarshal(payload, &data); err != nil {
			return nil, fmt.Errorf("parse direct-tcpip request: %w", err)
		}
		operation := sshprotocol.Operation{
			ChannelType:     channelType,
			DestinationHost: data.Host,
			DestinationPort: data.Port,
			OriginHost:      data.OriginHost,
			OriginPort:      data.OriginPort,
		}
		return &operation, nil
	default:
		return &sshprotocol.Operation{ChannelType: channelType}, nil
	}
}

type globalRequestPlan struct {
	operation  *sshprotocol.Operation
	forwardKey string
}

func planGlobalRequest(requestType string, payload []byte) (globalRequestPlan, error) {
	switch requestType {
	case sshprotocol.RequestTCPIPForward:
		var data globalForwardData
		if err := cryptossh.Unmarshal(payload, &data); err != nil {
			return globalRequestPlan{}, fmt.Errorf("parse tcpip-forward request: %w", err)
		}
		operation := sshprotocol.Operation{RequestType: requestType, BindHost: data.Host, BindPort: data.Port}
		return globalRequestPlan{operation: &operation, forwardKey: forwardKey(data)}, nil
	case sshprotocol.RequestCancelTCPIPForward:
		var data globalForwardData
		if err := cryptossh.Unmarshal(payload, &data); err != nil {
			return globalRequestPlan{}, fmt.Errorf("parse cancel-tcpip-forward request: %w", err)
		}
		return globalRequestPlan{forwardKey: forwardKey(data)}, nil
	case sshprotocol.RequestKeepalive, sshprotocol.RequestNoMoreSessions:
		return globalRequestPlan{}, nil
	default:
		operation := sshprotocol.Operation{RequestType: requestType}
		return globalRequestPlan{operation: &operation}, nil
	}
}

func forwardKey(data globalForwardData) string {
	return net.JoinHostPort(data.Host, strconv.FormatUint(uint64(data.Port), 10))
}

func actualRemoteForwardKey(requested string, payload []byte) string {
	_, port, err := net.SplitHostPort(requested)
	if err != nil || port != "0" {
		return requested
	}
	var success struct{ Port uint32 }
	if cryptossh.Unmarshal(payload, &success) != nil {
		return requested
	}
	host, _, _ := net.SplitHostPort(requested)
	return net.JoinHostPort(host, strconv.FormatUint(uint64(success.Port), 10))
}

type channelForwardData struct {
	Host       string
	Port       uint32
	OriginHost string
	OriginPort uint32
}

type globalForwardData struct {
	Host string
	Port uint32
}

func copyExtended(destination io.Writer, source io.Reader) {
	_, _ = io.Copy(destination, source)
}
