package server

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// sessionPolicyConn enforces a policy that may become more specific after SSH
// authentication. It uses one wake-up timer per connection; normal reads and
// writes only update the last-activity timestamp.
type sessionPolicyConn struct {
	net.Conn
	started        time.Time
	lastActivityNS atomic.Int64

	mu     sync.Mutex
	closed bool
	policy effectiveSessionPolicy
	timer  *time.Timer
}

func newSessionPolicyConn(conn net.Conn, policy effectiveSessionPolicy) *sessionPolicyConn {
	now := time.Now()
	c := &sessionPolicyConn{Conn: conn, started: now}
	c.ApplyPolicy(policy)
	return c
}

func (c *sessionPolicyConn) ApplyPolicy(policy effectiveSessionPolicy) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.policy = policy
	expired := c.scheduleLocked(time.Now())
	c.mu.Unlock()
	if expired {
		_ = c.Close()
	}
}

func (c *sessionPolicyConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *sessionPolicyConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *sessionPolicyConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	return c.Conn.Close()
}

// gliderlabs/ssh sets its own global deadlines on the connection returned by
// ConnCallback. Dynamic session policy is authoritative, so those deadlines
// must not overwrite this feature's timer.
func (c *sessionPolicyConn) SetDeadline(time.Time) error      { return nil }
func (c *sessionPolicyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *sessionPolicyConn) SetWriteDeadline(time.Time) error { return nil }

func (c *sessionPolicyConn) touch() {
	c.lastActivityNS.Store(time.Since(c.started).Nanoseconds())
}

func (c *sessionPolicyConn) onTimer() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	expired := c.scheduleLocked(time.Now())
	c.mu.Unlock()
	if expired {
		_ = c.Close()
	}
}

// scheduleLocked schedules the next policy boundary and reports whether the
// current policy has already expired.
func (c *sessionPolicyConn) scheduleLocked(now time.Time) bool {
	deadline := c.nextDeadlineLocked()
	if deadline.IsZero() {
		if c.timer != nil {
			c.timer.Stop()
		}
		return false
	}
	delay := deadline.Sub(now)
	if delay <= 0 {
		return true
	}
	if c.timer == nil {
		c.timer = time.AfterFunc(delay, c.onTimer)
	} else {
		c.timer.Reset(delay)
	}
	return false
}

func (c *sessionPolicyConn) nextDeadlineLocked() time.Time {
	var deadline time.Time
	if c.policy.MaxDuration > 0 {
		deadline = c.started.Add(c.policy.MaxDuration)
	}
	if c.policy.IdleTimeout > 0 {
		idleDeadline := c.started.Add(time.Duration(c.lastActivityNS.Load()) + c.policy.IdleTimeout)
		if deadline.IsZero() || idleDeadline.Before(deadline) {
			deadline = idleDeadline
		}
	}
	return deadline
}
