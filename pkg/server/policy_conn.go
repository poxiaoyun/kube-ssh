package server

import (
	"net"
	"sync"
	"time"
)

type policyConn struct {
	conn    net.Conn
	started time.Time

	mu          sync.Mutex
	closed      bool
	policy      effectiveSessionPolicy
	maxTimer    *time.Timer
	timerActive bool
}

func newPolicyConn(conn net.Conn, policy effectiveSessionPolicy) *policyConn {
	policyConn := &policyConn{
		conn:    conn,
		started: time.Now(),
	}
	policyConn.ApplyPolicy(policy)
	return policyConn
}

func (c *policyConn) ApplyPolicy(policy effectiveSessionPolicy) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.policy = policy
	c.resetMaxTimerLocked(time.Now())
	err := c.updateDeadlineLocked(time.Now())
	c.mu.Unlock()
	if err != nil {
		_ = c.Close()
	}
}

func (c *policyConn) Read(p []byte) (int, error) {
	if err := c.touch(); err != nil {
		return 0, err
	}
	return c.conn.Read(p)
}

func (c *policyConn) Write(p []byte) (int, error) {
	if err := c.touch(); err != nil {
		return 0, err
	}
	return c.conn.Write(p)
}

func (c *policyConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.maxTimer != nil && c.timerActive {
		c.maxTimer.Stop()
	}
	c.timerActive = false
	c.mu.Unlock()
	return c.conn.Close()
}

func (c *policyConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *policyConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *policyConn) SetDeadline(time.Time) error {
	return nil
}

func (c *policyConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *policyConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *policyConn) touch() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	err := c.updateDeadlineLocked(time.Now())
	c.mu.Unlock()
	return err
}

func (c *policyConn) updateDeadlineLocked(now time.Time) error {
	return c.conn.SetDeadline(c.deadlineLocked(now))
}

func (c *policyConn) deadlineLocked(now time.Time) time.Time {
	var deadline time.Time
	if c.policy.MaxDuration > 0 {
		deadline = c.started.Add(c.policy.MaxDuration)
	}
	if c.policy.IdleTimeout > 0 {
		idleDeadline := now.Add(c.policy.IdleTimeout)
		if deadline.IsZero() || idleDeadline.Before(deadline) {
			deadline = idleDeadline
		}
	}
	return deadline
}

func (c *policyConn) resetMaxTimerLocked(now time.Time) {
	if c.maxTimer != nil && c.timerActive {
		c.maxTimer.Stop()
	}
	c.timerActive = false
	if c.policy.MaxDuration <= 0 {
		return
	}
	delay := c.started.Add(c.policy.MaxDuration).Sub(now)
	if delay <= 0 {
		go func() {
			_ = c.Close()
		}()
		return
	}
	c.maxTimer = time.AfterFunc(delay, func() {
		_ = c.Close()
	})
	c.timerActive = true
}
