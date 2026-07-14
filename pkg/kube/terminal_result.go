package kube

import "sync"

// terminalResult stores one asynchronous terminal result. Unlike receiving
// directly from a channel, Wait and Poll may be called repeatedly without
// consuming the result.
type terminalResult struct {
	once sync.Once
	done chan struct{}
	err  error
}

func newTerminalResult() *terminalResult {
	return &terminalResult{done: make(chan struct{})}
}

func (r *terminalResult) complete(err error) {
	r.once.Do(func() {
		r.err = err
		close(r.done)
	})
}

func (r *terminalResult) wait() error {
	<-r.done
	return r.err
}

func (r *terminalResult) poll() (error, bool) {
	select {
	case <-r.done:
		return r.err, true
	default:
		return nil, false
	}
}
