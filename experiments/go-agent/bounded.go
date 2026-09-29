package main

import (
	"fmt"
	"sync"
	"time"
)

// The Go counterpart of bounded.call_bounded + io_topology's _stalled_worker:
// run a collector under a wall-clock deadline, abandon it if it blocks, and
// single-flight it so a stall leaks one goroutine, not one per tick.
//
// Same limits as the Python version, because they are the kernel's, not the
// language's: a goroutine stuck in an uninterruptible syscall (a kernfs
// readdir behind reclaim) cannot be killed either, it is only abandoned. What
// changes is the cost: a goroutine is a few KB and the idiom is one select.

type result struct {
	value any
	err   error
}

var (
	stalledMu sync.Mutex
	stalled   = map[string]bool{}
)

func callBounded(name string, timeout time.Duration, fn func() (any, error)) (any, error) {
	stalledMu.Lock()
	if stalled[name] {
		stalledMu.Unlock()
		return nil, fmt.Errorf("%s: previous call still blocked", name)
	}
	stalledMu.Unlock()

	done := make(chan result, 1) // buffered: an abandoned worker never blocks on send
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- result{nil, fmt.Errorf("%s: panic: %v", name, r)}
			}
		}()
		v, err := fn()
		done <- result{v, err}
	}()

	select {
	case r := <-done:
		return r.value, r.err
	case <-time.After(timeout):
		stalledMu.Lock()
		stalled[name] = true
		stalledMu.Unlock()
		go func() { // clear the single-flight flag once the worker returns
			<-done
			stalledMu.Lock()
			delete(stalled, name)
			stalledMu.Unlock()
		}()
		return nil, fmt.Errorf("%s: blocked for %s, abandoned", name, timeout)
	}
}
