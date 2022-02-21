package health

import (
	"context"
	"sync"
	"time"

	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/plugin"
)

func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.HealthPlugin,
		ID:   "health",
		Config: &Config{
			TickDuration: "10s",
			TIMEOUT:      "1s",
			EchoServer:   "127.0.0.1:8089",
		},
		Requires: []plugin.Type{
			plugin.EventPlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			cfg := ic.Config.(*Config)
			if cfg.MaxRetry <= 0 {
				cfg.MaxRetry = 1
			}
			ev, err := ic.Get(plugin.EventPlugin)
			if err != nil {
				return nil, err
			}
			// publish a clean or block event to netpolicy module.
			eventPublisher := ev.(events.Publisher)

			timeout, err := time.ParseDuration(cfg.TIMEOUT)
			if err != nil {
				return nil, err
			}
			cli, err := newClient(cfg.EchoServer, timeout)
			if err != nil {
				return nil, err
			}

			tickDuration, err := time.ParseDuration(cfg.TickDuration)
			if err != nil {
				return nil, err
			}

			hl := &Health{
				cfg:         cfg,
				publisher:   eventPublisher,
				cli:         cli,
				state:       OK,
				lastState:   OK,
				tick:        tickDuration,
				recoverChan: make(chan struct{}),
			}

			go hl.run()
			return hl, nil
		},
	})
}

type State int

const (
	UNKNOWN State = iota
	OK
	TIMEOUT
	REJECT
)

type Health struct {
	mu          *sync.RWMutex
	cfg         *Config
	publisher   events.Publisher
	cli         *client
	lastState   State
	state       State
	tick        time.Duration
	recoverChan chan struct{}
}

func (h *Health) Enabled() bool {
	return h.cfg.Enable
}

func (h *Health) Exclude() []string {
	return h.cfg.Exclude
}

func (h *Health) IsBlock() bool {
	h.mu.RLock()
	state := h.state
	h.mu.RUnlock()
	if state == OK {
		return false
	}
	return true
}

// Recover, shoud force sync network policys ,when lastState == blocking and state == OK;
func (h *Health) ShouldRecover() bool {
	h.mu.RLock()
	state := h.state
	lastState := h.lastState
	h.mu.RUnlock()

	if state == OK && lastState != OK {
		h.recoverChan <- struct{}{}
		return true
	}
	return false
}

func (h *Health) run() {
	ticker := time.NewTicker(h.tick)
	maxRetry := h.cfg.MaxRetry
	for {
		select {
		case <-ticker.C:
			waitRetry(maxRetry, h.check)
		case <-h.recoverChan:
			h.lastState = OK
		}
	}
}

func (h *Health) check() bool {
	state := h.cli.check()
	// all is ok
	if state == OK && h.state == OK {
		return true
	}
	oldState := h.state
	h.mu.Lock()
	h.lastState = h.state
	h.state = state
	h.mu.Unlock()
	if oldState == OK && state != OK {
		// publish a blocking event

	}

	// only timeout or other network problem ,could retry.
	if state == TIMEOUT {
		return false
	}
	return true
}

func (h *Health) publish() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := h.publisher.Publish(ctx, "/network/blocking", ""); err != nil {

	}
}

func waitRetry(retry int, fn func() bool) {
	for count := 0; count < retry; count++ {
		if fn() {
			break
		}
	}
}
