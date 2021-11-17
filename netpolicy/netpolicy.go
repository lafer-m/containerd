package netpolicy

import (
	"context"
	"time"

	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/plugin"
)

func init() {
	plugin.Register(&plugin.Registration{
		Type:   plugin.NetPolicyPlugin,
		ID:     "netpolicy",
		Config: &Config{TickDuration: 10},
		Requires: []plugin.Type{
			plugin.EventPlugin,
			plugin.ServicePlugin,
			plugin.RuntimePluginV2,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			cfg := ic.Config.(*Config)
			ev, err := ic.Get(plugin.EventPlugin)
			if err != nil {
				return nil, err
			}
			subscibeEvent := ev.(events.Subscriber)
			svc := &service{
				cfg:       cfg,
				subscribe: subscibeEvent,
			}
			go svc.run()
			return svc, nil
		}},
	)
}

type service struct {
	cfg       *Config
	subscribe events.Subscriber
}

// timer ticker running
func (s *service) run() {
	ticker := time.NewTicker(time.Duration(s.cfg.TickDuration) * time.Second)
	sub, err := s.subscribe.Subscribe(context.Background())
	// log.L.Info("start netpolicy info")

	for {
		select {
		case <-ticker.C:
			// log.L.Info("netpolicy sync timer")
			// sync netpolicy here
		case ev := <-sub:
			// if is task start or restart event , must sync netpolicy to containers.
			log.L.Infof("events: %v, %s", ev.Event, ev.Topic)
		case e := <-err:
			log.L.Infof("event err: %v", e)
		}
	}

}
