package netpolicy

import (
	"context"
	"time"

	"github.com/containerd/containerd"
	policy "github.com/containerd/containerd/api/services/auth/proto"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/plugin"
	v2 "github.com/containerd/containerd/runtime/v2"
	"github.com/containerd/containerd/services"
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

			pl, err := ic.Get(plugin.RuntimePluginV2)
			if err != nil {
				return nil, err
			}

			back, err := ic.GetByID(plugin.ServicePlugin, services.SessionService)
			if err != nil {
				return nil, err
			}

			svc := &service{
				cfg:       cfg,
				subscribe: subscibeEvent,
				runtime:   pl.(*v2.TaskManager),
				backend:   back.(containerd.SessionClient),
				policys:   map[string]*policyVersion{},
			}
			if err := svc.loadServicesExist(); err != nil {
				log.L.Warnf("load exist service err: %v", err)
			}
			go svc.run()
			return svc, nil
		}},
	)
}

type policyVersion struct {
	service string
	version string
	policys *policy.PolicyGroup
}

type service struct {
	cfg       *Config
	subscribe events.Subscriber
	runtime   *v2.TaskManager
	backend   containerd.SessionClient
	policys   map[string]*policyVersion
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
			// resubscribe
			sub, err = s.subscribe.Subscribe(context.Background())
		}
	}
}

func (s *service) syncAll() error {

	return nil
}

func (s *service) loadServicesExist() error {
	svcs, err := s.backend.ListService()
	if err != nil {
		return err
	}

	for _, svc := range svcs {
		ak, sk, err := s.backend.GetAKSKLocal(svc)
		if err != nil {
			log.L.Warnf("load exsiting service err: %v", err)
			continue
		}
		req := newNetPolicyRequest(ak, sk)
		resp, err := s.backend.FetchPolicy(context.Background(), req)
		if err != nil {
			log.L.Warnf("get policy err: %v", err)
			continue
		}
		pv := &policyVersion{
			service: svc,
			version: hashObject(resp.Group),
			policys: resp.Group,
		}
		s.policys[svc] = pv
	}
	return nil
}
