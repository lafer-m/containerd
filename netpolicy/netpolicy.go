package netpolicy

import (
	"context"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/namespaces"
	dacssvc "github.com/containerd/containerd/pkg/dacscri/server"
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
			plugin.MetadataPlugin,
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

			m, err := ic.Get(plugin.MetadataPlugin)
			if err != nil {
				return nil, err
			}

			db := m.(*metadata.DB)
			svc := &service{
				cfg:        cfg,
				subscribe:  subscibeEvent,
				runtime:    pl.(*v2.TaskManager),
				backend:    back.(containerd.SessionClient),
				policys:    map[string]*policyVersion{},
				containers: metadata.NewContainerStore(db),
			}
			if err := svc.loadExistPolicysFromRemote(); err != nil {
				log.L.Warnf("load exist policys err: %v", err)
			}
			if err := svc.syncPolicyToContainers(); err != nil {
				log.L.Warnf("sync policy to containers err: %v", err)
			}
			go svc.run()
			return svc, nil
		}},
	)
}

type service struct {
	cfg        *Config
	subscribe  events.Subscriber
	containers containers.Store
	runtime    *v2.TaskManager
	backend    containerd.SessionClient
	policys    map[string]*policyVersion
}

// timer ticker running
func (s *service) run() {
	ticker := time.NewTicker(time.Duration(s.cfg.TickDuration) * time.Second)
	sub, err := s.subscribe.Subscribe(context.Background(), `topic=="/tasks/start"`)
	// log.L.Info("start netpolicy info")

	for {
		select {
		case <-ticker.C:
			// log.L.Info("netpolicy sync timer")
			// sync netpolicy here
			if err := s.loadExistPolicysFromRemote(); err != nil {
				log.L.Warnf("load exist policys err: %v", err)
			}
			if err := s.syncPolicyToContainers(); err != nil {
				log.L.Warnf("sync policy to containers err: %v", err)
			}

		case ev := <-sub:
			// if is task start or restart event , must sync netpolicy to containers.
			log.L.Infof("events: %v, %s", ev.Event, ev.Topic)
			if err := s.loadExistPolicysFromRemote(); err != nil {
				log.L.Warnf("load exist policys err: %v", err)
			}
			if err := s.syncPolicyToContainers(); err != nil {
				log.L.Warnf("sync policy to containers err: %v", err)
			}

		case e := <-err:
			log.L.Infof("event err: %v", e)
			// resubscribe
			sub, err = s.subscribe.Subscribe(context.Background(), `topic=="/tasks/start"`)
		}
	}
}

func (s *service) syncPolicyToContainers() error {
	ns := namespaces.Default
	ctx := namespaces.WithNamespace(context.Background(), ns)
	cns, err := s.containers.List(ctx)
	if err != nil {
		return err
	}

	for _, c := range cns {
		svc, ok := c.Labels[dacssvc.ServiceLabelKey]
		if !ok {
			continue
		}
		policys, ok := s.policys[svc]
		if ok {
			if !policys.changed {
				continue
			}
			// Get task object
			t, err := s.runtime.Get(ctx, c.ID)
			if err != nil {
				log.L.Warnf("sync policy failed : task %v not found", c.ID)
				continue
			}
			pol, err := policys.marshal()
			if err != nil {
				log.L.Warnf("sync policy failed : task: %v marshal policys err: %v", c.ID, err)
				continue
			}

			// set netpolicy for container
			if err := t.SetNetPolicy(ctx, svc, string(pol)); err != nil {
				log.L.Warnf("set netpolicy err: task %v., err: %v", c.ID, err)
			}
			policys.applied = true
		}
	}
	return nil
}

func (s *service) loadExistPolicysFromRemote() error {
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
			changed: true,
			applied: false,
		}
		if p, ok := s.policys[svc]; ok {
			if p.version == pv.version && p.applied {
				pv.changed = false
				pv.applied = true
			}
		}
		s.policys[svc] = pv
	}
	return nil
}
