package netpolicy

import "github.com/containerd/containerd/plugin"

func init() {
	plugin.Register(&plugin.Registration{
		Type:   plugin.NetPolicyPlugin,
		ID:     "netpolicy",
		Config: &Config{},
		Requires: []plugin.Type{
			plugin.EventPlugin,
			plugin.ServicePlugin,
			plugin.RuntimePluginV2,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {

			return nil, nil
		}},
	)
}

type service struct {
}

// timer ticker running
func (s *service) run() {

}
