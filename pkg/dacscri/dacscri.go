package dacscri

import (
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/pkg/dacscri/config"
	"github.com/containerd/containerd/pkg/dacscri/server"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/plugin"
)

func init() {

	plugin.Register(&plugin.Registration{
		Type:   plugin.GRPCPlugin,
		ID:     "dacscri",
		Config: config.DefaultConfig(),
		Requires: []plugin.Type{
			plugin.EventPlugin,
			plugin.ServicePlugin,
		},
		InitFn: initDacsCRIService,
	})

}

func initDacsCRIService(ic *plugin.InitContext) (interface{}, error) {
	cfg := ic.Config.(*config.Config)

	var clientOpts []containerd.ClientOpt
	clientOpts = append(clientOpts, containerd.WithDefaultPlatform(platforms.Default()))

	client, err := containerd.New("", clientOpts...)
	if err != nil {
		return nil, err
	}

	return server.NewService(cfg, client), nil
}
