package sessions

import (
	"context"
	"errors"

	"github.com/containerd/containerd"
	api "github.com/containerd/containerd/api/services/sessions/v1"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/services"
	"google.golang.org/grpc"
)

func init() {
	plugin.Register(&plugin.Registration{
		Type:     plugin.GRPCPlugin,
		ID:       "sessions",
		Requires: []plugin.Type{plugin.ServicePlugin},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			plugins, err := ic.GetByType(plugin.ServicePlugin)
			if err != nil {
				return nil, err
			}
			p, ok := plugins[services.SessionService]
			if !ok {
				return nil, errors.New("sessions service not found")
			}
			i, err := p.Instance()
			if err != nil {
				return nil, err
			}
			return &service{local: i.(containerd.SessionClient)}, nil
		},
	})
}

type service struct {
	local containerd.SessionClient
}

var _ api.SessionsServer = &service{}

func (s *service) Register(server *grpc.Server) error {
	api.RegisterSessionsServer(server, s)
	return nil
}

func (s *service) Auth(ctx context.Context, req *api.AuthRequest) (*api.AuthResponse, error) {
	return s.local.Auth(ctx, req)
}

func (s *service) RegisterSession(ctx context.Context, req *api.RegisterSessionRequest) (*api.RegisterSessionResponse, error) {
	return s.local.RegisterSession(ctx, req)
}

func (s *service) VerifySession(ctx context.Context, req *api.VerifySessionRequest) (*api.VerifySessionResponse, error) {
	return s.local.VerifySession(ctx, req)
}
