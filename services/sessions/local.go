package sessions

import (
	"context"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/services"

	api "github.com/containerd/containerd/api/services/sessions/v1"
	"google.golang.org/grpc"
)

func init() {
	plugin.Register(&plugin.Registration{
		Type:     plugin.ServicePlugin,
		ID:       services.SessionService,
		Requires: []plugin.Type{},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			return &local{}, nil
		},
	})
}

type local struct{}

var _ api.SessionsClient = &local{}

func (l *local) Auth(ctx context.Context, in *api.AuthRequest, opts ...grpc.CallOption) (*api.AuthResponse, error) {
	log.G(ctx).Logger.Infoln("todo: implement auth")
	return &api.AuthResponse{Token: "not implement yet"}, nil
}

func (l *local) RegisterSession(ctx context.Context, in *api.RegisterSessionRequest, opts ...grpc.CallOption) (*api.RegisterSessionResponse, error) {
	log.G(ctx).Logger.Infoln("todo: implement register session")
	return nil, nil
}

func (l *local) VerifyToken(ctx context.Context, in *api.VerifyTokenRequest, opts ...grpc.CallOption) (*api.VerifyTokenResponse, error) {
	log.G(ctx).Logger.Infoln("todo: implement verify token")
	return nil, nil
}

func (l *local) VerifySession(ctx context.Context, in *api.VerifySessionRequest, opts ...grpc.CallOption) (*api.VerifySessionResponse, error) {
	log.G(ctx).Logger.Infoln("todo: implement verify session")
	return nil, nil
}
