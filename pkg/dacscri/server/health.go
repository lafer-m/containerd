package server

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

type healthService struct {
	serve *health.Server
}

func newHealthService() *healthService {
	return &healthService{
		health.NewServer(),
	}
}

func (s *healthService) Register(server *grpc.Server) error {
	grpc_health_v1.RegisterHealthServer(server, s.serve)
	return nil
}
