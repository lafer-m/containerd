package server

import (
	"github.com/containerd/containerd"
	criapi "github.com/containerd/containerd/api/services/dacscri/v1"
	"github.com/containerd/containerd/pkg/dacscri/config"
	"github.com/containerd/containerd/pkg/netlink"
	osinterface "github.com/containerd/containerd/pkg/os"
	"google.golang.org/grpc"
)

type service struct {
	config *config.Config
	// client is an instance of the containerd client
	client *containerd.Client
	// os is an interface for all required os operations.
	os osinterface.OS
	// healthServer
	health *healthService
	//
	linkCli *netlink.DACSNetlinkClient
}

func NewService(cfg *config.Config, client *containerd.Client, linkCli *netlink.DACSNetlinkClient) *service {
	return &service{
		config:  cfg,
		client:  client,
		os:      osinterface.RealOS{},
		health:  newHealthService(),
		linkCli: linkCli,
	}
}

func (c *service) RegisterTCP(s *grpc.Server) error {
	criapi.RegisterDacsCRIServer(s, c)
	c.health.Register(s)
	return nil
}
