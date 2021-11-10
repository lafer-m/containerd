package server

import (
	"context"

	criapi "github.com/containerd/containerd/api/services/dacscri/v1"
	"github.com/containerd/containerd/namespaces"
)

func (c *service) List(ctx context.Context, req *criapi.ListContainersRequest) (*criapi.ListContainersResponse, error) {
	client := c.client

	ctx = namespaces.WithNamespace(ctx, "default")
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	resp, err := client.ContainerService().List(ctx, req.Filters...)
	if err != nil {
		return nil, err
	}

	containers := []criapi.Container{}
	for _, ct := range resp {
		container := criapi.Container{
			ID:     ct.ID,
			Labels: ct.Labels,
			Image:  ct.Image,
			Runtime: &criapi.Container_Runtime{
				Name:    ct.Runtime.Name,
				Options: ct.Runtime.Options,
			},
			Spec:      ct.Spec,
			CreatedAt: ct.CreatedAt,
			UpdatedAt: ct.UpdatedAt,
		}
		containers = append(containers, container)
	}

	return &criapi.ListContainersResponse{
		Containers: containers,
	}, nil
}
