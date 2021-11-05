package server

import (
	"context"

	criapi "github.com/containerd/containerd/api/services/dacscri/v1"
	"github.com/gogo/protobuf/types"
)

func (c *service) Remove(context.Context, *criapi.RemoveContainerRequest) (*types.Empty, error) {

	return &types.Empty{}, nil
}
