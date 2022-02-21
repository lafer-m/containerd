package health

import (
	"context"
	"fmt"
	"time"

	"github.com/containerd/containerd/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

type client struct {
	gcli    grpc_health_v1.HealthClient
	timeout time.Duration
}

func (c *client) check() State {
	state := UNKNOWN
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	resp, err := c.gcli.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		log.L.Warnf("health check failed err: %v", err)
		// if err == grpc.ErrClientConnTimeout {
		// 	state =
		// }
		return TIMEOUT
	}
	if resp.Status == grpc_health_v1.HealthCheckResponse_SERVING {
		state = OK
	} else {
		state = REJECT
	}
	return state
}

func newClient(endpoint string, timeout time.Duration) (*client, error) {
	gopts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithInsecure(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := grpc.DialContext(ctx, endpoint, gopts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s err: %v", endpoint, err)
	}
	gcli := grpc_health_v1.NewHealthClient(conn)

	cli := &client{
		gcli: gcli,
	}
	return cli, nil
}
