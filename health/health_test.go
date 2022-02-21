package health

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/health/grpc_health_v1"
)

func Test_GrpcHealthCheck(t *testing.T) {
	client, err := newClient("127.0.0.1:8089", 10*time.Second)
	if err != nil {
		panic(err)
	}
	resp, err := client.gcli.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		panic(err)
	}
	t.Fatal(resp)
}

func Test_duration(t *testing.T) {
	t1 := "10ms"
	tp1, err := time.ParseDuration(t1)
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("ttt: ", int(tp1))
}
