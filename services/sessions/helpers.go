package sessions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	api "github.com/containerd/containerd/api/services/auth/v1"
	auth "github.com/containerd/containerd/api/services/auth/v1"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/pkg/dialer"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
)

// Sessions provides configuration for sessions
type SessionConfig struct {
	IdentifyAddress string `toml:"identify_address"`
	TLSCA           string `toml:"tls_ca"`
	TLSCert         string `toml:"tls_cert"`
	TLSKey          string `toml:"tls_key"`
	MaxRecvMsgSize  int    `toml:"max_recv_message_size"`
	MaxSendMsgSize  int    `toml:"max_send_message_size"`
	Debug           bool   `toml:"debug"`
}

func (s *SessionConfig) String() string {
	ct := &strings.Builder{}
	ct.WriteString(fmt.Sprintf("backend address %s\n", s.IdentifyAddress))
	ct.WriteString(fmt.Sprintf("tls files ca: %s, cert: %s, key: %s\n", s.TLSCA, s.TLSCert, s.TLSKey))
	return ct.String()
}

var _ api.UserIdentificationClient = &backend{}

type backend struct {
}

func (b *backend) Login(ctx context.Context, in *api.LoginReq, opts ...grpc.CallOption) (*api.LoginResp, error) {
	return &api.LoginResp{Token: "xxxxxxxxxxx"}, nil
}

func (b *backend) Logout(ctx context.Context, in *api.LogoutReq, opts ...grpc.CallOption) (*api.LogoutResp, error) {
	return &api.LogoutResp{}, nil
}

func (b *backend) VerifyToken(ctx context.Context, in *api.VerifyTokenReq, opts ...grpc.CallOption) (*api.VerifyTokenResp, error) {
	return &api.VerifyTokenResp{}, nil
}

type aksk struct {
}

func (l *aksk) GetServiceAKSK(ctx context.Context, in *auth.GetAKSKReq, opts ...grpc.CallOption) (*auth.GetAKSKResp, error) {
	return &auth.GetAKSKResp{
		AccessKeyId:     "abcd",
		SecretAccessKey: "bcde",
	}, nil
}

func (l *aksk) VerifyServiceAKSK(ctx context.Context, in *auth.VerifyAKSKReq, opts ...grpc.CallOption) (*auth.VerifyASKSResp, error) {
	return &auth.VerifyASKSResp{}, nil
}

// for now without tls
func ConnectToBackend(cfg *SessionConfig) (*grpc.ClientConn, error) {
	backoffConfig := backoff.DefaultConfig
	backoffConfig.MaxDelay = 3 * time.Second
	connParams := grpc.ConnectParams{
		Backoff: backoffConfig,
	}

	gopts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithInsecure(),
		grpc.FailOnNonTempDialError(true),
		grpc.WithConnectParams(connParams),
		grpc.WithContextDialer(dialer.ContextDialer),
		grpc.WithReturnConnectionError(),

		// TODO(stevvooe): We may need to allow configuration of this on the client.
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(defaults.DefaultMaxRecvMsgSize)),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(defaults.DefaultMaxSendMsgSize)),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, cfg.IdentifyAddress, gopts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to dial %q", cfg.IdentifyAddress)
	}
	return conn, nil
}

const IDLength = 64

func GenerateID() string {
	bytesLength := IDLength / 2
	b := make([]byte, bytesLength)
	n, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	if n != bytesLength {
		panic(errors.Errorf("expected %d bytes, got %d bytes", bytesLength, n))
	}
	return hex.EncodeToString(b)
}
