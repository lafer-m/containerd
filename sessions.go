package containerd

import (
	auth "github.com/containerd/containerd/api/services/auth/proto"
	api "github.com/containerd/containerd/api/services/sessions/v1"
)

type SessionClient interface {
	api.SessionsClient
	auth.ServiceAuthClient
	auth.UserIdentificationClient
	StoreAKSK(ak, sk, service string) error
	GetAKSKLocal(service string) (string, string, error)
}
