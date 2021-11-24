package sessions

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/pkg/aesutil"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/services"
	"github.com/gogo/protobuf/proto"

	auth "github.com/containerd/containerd/api/services/auth/proto"
	api "github.com/containerd/containerd/api/services/sessions/v1"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	versionInt       = 1
	version          = "v1"
	BucketName       = "sessions"
	serviceBucket    = "services"
	RootSessionIDKey = "root-session"
)

func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.ServicePlugin,
		ID:   services.SessionService,
		Requires: []plugin.Type{
			plugin.MetadataPlugin,
		},
		Config: &SessionConfig{},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			if err := os.MkdirAll(ic.Root, 0711); err != nil {
				return nil, err
			}
			path := filepath.Join(ic.Root, "sessions.db")
			db, err := bolt.Open(path, 755, nil)
			if err != nil {
				return nil, err
			}

			// create buckets
			// db schema, just one bucket with keys/values
			// keys.
			//  ├──version : <varint>
			//  └──v1
			//     ╘══*sessions*                    -- sessions bucket
			//        |══*sessionID* : <string>                 -
			//     ╘══*services*                    -- service bucket
			//        │══*service name*: <ak-sk>
			if err := db.Update(func(t *bolt.Tx) error {
				bk, err := t.CreateBucketIfNotExists([]byte(version))
				if err != nil {
					return err
				}
				sessionBK, err := bk.CreateBucketIfNotExists([]byte(BucketName))
				if err != nil {
					return err
				}
				_, err = bk.CreateBucketIfNotExists([]byte(serviceBucket))
				if err != nil {
					return err
				}

				root := sessionBK.Get([]byte(RootSessionIDKey))
				if len(root) == 0 {
					rootSessionID := fmt.Sprintf("%s%s", "root-", GenerateID()[:19])
					if err := bk.Put([]byte(RootSessionIDKey), []byte(rootSessionID)); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				return nil, err
			}
			// TODO add gc, maybe not needed.

			local := &local{
				db: db,
			}
			// for now just use
			cfg := ic.Config.(*SessionConfig)
			if cfg != nil {
				if cfg.IdentifyAddress == "" {
					cfg.IdentifyAddress = "127.0.0.1:8090"
				}
			}
			log.L.Infof("init session service config %s", cfg.String())
			if cfg.Debug {
				local.identifyAuth = &backend{}
				local.akskAuth = &aksk{}
				local.policy = &policy{}
			} else {
				conn, err := ConnectToBackend(cfg)
				if err != nil {
					return nil, err
				}

				local.akskAuth = auth.NewServiceAuthClient(conn)
				local.identifyAuth = auth.NewUserIdentificationClient(conn)
				local.policy = auth.NewPolicyClient(conn)
			}
			return local, nil
		},
	})
}

type local struct {
	db           *bolt.DB
	akskAuth     auth.ServiceAuthClient
	identifyAuth auth.UserIdentificationClient
	policy       auth.PolicyClient
}

var _ containerd.SessionClient = &local{}

var (
	ErrInvalidParam          = status.Error(codes.InvalidArgument, "invalid param")
	ErrStoreInDB             = status.Error(codes.Internal, "store in bolt db error")
	ErrInvalidToken          = status.Error(codes.PermissionDenied, "invalid token, permission deny")
	ErrInvalidUserOrPassword = status.Error(codes.InvalidArgument, "invalid username or password")
	ErrInvalidSession        = status.Error(codes.InvalidArgument, "invalid session")
)

func (l *local) Auth(ctx context.Context, in *api.AuthRequest, opts ...grpc.CallOption) (*api.AuthResponse, error) {
	if in.User == nil {
		return nil, ErrInvalidParam
	}
	resp, err := l.identifyAuth.Login(ctx, &auth.LoginReq{Username: in.User.Username, Password: in.User.Password, Timestamp: time.Now().Unix()})
	if err != nil {
		log.G(ctx).Errorf("session login err: %v", err)
		return nil, ErrInvalidUserOrPassword
	}
	return &api.AuthResponse{Token: resp.Token}, nil
}

func (l *local) RegisterSession(ctx context.Context, in *api.RegisterSessionRequest, opts ...grpc.CallOption) (*api.RegisterSessionResponse, error) {
	if in.Session == nil {
		return nil, ErrInvalidParam
	}

	if in.Session.ID == "" || in.Session.Username == "" || in.Session.Token == "" {
		return nil, ErrInvalidParam
	}

	// verify token
	if _, err := l.identifyAuth.VerifyToken(ctx, &auth.VerifyTokenReq{Username: in.Session.Username, Token: in.Session.Token, Timestamp: time.Now().Unix()}); err != nil {
		log.G(ctx).Errorf("verify token err: %v", err)
		return nil, ErrInvalidToken
	}

	if err := l.db.Update(func(t *bolt.Tx) error {
		bk := t.Bucket([]byte(version))
		sessionBK := bk.Bucket([]byte(BucketName))
		if in.Action == api.ACTION_REGISTER {
			s, err := proto.Marshal(in.Session)
			if err != nil {
				return err
			}
			if err := sessionBK.Put([]byte(in.Session.ID), s); err != nil {
				return err
			}
		}

		if in.Action == api.ACTION_UNREGISTER {
			if err := sessionBK.Delete([]byte(in.Session.ID)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		log.G(ctx).Errorf("%s sessions err: %v", in.Action.String(), err)
		return nil, err
	}

	return &api.RegisterSessionResponse{}, nil
}

func (l *local) VerifySession(ctx context.Context, in *api.VerifySessionRequest, opts ...grpc.CallOption) (*api.VerifySessionResponse, error) {
	if in.ID == "" {
		return nil, ErrInvalidParam
	}
	rootSession := ""
	if err := l.db.Update(func(t *bolt.Tx) error {
		bk := t.Bucket([]byte(version))
		sessionBK := bk.Bucket([]byte(BucketName))
		rootSession = string(sessionBK.Get([]byte(RootSessionIDKey)))
		return nil
	}); err != nil {
		log.G(ctx).Errorf("get session err: %v", err)
		return nil, err
	}

	// root session just have all permissions
	if rootSession == in.ID {
		return &api.VerifySessionResponse{}, nil
	}

	sess := &api.Session{}
	if err := l.db.Update(func(t *bolt.Tx) error {
		bk := t.Bucket([]byte(version))
		sessionBK := bk.Bucket([]byte(BucketName))
		session := sessionBK.Get([]byte(in.ID))
		if err := proto.Unmarshal(session, sess); err != nil {
			return err
		}
		return nil
	}); err != nil {
		log.G(ctx).Errorf("get session err: %v", err)
		return nil, err
	}

	if sess.Token == "" || sess.ID == "" || sess.ID != in.ID {
		return nil, ErrInvalidSession
	}

	// check token again, if err just delete the session in boltdb
	if _, err := l.identifyAuth.VerifyToken(ctx, &auth.VerifyTokenReq{Token: sess.Token, Username: sess.Username, Timestamp: time.Now().Unix()}); err != nil {
		if err := l.db.Update(func(t *bolt.Tx) error {
			bk := t.Bucket([]byte(version))
			sessionBK := bk.Bucket([]byte(BucketName))
			if err := sessionBK.Delete([]byte(in.ID)); err != nil {
				return err
			}
			return nil
		}); err != nil {
			log.G(ctx).Errorf("del session err: %v", err)
		}
	}

	return &api.VerifySessionResponse{}, nil
}

// client proxy
func (l *local) FetchPolicy(ctx context.Context, in *auth.FetchPolicyReq, opts ...grpc.CallOption) (*auth.FetchPolicyResp, error) {
	return l.policy.FetchPolicy(ctx, in)
}

func (l *local) GetServiceAKSK(ctx context.Context, in *auth.GetAKSKReq, opts ...grpc.CallOption) (*auth.GetAKSKResp, error) {
	return l.akskAuth.GetServiceAKSK(ctx, in)
}

func (l *local) VerifyServiceAKSK(ctx context.Context, in *auth.VerifyAKSKReq, opts ...grpc.CallOption) (*auth.VerifyASKSResp, error) {
	return l.akskAuth.VerifyServiceAKSK(ctx, in)
}

func (l *local) Login(ctx context.Context, in *auth.LoginReq, opts ...grpc.CallOption) (*auth.LoginResp, error) {
	return l.identifyAuth.Login(ctx, in)
}

func (l *local) Logout(ctx context.Context, in *auth.LogoutReq, opts ...grpc.CallOption) (*auth.LogoutResp, error) {
	return l.identifyAuth.Logout(ctx, in)
}

func (l *local) VerifyToken(ctx context.Context, in *auth.VerifyTokenReq, opts ...grpc.CallOption) (*auth.VerifyTokenResp, error) {
	return l.identifyAuth.VerifyToken(ctx, in)
}

func (l *local) StoreAKSK(ak, sk, service string) error {
	akE, err := aesutil.AesEncrypt([]byte(ak))
	if err != nil {
		return err
	}

	skE, err := aesutil.AesEncrypt([]byte(sk))
	if err != nil {
		return err
	}

	value := fmt.Sprintf("%s-%s", akE, skE)
	if err := l.db.Update(func(t *bolt.Tx) error {
		bk := t.Bucket([]byte(version)).Bucket([]byte(serviceBucket))
		if err := bk.Put([]byte(service), []byte(value)); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (l *local) DeleteAKSKLocal(service string) error {
	return l.db.Update(func(t *bolt.Tx) error {
		bk := t.Bucket([]byte(version)).Bucket([]byte(serviceBucket))
		return bk.Delete([]byte(service))
	})
}

func (l *local) GetAKSKLocal(service string) (string, string, error) {
	ak, sk := "", ""
	var err error

	if err := l.db.Update(func(t *bolt.Tx) error {
		bk := t.Bucket([]byte(version)).Bucket([]byte(serviceBucket))
		val := bk.Get([]byte(service))
		split := strings.Split(string(val), "-")
		if len(split) == 2 {
			ak = split[0]
			sk = split[1]
		}
		return nil
	}); err != nil {
		return ak, sk, err
	}

	if ak != "" && sk != "" {
		a, _ := hex.DecodeString(ak)
		ak, err = aesutil.AesDecrypt([]byte(a))
		if err != nil {
			return "", "", err
		}
		s, _ := hex.DecodeString(sk)
		sk, err = aesutil.AesDecrypt([]byte(s))
		if err != nil {
			return "", "", err
		}
	}

	return ak, sk, nil
}

func (l *local) ListService() ([]string, error) {
	svcs := []string{}
	if err := l.db.Update(func(t *bolt.Tx) error {
		bk := t.Bucket([]byte(version)).Bucket([]byte(serviceBucket))
		if err := bk.ForEach(func(k, v []byte) error {
			svcs = append(svcs, string(k))
			return nil
		}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return svcs, nil
}
