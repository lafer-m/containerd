package sessions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/services"
	"github.com/gogo/protobuf/proto"

	iapi "github.com/containerd/containerd/api/services/identities/v1"
	api "github.com/containerd/containerd/api/services/sessions/v1"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	BucketName       = "sessions"
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
			if err := db.Update(func(t *bolt.Tx) error {
				bk, err := t.CreateBucketIfNotExists([]byte(BucketName))
				if err != nil {
					return err
				}

				root := bk.Get([]byte(RootSessionIDKey))
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

			// for now just use
			var client iapi.UserIdentificationClient
			client = &backend{}
			cfg := ic.Config.(*SessionConfig)
			if cfg != nil {
				if cfg.IdentifyAddress == "" {
					cfg.IdentifyAddress = "127.0.0.1:8090"
				}
			}
			log.L.Infof("init session service config %s", cfg.String())
			if cfg.Debug {
				conn, err := ConnectToBackend(cfg)
				if err != nil {
					return nil, err
				}
				client = iapi.NewUserIdentificationClient(conn)
			}

			return &local{
				db:     db,
				client: client,
			}, nil
		},
	})
}

type local struct {
	db     *bolt.DB
	client iapi.UserIdentificationClient
}

var _ api.SessionsClient = &local{}

var (
	ErrInvalidParam          = status.Error(codes.InvalidArgument, "invalid param")
	ErrStoreInDB             = status.Error(codes.Internal, "store in bolt db error")
	ErrInvalidToken          = status.Error(codes.PermissionDenied, "invalid token, permission deny")
	ErrInvalidUserOrPassword = status.Error(codes.InvalidArgument, "invalid username or password")
	ErrInvalidSession        = status.Error(codes.InvalidArgument, "invalid session")
)

func (l *local) Auth(ctx context.Context, in *api.AuthRequest, opts ...grpc.CallOption) (*api.AuthResponse, error) {
	resp, err := l.client.Login(ctx, &iapi.LoginReq{Username: in.User.Username, Password: in.User.Password})
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
	if _, err := l.client.VerifyToken(ctx, &iapi.VerifyTokenReq{Username: in.Session.Username, Token: in.Session.Token}); err != nil {
		log.G(ctx).Errorf("verify token err: %v", err)
		return nil, ErrInvalidToken
	}

	if err := l.db.Update(func(t *bolt.Tx) error {
		bk := t.Bucket([]byte(BucketName))
		if in.Action == api.ACTION_REGISTER {
			s, err := proto.Marshal(in.Session)
			if err != nil {
				return err
			}
			if err := bk.Put([]byte(in.Session.ID), s); err != nil {
				return err
			}
		}

		if in.Action == api.ACTION_UNREGISTER {
			if err := bk.Delete([]byte(in.Session.ID)); err != nil {
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

func (l *local) VerifyToken(ctx context.Context, in *api.VerifyTokenRequest, opts ...grpc.CallOption) (*api.VerifyTokenResponse, error) {
	if in.Token == "" || in.Username == "" {
		return nil, ErrInvalidParam
	}

	if _, err := l.client.VerifyToken(ctx, &iapi.VerifyTokenReq{
		Token:    in.Token,
		Username: in.Username,
	}); err != nil {
		log.G(ctx).Errorf("verfiy token err: %v", err)
		return nil, err
	}

	return &api.VerifyTokenResponse{}, nil
}

func (l *local) VerifySession(ctx context.Context, in *api.VerifySessionRequest, opts ...grpc.CallOption) (*api.VerifySessionResponse, error) {
	if in.ID == "" {
		return nil, ErrInvalidParam
	}
	rootSession := ""
	if err := l.db.Update(func(t *bolt.Tx) error {
		bk := t.Bucket([]byte(BucketName))
		rootSession = string(bk.Get([]byte(RootSessionIDKey)))
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
		bk := t.Bucket([]byte(BucketName))
		session := bk.Get([]byte(in.ID))
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
	if _, err := l.client.VerifyToken(ctx, &iapi.VerifyTokenReq{Token: sess.Token, Username: sess.Username}); err != nil {
		if err := l.db.Update(func(t *bolt.Tx) error {
			bk := t.Bucket([]byte(BucketName))
			if err := bk.Delete([]byte(in.ID)); err != nil {
				return err
			}
			return nil
		}); err != nil {
			log.G(ctx).Errorf("del session err: %v", err)
		}
	}

	return &api.VerifySessionResponse{}, nil
}
