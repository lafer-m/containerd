package server

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrInvalidParam    = status.Error(codes.InvalidArgument, "invalid param")
	ErrNoSuchContainer = status.Error(codes.NotFound, "no such container")
	ErrFindContainer   = status.Error(codes.Internal, "find container err")
	ErrNotFoundAKSK    = status.Error(codes.NotFound, "not found ak/sk")
)
