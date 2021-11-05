package utils

import (
	"context"
	"fmt"
	"regexp"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/images"
	refdocker "github.com/containerd/containerd/reference/docker"
)

type Found struct {
	Image      images.Image
	Req        string // The raw request string. name, short ID, or long ID.
	MatchIndex int    // Begins with 0, up to MatchCount - 1.
	MatchCount int    // 1 on exact match. > 1 on ambiguous match. Never be <= 0.
}

type OnFound func(ctx context.Context, found Found) error

type ImageWalker struct {
	Client  *containerd.Client
	OnFound OnFound
}

// Walk walks images and calls w.OnFound .
// Req is name, short ID, or long ID.
// Returns the number of the found entries.
func (w *ImageWalker) Walk(ctx context.Context, req string) (int, error) {
	var filters []string
	if canonicalRef, err := refdocker.ParseDockerRef(req); err == nil {
		filters = append(filters, fmt.Sprintf("name==%s", canonicalRef.String()))
	}
	filters = append(filters,
		fmt.Sprintf("target.digest~=^sha256:%s.*$", regexp.QuoteMeta(req)),
		fmt.Sprintf("target.digest~=^%s.*$", regexp.QuoteMeta(req)),
	)

	images, err := w.Client.ImageService().List(ctx, filters...)
	if err != nil {
		return -1, err
	}

	matchCount := len(images)
	for i, img := range images {
		f := Found{
			Image:      img,
			Req:        req,
			MatchIndex: i,
			MatchCount: matchCount,
		}
		if e := w.OnFound(ctx, f); e != nil {
			return -1, e
		}
	}
	return matchCount, nil
}
