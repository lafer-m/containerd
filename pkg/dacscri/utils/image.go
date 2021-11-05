package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/containerd/containerd"
	ctrcontent "github.com/containerd/containerd/cmd/ctr/commands/content"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/pkg/dacscri/dockerconfigresolver"
	"github.com/containerd/containerd/platforms"
	refdocker "github.com/containerd/containerd/reference/docker"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/imgcrypt"
	"github.com/containerd/imgcrypt/images/encryption"
	"github.com/containerd/stargz-snapshotter/fs/source"
	"github.com/docker/docker/errdefs"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type EnsuredImage struct {
	Ref         string
	Image       containerd.Image
	ImageConfig ocispec.ImageConfig
	Snapshotter string
	Remote      bool // true for stargz
}

// PullMode is either one of "always", "missing", "never"
type PullMode = string

// EnsureImage ensures the image.
//
// When insecure is set, skips verifying certs, and also falls back to HTTP when the registry does not speak HTTPS
func EnsureImage(ctx context.Context, client *containerd.Client, stdout io.Writer, snapshotter, rawRef string, mode PullMode, insecure bool, ocispecPlatforms []ocispec.Platform) (*EnsuredImage, error) {
	switch mode {
	case "always", "missing", "never":
		// NOP
	default:
		return nil, fmt.Errorf("unexpected pull mode: %q", mode)
	}

	if mode != "always" && len(ocispecPlatforms) == 1 {
		res, err := getExistingImage(ctx, client, snapshotter, rawRef, ocispecPlatforms[0])
		if err == nil {
			return res, nil
		}
		if !errdefs.IsNotFound(err) {
			return nil, err
		}
	}

	if mode == "never" {
		return nil, errors.Errorf("image %q is not available", rawRef)
	}

	named, err := refdocker.ParseDockerRef(rawRef)
	if err != nil {
		return nil, err
	}
	ref := named.String()
	refDomain := refdocker.Domain(named)

	var dOpts []dockerconfigresolver.Opt
	if insecure {
		logrus.Warnf("skipping verifying HTTPS certs for %q", refDomain)
		dOpts = append(dOpts, dockerconfigresolver.WithSkipVerifyCerts(true))
	}
	resolver, err := dockerconfigresolver.New(refDomain, dOpts...)
	if err != nil {
		return nil, err
	}

	img, err := pullImage(ctx, client, stdout, snapshotter, resolver, ref, ocispecPlatforms)
	if err != nil {
		if !IsErrHTTPResponseToHTTPSClient(err) {
			return nil, err
		}
		if insecure {
			logrus.WithError(err).Warnf("server %q does not seem to support HTTPS, falling back to plain HTTP", refDomain)
			dOpts = append(dOpts, dockerconfigresolver.WithPlainHTTP(true))
			resolver, err = dockerconfigresolver.New(refDomain, dOpts...)
			if err != nil {
				return nil, err
			}
			return pullImage(ctx, client, stdout, snapshotter, resolver, ref, ocispecPlatforms)
		} else {
			logrus.WithError(err).Errorf("server %q does not seem to support HTTPS", refDomain)
			logrus.Info("Hint: you may want to try --insecure-registry to allow plain HTTP (if you are in a trusted network)")
			return nil, err
		}
	}
	return img, nil
}

// IsErrHTTPResponseToHTTPSClient returns whether err is
// "http: server gave HTTP response to HTTPS client"
func IsErrHTTPResponseToHTTPSClient(err error) bool {
	// The error string is unexposed as of Go 1.16, so we can't use `errors.Is`.
	// https://github.com/golang/go/issues/44855
	const unexposed = "server gave HTTP response to HTTPS client"
	return strings.Contains(err.Error(), unexposed)
}

func pullImage(ctx context.Context, client *containerd.Client, stdout io.Writer, snapshotter string, resolver remotes.Resolver, ref string, ocispecPlatforms []ocispec.Platform) (*EnsuredImage, error) {
	ctx, done, err := client.WithLease(ctx)
	if err != nil {
		return nil, err
	}
	defer done(ctx)

	var containerdImage containerd.Image
	config := &Config{
		Resolver:       resolver,
		ProgressOutput: stdout,
		RemoteOpts:     []containerd.RemoteOpt{},
		Platforms:      ocispecPlatforms, // empty for all-platforms
	}

	var sgz bool
	// unpacking is possible only for single-platform mode
	if len(ocispecPlatforms) == 1 {
		logrus.Debugf("Single-platform mode. The image will be unpacked for platform %q, snapshotter %q.", ocispecPlatforms[0], snapshotter)
		imgcryptPayload := imgcrypt.Payload{}
		imgcryptUnpackOpt := encryption.WithUnpackConfigApplyOpts(encryption.WithDecryptedUnpack(&imgcryptPayload))
		config.RemoteOpts = append(config.RemoteOpts,
			containerd.WithPullUnpack,
			containerd.WithPullSnapshotter(snapshotter),
			containerd.WithUnpackOpts([]containerd.UnpackOpt{imgcryptUnpackOpt}))

		sgz = isStargz(snapshotter)
		if sgz {
			// TODO: support "skip-content-verify"
			config.RemoteOpts = append(
				config.RemoteOpts,
				containerd.WithImageHandlerWrapper(source.AppendDefaultLabelsHandlerWrapper(ref, 10*1024*1024)),
			)
		}
	} else {
		logrus.Debugf("Multi-platform mode. The image will not be unpacked. Platforms=%v.", ocispecPlatforms)
	}
	containerdImage, err = Pull(ctx, client, ref, config)
	if err != nil {
		return nil, err
	}
	imgConfig, err := getImageConfig(ctx, containerdImage)
	if err != nil {
		return nil, err
	}
	res := &EnsuredImage{
		Ref:         ref,
		Image:       containerdImage,
		ImageConfig: *imgConfig,
		Snapshotter: snapshotter,
		Remote:      sgz,
	}
	return res, nil

}

// Config for content fetch
type Config struct {
	// Resolver
	Resolver remotes.Resolver
	// ProgressOutput to display progress
	ProgressOutput io.Writer
	// RemoteOpts, e.g. containerd.WithPullUnpack.
	//
	// Regardless to RemoteOpts, the following opts are always set:
	// WithResolver, WithImageHandler, WithSchema1Conversion
	//
	// RemoteOpts related to unpacking can be set only when len(Platforms) is 1.
	RemoteOpts []containerd.RemoteOpt
	Platforms  []ocispec.Platform // empty for all-platforms
}

// Pull loads all resources into the content store and returns the image
func Pull(ctx context.Context, client *containerd.Client, ref string, config *Config) (containerd.Image, error) {
	ongoing := ctrcontent.NewJobs(ref)

	pctx, stopProgress := context.WithCancel(ctx)
	progress := make(chan struct{})

	go func() {
		if config.ProgressOutput != nil {
			// no progress bar, because it hides some debug logs
			ctrcontent.ShowProgress(pctx, ongoing, client.ContentStore(), config.ProgressOutput)
		}
		close(progress)
	}()

	h := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if desc.MediaType != images.MediaTypeDockerSchema1Manifest {
			ongoing.Add(desc)
		}
		return nil, nil
	})

	log.G(pctx).WithField("image", ref).Debug("fetching")
	platformMC := NewMatchComparerFromOCISpecPlatformSlice(config.Platforms)
	opts := []containerd.RemoteOpt{
		containerd.WithResolver(config.Resolver),
		containerd.WithImageHandler(h),
		containerd.WithSchema1Conversion,
		containerd.WithPlatformMatcher(platformMC),
	}
	opts = append(opts, config.RemoteOpts...)

	var (
		img containerd.Image
		err error
	)
	if len(config.Platforms) == 1 {
		// client.Pull is for single-platform (w/ unpacking)
		img, err = client.Pull(pctx, ref, opts...)
	} else {
		// client.Fetch is for multi-platform (w/o unpacking)
		var imagesImg images.Image
		imagesImg, err = client.Fetch(pctx, ref, opts...)
		img = containerd.NewImageWithPlatform(client, imagesImg, platformMC)
	}
	stopProgress()
	if err != nil {
		return nil, err
	}

	<-progress
	return img, nil
}

func NewMatchComparerFromOCISpecPlatformSlice(platformz []ocispec.Platform) platforms.MatchComparer {
	if len(platformz) == 0 {
		return platforms.All
	}
	return platforms.Ordered(platformz...)
}

func isStargz(sn string) bool {
	if !strings.Contains(sn, "stargz") {
		return false
	}
	if sn != "stargz" {
		logrus.Debugf("assuming %q to be a stargz-compatible snapshotter", sn)
	}
	return true
}

func getImageConfig(ctx context.Context, image containerd.Image) (*ocispec.ImageConfig, error) {
	desc, err := image.Config(ctx)
	if err != nil {
		return nil, err
	}
	switch desc.MediaType {
	case ocispec.MediaTypeImageConfig, images.MediaTypeDockerSchema2Config:
		var ocispecImage ocispec.Image
		b, err := content.ReadBlob(ctx, image.ContentStore(), desc)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(b, &ocispecImage); err != nil {
			return nil, err
		}
		return &ocispecImage.Config, nil
	default:
		return nil, errors.Errorf("unknown media type %q", desc.MediaType)
	}
}

// getExistingImage may return errdefs.NotFound()
func getExistingImage(ctx context.Context, client *containerd.Client, snapshotter, rawRef string, platform ocispec.Platform) (*EnsuredImage, error) {
	var res *EnsuredImage
	imagewalker := &ImageWalker{
		Client: client,
		OnFound: func(ctx context.Context, found Found) error {
			if res != nil {
				return nil
			}
			image := containerd.NewImageWithPlatform(client, found.Image, platforms.OnlyStrict(platform))
			imgConfig, err := getImageConfig(ctx, image)
			if err != nil {
				// Image found but blob not found for foreign arch
				// Ignore err and return nil, so that the walker can visit the next candidate.
				return nil
			}
			res = &EnsuredImage{
				Ref:         found.Image.Name,
				Image:       image,
				ImageConfig: *imgConfig,
				Snapshotter: snapshotter,
				Remote:      isStargz(snapshotter),
			}
			if unpacked, err := image.IsUnpacked(ctx, snapshotter); err == nil && !unpacked {
				if err := image.Unpack(ctx, snapshotter); err != nil {
					return err
				}
			}
			return nil
		},
	}
	count, err := imagewalker.Walk(ctx, rawRef)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errdefs.NotFound(fmt.Errorf("got count 0 after walking"))
	}
	if res == nil {
		return nil, errdefs.NotFound(fmt.Errorf("got nil res after walking"))
	}
	return res, nil
}
