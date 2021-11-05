package server

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/containerd/containerd"
	criapi "github.com/containerd/containerd/api/services/dacscri/v1"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/pkg/dacscri/utils"
	"github.com/containerd/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	defaultImage = "baseruntime"
)

func (c *service) Run(ctx context.Context, req *criapi.RunContainerRequest) (*criapi.RunContainerResponse, error) {
	image := defaultImage
	if req.Image != "" {
		image = req.Image
	}
	// only use the containerd default namespace
	ns := namespaces.Default

	ctx = namespaces.WithNamespace(ctx, ns)

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	var (
		opts  []oci.SpecOpts
		cOpts []containerd.NewContainerOpts
		id    = utils.GenerateID()
	)

	dataStore, err := utils.GetDataStore()
	if err != nil {
		return nil, err
	}

	stateDir := filepath.Join(dataStore, "containers", ns, id)
	if err := c.os.MkdirAll(stateDir, 755); err != nil {
		return nil, err
	}

	opts = append(opts,
		oci.WithDefaultSpec(),
		oci.WithDefaultUnixDevices,
		WithoutRunMount(), // unmount default tmpfs on "/run": https://github.com/containerd/nerdctl/issues/157
	)

	if runtime.GOOS == "linux" {
		opts = append(opts,
			oci.WithMounts([]specs.Mount{
				{Type: "cgroup", Source: "cgroup", Destination: "/sys/fs/cgroup", Options: []string{"ro", "nosuid", "noexec", "nodev"}},
			}))
	}

	snapshotter := containerd.DefaultSnapshotter
	// pull image
	rootfsOpts, rootfsCOpts, ensuredImage, err := generateRootfsOpts(ctx, c.client, snapshotter, "", image, id)

	opts = append(opts, rootfsOpts...)
	cOpts = append(cOpts, rootfsCOpts...)

	return &criapi.RunContainerResponse{}, nil
}

func generateMountOpts() {

}

func generateRootfsOpts(ctx context.Context, client *containerd.Client, snapshotter, platform, image, id string) ([]oci.SpecOpts, []containerd.NewContainerOpts, *utils.EnsuredImage, error) {
	ocispecPlatform := []ocispec.Platform{platforms.DefaultSpec()}
	ensured, err := utils.EnsureImage(ctx, client, os.Stdout, snapshotter, image, "missing", false, ocispecPlatform)
	if err != nil {
		return nil, nil, nil, err
	}
	var (
		opts  []oci.SpecOpts
		cOpts []containerd.NewContainerOpts
	)

	cOpts = append(cOpts,
		containerd.WithImage(ensured.Image),
		containerd.WithSnapshotter(ensured.Snapshotter),
		containerd.WithNewSnapshot(id, ensured.Image),
		containerd.WithImageStopSignal(ensured.Image, "SIGTERM"),
	)

	if len(ensured.ImageConfig.Env) == 0 {
		opts = append(opts, oci.WithDefaultPathEnv)
	}
	for ind, env := range ensured.ImageConfig.Env {
		if strings.HasPrefix(env, "PATH=") {
			break
		} else {
			if ind == len(ensured.ImageConfig.Env)-1 {
				opts = append(opts, oci.WithDefaultPathEnv)
			}
		}
	}

	opts = append(opts, oci.WithImageConfigArgs(ensured.Image, []string{}))

	return opts, cOpts, ensured, nil
}

func WithoutRunMount() func(ctx context.Context, client oci.Client, c *containers.Container, s *oci.Spec) error {
	return oci.WithoutRunMount
}
