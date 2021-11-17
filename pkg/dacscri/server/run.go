package server

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/services/auth/proto"
	"github.com/containerd/containerd/api/services/dacscri/v1"
	criapi "github.com/containerd/containerd/api/services/dacscri/v1"
	"github.com/containerd/containerd/log"

	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/contrib/apparmor"
	"github.com/containerd/containerd/contrib/seccomp"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	pkgapparmor "github.com/containerd/containerd/pkg/apparmor"
	"github.com/containerd/containerd/pkg/dacscri/utils"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/runtime/restart"
	runcoptions "github.com/containerd/containerd/runtime/v2/runc/options"
	gocni "github.com/containerd/go-cni"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
)

const (
	defaultImage    = "baseruntime"
	encrptDir       = "encrpts"
	MagicArgv1      = "_NERDCTL_INTERNAL_LOGGING"
	nerdctl         = "/usr/bin/nerdctl"
	ServiceLabelKey = "com.dacs.service"
)

func (c *service) Run(ctx context.Context, req *criapi.RunContainerRequest) (*criapi.RunContainerResponse, error) {
	if err := checkParams(req); err != nil {
		return nil, err
	}

	ak, sk, err := c.getAKSK(req.Token, req.App.Type)
	if err != nil {
		log.G(ctx).Errorf("get ak/sk err: %v", err)
		return nil, ErrNotFoundAKSK
	}

	defer func() {
		if err := c.storeAKSK(ak, sk, req.App.Type); err != nil {
			log.G(ctx).Errorf("store ak/sk error")
		}
	}()

	// for http download app tar file
	downAppToken := signToken(sk, fmt.Sprintf("%s%d", "test", time.Now().Unix()))
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
	if err := c.os.MkdirAll(stateDir, 700); err != nil {
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
	mountOpts, err := generateMountOpts(ctx, c.client, ensuredImage, id, req, downAppToken)
	if err != nil {
		return nil, err
	}
	opts = append(opts, mountOpts...)

	var logURI string
	if lu, err := generateLogURI(dataStore); err != nil {
		return nil, err
	} else if lu != nil {
		logURI = lu.String()
	}

	// restartFlag := strings.ToLower(req.Restart.String())
	restartOpts, err := generateRestartOpts("no", logURI)
	if err != nil {
		return nil, err
	}
	cOpts = append(cOpts, restartOpts...)

	portSlice := req.Publish
	ports := make([]gocni.PortMapping, 0)
	// netType := CNI, for now only support cni

	netSlice := []string{"bridge"}

	{
		cniPath := "/opt/cni/bin"
		cniNetConfigPath := "/etc/cni/net.d"
		e := &utils.CNIEnv{
			Path:        cniPath,
			NetconfPath: cniNetConfigPath,
		}
		ll, err := utils.ConfigLists(e)
		if err != nil {
			return nil, err
		}

		for _, netstr := range netSlice {
			var netconflist *utils.NetworkConfigList
			for _, f := range ll {
				if f.Name == netstr {
					netconflist = f
					break
				}
			}
			if netconflist == nil {
				return nil, errors.Errorf("no such network: %q", netstr)
			}
		}

		resolvConfPath := filepath.Join(stateDir, "resolv.conf")

		conf, err := utils.Get()
		if err != nil {
			return nil, err
		}
		slirp4Dns := []string{}

		conf, err = utils.FilterResolvDNS(conf.Content, true)
		if err != nil {
			return nil, err
		}
		searchDomains := utils.GetSearchDomains(conf.Content)
		dnsOptions := utils.GetOptions(conf.Content)
		nameServers := []string{}
		if len(nameServers) == 0 {
			nameServers = utils.GetNameservers(conf.Content, utils.IPv4)
		}
		if _, err := utils.Build(resolvConfPath, append(slirp4Dns, nameServers...), searchDomains, dnsOptions); err != nil {
			return nil, err
		}
		// the content of /etc/hosts is created in OCI Hook
		etcHostsPath, err := utils.AllocHostsFile(dataStore, ns, id)
		if err != nil {
			return nil, err
		}
		opts = append(opts, withCustomResolvConf(resolvConfPath), withCustomHosts(etcHostsPath))
		for _, p := range portSlice {
			pm, err := utils.ParseFlagP(p)
			if err != nil {
				return nil, err
			}
			ports = append(ports, pm...)
		}

	}

	hostname := id[0:12]
	opts = append(opts, oci.WithHostname(hostname))

	if runtime.GOOS == "linux" {
		hostnamePath := filepath.Join(stateDir, "hostname")
		if err := os.WriteFile(hostnamePath, []byte(hostname+"\n"), 0644); err != nil {
			return nil, err
		}
		opts = append(opts, withCustomEtcHostname(hostnamePath))
	}

	hookOpt, err := withNerdctlOCIHook(id, stateDir)
	if err != nil {
		return nil, err
	}
	opts = append(opts, hookOpt)
	// cgroup only support cgroupfs
	// cgroup := "cgroupfs"
	// cgroupns := "host"
	opts = append(opts, oci.WithHostNamespace(specs.CgroupNamespace))
	opts = append(opts, seccomp.WithDefaultProfile())
	aaSupported := pkgapparmor.HostSupports()
	if aaSupported {
		opts = append(opts, apparmor.WithDefaultProfile("dacsctl-default"))
	}
	opts = append(opts, oci.WithNewPrivileges)

	cOpts = append(cOpts, generateRuntimeCopts()...)
	labels := map[string]string{}
	if req.App.Labels != nil {
		labels = req.App.Labels
	}
	labels[ServiceLabelKey] = req.App.Type
	lopts := containerd.WithAdditionalContainerLabels(labels)
	cOpts = append(cOpts, lopts)
	ilopts, err := withInternalLabels(ns, hostname, stateDir, netSlice, ports, logURI)

	cOpts = append(cOpts, ilopts)
	opts = append(opts, propagateContainerdLabelsToOCIAnnotations())
	var s specs.Spec
	spec := containerd.WithSpec(&s, opts...)
	cOpts = append(cOpts, spec)

	container, err := c.client.NewContainer(ctx, id, cOpts...)
	if err != nil {
		return nil, err
	}

	task, err := utils.NewTask(ctx, c.client, container, false, false, true, nil, logURI)
	if err != nil {
		return nil, err
	}

	if err := task.Start(ctx); err != nil {
		return nil, err
	}
	// fmt.Fprintf(cmd.OutOrStdout(), "%s\n", id)
	log.G(ctx).Infof("start container: %s", id)
	return &criapi.RunContainerResponse{
		Container: &criapi.Container{
			ID: container.ID(),
		},
	}, nil
}

// store
func (c *service) storeAKSK(ak, sk, service string) error {
	aksk := c.client.SessionClient()
	if err := aksk.StoreAKSK(ak, sk, service); err != nil {
		return err
	}
	return nil
}

func (c *service) getAKSK(token, service string) (string, string, error) {
	// found from backend
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req := &proto.GetAKSKReq{
		Token:     token,
		Timestamp: time.Now().Unix(),
	}
	resp, err := c.client.SessionClient().GetServiceAKSK(ctx, req)
	if err != nil {
		log.G(ctx).Errorf("get ak/sk err: %v", err)
		return "", "", ErrNotFoundAKSK
	}

	return resp.AccessKeyId, resp.SecretAccessKey, nil
}

func signToken(sk, data string) string {
	mac := hmac.New(md5.New, []byte(sk))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum([]byte("")))
}

func checkParams(req *criapi.RunContainerRequest) error {
	if req.App == nil {
		return ErrInvalidParam
	}
	if req.App.Type == "" {
		return ErrInvalidParam
	}
	if req.App.TarUrl == "" {
		return ErrInvalidParam
	}
	if len(req.Publish) == 0 {
		return ErrInvalidParam
	}
	if req.Token == "" {
		return ErrInvalidParam
	}
	return nil
}

func propagateContainerdLabelsToOCIAnnotations() oci.SpecOpts {
	return func(ctx context.Context, oc oci.Client, c *containers.Container, s *oci.Spec) error {
		return oci.WithAnnotations(c.Labels)(ctx, oc, c, s)
	}
}

func withInternalLabels(ns, hostname, containerStateDir string, networks []string, ports []gocni.PortMapping, logURI string) (containerd.NewContainerOpts, error) {
	m := make(map[string]string)
	m[utils.Namespace] = ns
	m[utils.Hostname] = hostname
	m[utils.StateDir] = containerStateDir
	str, _ := json.Marshal([]string{})
	m[utils.ExtraHosts] = string(str)
	networksJSON, err := json.Marshal(networks)
	if err != nil {
		return nil, err
	}
	m[utils.Networks] = string(networksJSON)
	if len(ports) > 0 {
		portsJSON, err := json.Marshal(ports)
		if err != nil {
			return nil, err
		}
		m[utils.Ports] = string(portsJSON)
	}
	if logURI != "" {
		m[utils.LogURI] = logURI
	}

	m[utils.Platform] = platforms.DefaultString()
	return containerd.WithAdditionalContainerLabels(m), nil
}

func generateRuntimeCopts() []containerd.NewContainerOpts {
	runtime := plugin.RuntimeRuncV2
	var (
		runcOpts    runcoptions.Options
		runtimeOpts interface{} = &runcOpts
	)
	runcOpts.BinaryName = "runsc"
	o := containerd.WithRuntime(runtime, runtimeOpts)
	return []containerd.NewContainerOpts{o}
}

func generateRestartOpts(restartFlag, logURI string) ([]containerd.NewContainerOpts, error) {
	switch restartFlag {
	case "", "no":
		return nil, nil
	case "always":
		opts := []containerd.NewContainerOpts{restart.WithStatus(containerd.Running)}
		if logURI != "" {
			opts = append(opts, restart.WithLogURIString(logURI))
		}
		return opts, nil
	default:
		return nil, errors.Errorf("unsupported restart type %q, supported types are: \"no\",  \"always\"", restartFlag)
	}
}

func generateLogURI(dataStore string) (*url.URL, error) {
	args := map[string]string{
		MagicArgv1: dataStore,
	}
	return cio.LogURIGenerator("binary", nerdctl, args)
}

func generateMountOpts(ctx context.Context, client *containerd.Client, ensuredImage *utils.EnsuredImage, id string, req *criapi.RunContainerRequest, token string) ([]oci.SpecOpts, error) {
	//nolint:golint,prealloc
	var (
		opts []oci.SpecOpts
	)
	var tempDir string

	if ensuredImage != nil {
		snapshotter := containerd.DefaultSnapshotter
		diffIDs, err := ensuredImage.Image.RootFS(ctx)
		if err != nil {
			return nil, err
		}
		chainID := identity.ChainID(diffIDs).String()

		s := client.SnapshotService(snapshotter)
		tempDir, err = ioutil.TempDir("", "initialC")
		if err != nil {
			return nil, err
		}
		// We use Remove here instead of RemoveAll.
		// The RemoveAll will delete the temp dir and all children it contains.
		// When the Unmount fails, RemoveAll will incorrectly delete data from the mounted dir
		defer os.Remove(tempDir)

		var mounts []mount.Mount
		mounts, err = s.View(ctx, tempDir, chainID)
		if err != nil {
			return nil, err
		}

		// We should do defer first, if not we will not do Unmount when only a part of Mounts are failed.
		defer func() {
			err = mount.UnmountAll(tempDir, 0)
		}()

		if err := mount.All(mounts, tempDir); err != nil {
			if err := s.Remove(ctx, tempDir); err != nil && !errdefs.IsNotFound(err) {
				return nil, err
			}
			return nil, err
		}
	}

	encrpts, err := ensureEncrpts(id, req)
	if err != nil {
		return nil, err
	}

	opts = append(opts, oci.WithMounts([]specs.Mount{encrpts}))
	return opts, nil
}

// ensureEncrpts mount encrpt file systems
func ensureEncrpts(id string, req *criapi.RunContainerRequest) (specs.Mount, error) {
	var mt specs.Mount
	dataStore, err := utils.GetDataStore()
	if err != nil {
		return mt, err
	}

	encrptPath := filepath.Join(dataStore, encrptDir, namespaces.Default, id)
	if err := os.MkdirAll(encrptPath, 700); err != nil {
		return mt, err
	}
	// TODO should mount encrptPath filesystem

	// TODO download app files and mount encrpt filesystem in here
	if req.App.TarType == dacscri.TARTYPE_FILE {
		src, err := os.Open(req.App.TarUrl)
		if err != nil {
			return mt, err
		}

		defer src.Close()
		splits := strings.Split(req.App.TarUrl, "/")
		dst, err := os.OpenFile(filepath.Join(encrptPath, splits[len(splits)-1]), os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return mt, err
		}
		defer dst.Close()
		if _, err := io.Copy(dst, src); err != nil {
			return mt, err
		}
	} else {
		// should download here
	}

	mt = specs.Mount{
		Type:        "none",
		Destination: "/root/app",
		Source:      encrptPath,
		Options: []string{
			"rprivate",
			"rbind",
		},
	}
	return mt, nil
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

func withCustomResolvConf(src string) func(context.Context, oci.Client, *containers.Container, *oci.Spec) error {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		s.Mounts = append(s.Mounts, specs.Mount{
			Destination: "/etc/resolv.conf",
			Type:        "bind",
			Source:      src,
			Options:     []string{"bind", "rprivate"}, // writable
		})
		return nil
	}
}

func withCustomEtcHostname(src string) func(context.Context, oci.Client, *containers.Container, *oci.Spec) error {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		s.Mounts = append(s.Mounts, specs.Mount{
			Destination: "/etc/hostname",
			Type:        "bind",
			Source:      src,
			Options:     []string{"bind", "rprivate"}, // writable
		})
		return nil
	}
}

func withCustomHosts(src string) func(context.Context, oci.Client, *containers.Container, *oci.Spec) error {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		s.Mounts = append(s.Mounts, specs.Mount{
			Destination: "/etc/hosts",
			Type:        "bind",
			Source:      src,
			Options:     []string{"bind", "rprivate"}, // writable
		})
		return nil
	}
}

func withNerdctlOCIHook(id, stateDir string) (oci.SpecOpts, error) {
	selfExe := nerdctl
	args := append([]string{selfExe, "internal", "oci-hook"})
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *specs.Spec) error {
		if s.Hooks == nil {
			s.Hooks = &specs.Hooks{}
		}
		crArgs := append(args, "createRuntime")
		s.Hooks.Prestart = append(s.Hooks.CreateRuntime, specs.Hook{
			Path: selfExe,
			Args: crArgs,
			Env:  os.Environ(),
		})
		argsCopy := append([]string(nil), args...)
		psArgs := append(argsCopy, "postStop")
		s.Hooks.Poststop = append(s.Hooks.Poststop, specs.Hook{
			Path: selfExe,
			Args: psArgs,
			Env:  os.Environ(),
		})
		return nil
	}, nil
}
