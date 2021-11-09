package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/errdefs"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/sirupsen/logrus"
)

const (
	// hostsDirBasename is the base name of /var/lib/nerdctl/<ADDRHASH>/etchosts
	hostsDirBasename = "etchosts"
	// metaJSON is stored as /var/lib/nerdctl/<ADDRHASH>/etchosts/<NS>/<ID>/meta.json
	metaJSON = "meta.json"
)

// HostsPath returns "/var/lib/nerdctl/<ADDRHASH>/etchosts/<NS>/<ID>/hosts"
func HostsPath(dataStore, ns, id string) string {
	if dataStore == "" || ns == "" || id == "" {
		panic(errdefs.ErrInvalidArgument)
	}
	return filepath.Join(dataStore, hostsDirBasename, ns, id, "hosts")
}

// ensureFile ensures a file with permission 0644.
// The file is initialized with no content.
// The dir (if not exists) is created with permission 0700.
func ensureFile(path string) error {
	if path == "" {
		return errdefs.ErrInvalidArgument
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE, 0644)
	if err != nil {
		f.Close()
	}
	return err
}

// AllocHostsFile is used for creating mount-bindable /etc/hosts file.
// The file is initialized with no content.
func AllocHostsFile(dataStore, ns, id string) (string, error) {
	lockDir := filepath.Join(dataStore, hostsDirBasename)
	if err := os.MkdirAll(lockDir, 0700); err != nil {
		return "", err
	}
	path := HostsPath(dataStore, ns, id)
	fn := func() error {
		return ensureFile(path)
	}
	err := WithDirLock(lockDir, fn)
	return path, err
}

func DeallocHostsFile(dataStore, ns, id string) error {
	lockDir := filepath.Join(dataStore, hostsDirBasename)
	if err := os.MkdirAll(lockDir, 0700); err != nil {
		return err
	}
	dirToBeRemoved := filepath.Dir(HostsPath(dataStore, ns, id))
	fn := func() error {
		return os.RemoveAll(dirToBeRemoved)
	}
	return WithDirLock(lockDir, fn)
}

func NewStore(dataStore string) (Store, error) {
	store := &store{
		dataStore: dataStore,
		hostsD:    filepath.Join(dataStore, hostsDirBasename),
	}
	return store, os.MkdirAll(store.hostsD, 0700)
}

type Meta struct {
	Namespace  string
	ID         string
	Networks   map[string]*types100.Result
	Hostname   string
	ExtraHosts []string
	Name       string
}

type Store interface {
	Acquire(Meta) error
	Release(ns, id string) error
}

type store struct {
	// dataStore is /var/lib/nerdctl/<ADDRHASH>
	dataStore string
	// hostsD is /var/lib/nerdctl/<ADDRHASH>/etchosts
	hostsD string
}

func (x *store) Acquire(meta Meta) error {
	fn := func() error {
		hostsPath := HostsPath(x.dataStore, meta.Namespace, meta.ID)
		if err := ensureFile(hostsPath); err != nil {
			return err
		}
		metaB, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		metaPath := filepath.Join(x.hostsD, meta.Namespace, meta.ID, metaJSON)
		if err := ioutil.WriteFile(metaPath, metaB, 0644); err != nil {
			return err
		}
		return newUpdater(x.hostsD, meta.ExtraHosts).update()
	}
	return WithDirLock(x.hostsD, fn)
}

func (x *store) Release(ns, id string) error {
	fn := func() error {
		metaPath := filepath.Join(x.hostsD, ns, id, metaJSON)
		if _, err := os.Stat(metaPath); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		// We remove "meta.json" but we still retain the "hosts" file
		// because it is needed for restarting. The "hosts" is removed on
		// `nerdctl rm`.
		// https://github.com/rootless-containers/rootlesskit/issues/220#issuecomment-783224610
		if err := os.RemoveAll(metaPath); err != nil {
			return err
		}
		return newUpdater(x.hostsD, nil).update()
	}
	return WithDirLock(x.hostsD, fn)
}

// newUpdater creates an updater for hostsD (/var/lib/nerdctl/<ADDRHASH>/etchosts)
func newUpdater(hostsD string, extraHosts []string) *updater {
	u := &updater{
		hostsD:        hostsD,
		metaByIPStr:   make(map[string]*Meta),
		nwNameByIPStr: make(map[string]string),
		metaByDir:     make(map[string]*Meta),
		extraHosts:    extraHosts,
	}
	return u
}

// updater is the struct for updater.update()
type updater struct {
	hostsD        string            // "/var/lib/nerdctl/<ADDRHASH>/etchosts"
	metaByIPStr   map[string]*Meta  // key: IP string
	nwNameByIPStr map[string]string // key: IP string, value: key of Meta.Networks
	metaByDir     map[string]*Meta  // key: "/var/lib/nerdctl/<ADDRHASH>/etchosts/<NS>/<ID>"
	extraHosts    []string
}

// update updates the hostsD tree.
// Must be called with a locker for the hostsD directory.
func (u *updater) update() error {
	// phase1: read meta.json
	if err := u.phase1(); err != nil {
		return err
	}
	// phase2: write hosts
	if err := u.phase2(); err != nil {
		return err
	}
	return nil
}

// phase1: read meta.json
func (u *updater) phase1() error {
	readMetaWF := func(path string, _ os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filepath.Base(path) != metaJSON {
			return nil
		}
		metaB, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		var meta Meta
		if err := json.Unmarshal(metaB, &meta); err != nil {
			return err
		}
		u.metaByDir[filepath.Dir(path)] = &meta
		for nwName, cniRes := range meta.Networks {
			for _, ipCfg := range cniRes.IPs {
				if ip := ipCfg.Address.IP; ip != nil {
					if ip.IsLoopback() || ip.IsUnspecified() {
						continue
					}
					ipStr := ip.String()
					u.metaByIPStr[ipStr] = &meta
					u.nwNameByIPStr[ipStr] = nwName
				}
			}
		}
		return nil
	}
	if err := filepath.Walk(u.hostsD, readMetaWF); err != nil {
		return err
	}
	return nil
}

const (
	markerBegin = "<nerdctl>"
	markerEnd   = "</nerdctl>"
)

// phase2: write hosts
func (u *updater) phase2() error {
	writeHostsWF := func(path string, _ os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filepath.Base(path) != "hosts" {
			return nil
		}
		dir := filepath.Dir(path)
		myMeta, ok := u.metaByDir[dir]
		if !ok {
			logrus.WithError(errdefs.ErrNotFound).Debugf("hostsstore metadata %q not found in %q?", metaJSON, dir)
			return nil
		}
		myNetworks := make(map[string]struct{})
		for nwName := range myMeta.Networks {
			myNetworks[nwName] = struct{}{}
		}

		var buf bytes.Buffer
		buf.WriteString(fmt.Sprintf("# %s\n", markerBegin))
		buf.WriteString("127.0.0.1	localhost localhost.localdomain\n")
		buf.WriteString(":1		localhost localhost.localdomain\n")
		for _, h := range u.extraHosts {
			buf.WriteString(fmt.Sprintf("%s\n", h))
		}
		// TODO: cut off entries for the containers in other networks
		for ip, nwName := range u.nwNameByIPStr {
			meta := u.metaByIPStr[ip]
			if line := createLine(ip, nwName, meta, myNetworks); line != "" {
				if _, err := buf.WriteString(line); err != nil {
					return err
				}
			}
		}
		buf.WriteString(fmt.Sprintf("# %s\n", markerEnd))
		// FIXME: retain custom /etc/hosts entries outside <nerdctl></nerdctl>
		// See https://github.com/norouter/norouter/blob/v0.6.2/pkg/agent/etchosts/etchosts.go#L113-L152
		return ioutil.WriteFile(path, buf.Bytes(), 0644)
	}
	if err := filepath.Walk(u.hostsD, writeHostsWF); err != nil {
		return err
	}
	return nil
}

// createLine returns a line string.
// line is like "10.4.2.2        foo foo.nw0 bar bar.nw0\n"
// for `nerdctl --name=foo --hostname=bar --network=n0`.
//
// May return an empty string
func createLine(thatIP, thatNetwork string, meta *Meta, myNetworks map[string]struct{}) string {
	if _, ok := myNetworks[thatNetwork]; !ok {
		// Do not add lines for other networks
		return ""
	}
	baseHostnames := []string{meta.Hostname}
	if meta.Name != "" {
		baseHostnames = append(baseHostnames, meta.Name)
	}

	line := thatIP + "\t"
	for _, baseHostname := range baseHostnames {
		line += baseHostname + " "
		if thatNetwork != DefaultNetworkName {
			// Do not add a entry like "foo.bridge"
			line += baseHostname + "." + thatNetwork + " "
		}
	}
	line = strings.TrimSpace(line) + "\n"
	return line
}
