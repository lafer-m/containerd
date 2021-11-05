package utils

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
)

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

// getDataStore returns a string like "/var/lib/nerdctl/1935db59".
// "1935db9" is from `$(echo -n "/run/containerd/containerd.sock" | sha256sum | cut -c1-8)``
func GetDataStore() (string, error) {
	dataRoot := "/var/lib/nerdctl"
	if err := os.MkdirAll(dataRoot, 0700); err != nil {
		return "", err
	}
	address := "/run/containerd/containerd.sock"
	addrHash, err := getAddrHash(address)
	if err != nil {
		return "", err
	}
	dataStore := filepath.Join(dataRoot, addrHash)
	if err := os.MkdirAll(dataStore, 0700); err != nil {
		return "", err
	}
	return dataStore, nil
}

func getAddrHash(addr string) (string, error) {
	const addrHashLen = 8

	if runtime.GOOS != "windows" {
		addr = strings.TrimPrefix(addr, "unix://")
	}

	var err error
	addr, err = filepath.EvalSymlinks(addr)
	if err != nil {
		return "", err
	}

	d := digest.SHA256.FromString(addr)
	h := d.Encoded()[0:addrHashLen]
	return h, nil
}

func GetContainerStateDirPath(ns, dataStore, id string) (string, error) {
	if strings.Contains(ns, "/") {
		return "", errors.New("namespace with '/' is unsupported")
	}
	return filepath.Join(dataStore, "containers", ns, id), nil
}
