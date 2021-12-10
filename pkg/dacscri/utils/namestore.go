package utils

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/identifiers"
	"github.com/pkg/errors"
)

func New(dataStore, ns string) (NameStore, error) {
	dir := filepath.Join(dataStore, "names", ns)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	store := &nameStore{
		dir: dir,
	}
	return store, nil
}

type NameStore interface {
	Acquire(name, id string) error
	Release(name, id string) error
}

type nameStore struct {
	dir string
}

func (x *nameStore) Acquire(name, id string) error {
	if err := identifiers.Validate(name); err != nil {
		return errors.Wrapf(err, "invalid name %q", name)
	}
	if strings.TrimSpace(id) != id {
		return errors.Errorf("untrimmed ID %q", id)
	}
	fn := func() error {
		fileName := filepath.Join(x.dir, name)
		if b, err := ioutil.ReadFile(fileName); err == nil {
			return errors.Errorf("name %q is already used by ID %q", name, string(b))
		}
		return ioutil.WriteFile(fileName, []byte(id), 0600)
	}
	return WithDirLock(x.dir, fn)
}

func (x *nameStore) Release(name, id string) error {
	if name == "" {
		return nil
	}
	if err := identifiers.Validate(name); err != nil {
		return errors.Wrapf(err, "invalid name %q", name)
	}
	if strings.TrimSpace(id) != id {
		return errors.Errorf("untrimmed ID %q", id)
	}
	fn := func() error {
		fileName := filepath.Join(x.dir, name)
		b, err := ioutil.ReadFile(fileName)
		if err != nil {
			if os.IsNotExist(err) {
				err = nil
			}
			return err
		}
		if s := strings.TrimSpace(string(b)); s != id {
			return errors.Errorf("name %q is used by ID %q, not by %q", name, s, id)
		}
		return os.RemoveAll(fileName)
	}
	return WithDirLock(x.dir, fn)
}
