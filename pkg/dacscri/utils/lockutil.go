package utils

import (
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func WithDirLock(dir string, fn func() error) error {
	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirFile.Close()
	if err := Flock(dirFile, unix.LOCK_EX); err != nil {
		return errors.Wrapf(err, "failed to lock %q", dir)
	}
	defer func() {
		if err := Flock(dirFile, unix.LOCK_UN); err != nil {
			logrus.WithError(err).Errorf("failed to unlock %q", dir)
		}
	}()
	return fn()
}

func Flock(f *os.File, flags int) error {
	fd := int(f.Fd())
	for {
		err := unix.Flock(fd, flags)
		if err == nil || err != unix.EINTR {
			return err
		}
	}
}
