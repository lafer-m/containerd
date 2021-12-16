package cryptsetup

import (
	"os"
	"testing"

	"github.com/containerd/containerd/pkg/testutil"
)

func TestSecureFS(t *testing.T) {
	testutil.EnsurePrivilege(t)
	defer testutil.ResetPrivilege(t)

	dev := &CryptDevice{}
	devPath := "/tmp/tmp.img"
	mountPoint := "/tmp/mount_point1"
	key := []byte("dummyKey")
	err := dev.CreateSecureFS(devPath, 1, key)
	if err != nil {
		if err == ErrUnsupportedCryptsetupVersion {
			t.Skip("installed version of cryptsetup is not supported, >=2.0.0 required")
		} else {
			t.Fatalf("test %s expected to succeed but failed: %s", devPath, err)
		}
	}
	defer os.Remove(devPath)

	crypt, err := dev.OpenSecureFS(devPath, mountPoint, key)
	if err != nil {
		t.Fatalf("open secure FS failed: %s", err)
	}

	err = dev.CloseSecureFS(crypt, mountPoint)
	if err != nil {
		t.Fatalf("close secure FS failed: %s", err)
	}

	// Reopen
	crypt2, err := dev.OpenSecureFS(devPath, mountPoint, key)
	if err != nil {
		t.Fatalf("reopen secure FS failed: %s", err)
	}

	err = dev.CloseSecureFS(crypt2, mountPoint)
	if err != nil {
		t.Fatalf("close secure FS failed: %s", err)
	}
}
