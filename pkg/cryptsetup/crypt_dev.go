package cryptsetup

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd/pkg/util/fs/lock"
	"github.com/google/uuid"

	"github.com/containerd/containerd/pkg/util/bin"
	"github.com/containerd/containerd/pkg/util/fs"
	"github.com/sirupsen/logrus"
)

// CryptDevice describes a crypt device
type CryptDevice struct{}

// Pre-defined error(s)
var (
	// ErrUnsupportedCryptsetupVersion is the error raised when the available version
	// of cryptsetup is not compatible with the Singularity encryption mechanism.
	ErrUnsupportedCryptsetupVersion = errors.New("installed version of cryptsetup is not supported, >=2.0.0 required")

	// ErrInvalidPassphrase raised when the passed key is not valid to open requested
	// encrypted device.
	ErrInvalidPassphrase = errors.New("no key available with this passphrase")
)

// createLoop attaches the specified file to the next available loop
// device and sets the sizelimit on it
func createLoop(path string, offset, size uint64) (string, int, error) {
	loopDev := &LoopDevice{
		MaxLoopDevices: GetMaxLoopDevices(),
		Shared:         true,
		Info: &Info64{
			SizeLimit: size,
			Offset:    offset,
			Flags:     FlagsAutoClear,
		},
	}
	idx := 0
	if err := loopDev.AttachFromPath(path, os.O_RDWR, &idx); err != nil {
		return "", 0, fmt.Errorf("failed to attach image %s: %s", path, err)
	}

	return fmt.Sprintf("/dev/loop%d", idx), *loopDev.fd, nil
}

func (crypt *CryptDevice) CreateSecureFS(path string, sizeInMB int64, key []byte) error {
	exist, err := fs.PathExists(path)
	if err != nil {
		return fmt.Errorf("failed to check path existence %s", path)
	}

	if exist {
		return fmt.Errorf("path already existed %s", path)
	}

	// Create a temporary file to format with crypt header
	err = fs.Touch(path)
	if err != nil {
		logrus.Debugf("Error creating temporary crypt file")
		return err
	}

	// Truncate the file taking the squashfs size and crypt header
	// into account. With the options specified below the LUKS header
	// is less than 16MB in size. Slightly over-allocate
	// to compensate for the encryption overhead itself.
	//
	// TODO(mem): the encryption overhead might depend on the size
	// of the data we are encrypting. For very large images, we
	// might not be overallocating enough. Figure out what's the
	// actual percentage we need to overallocate.
	devSize := sizeInMB*1024*1024 + 16*1024*1024

	logrus.Debugf("Total device size for encrypted image: %d", devSize)
	err = os.Truncate(path, devSize)
	if err != nil {
		logrus.Debugf("Unable to truncate crypt file to size %d", devSize)
		return err
	}

	// Associate the temporary crypt file with a loop device
	//loop, loopFD, err := createLoop(path, 0, uint64(devSize))
	//if err != nil {
	//	return err
	//}
	//defer syscall.Syscall(syscall.SYS_IOCTL, uintptr(loopFD), CmdClrFd, 0)

	cryptsetup, err := bin.FindBin("cryptsetup")
	if err != nil {
		return err
	}
	if !fs.IsOwner(cryptsetup, 0) {
		return fmt.Errorf("%s must be owned by root", cryptsetup)
	}

	cmd := exec.Command(cryptsetup, "luksFormat", "--batch-mode", "--type", "luks2", "--key-file", "-", path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	go func() {
		stdin.Write(key)
		stdin.Close()
	}()

	logrus.Debugf("Running %s %s", cmd.Path, strings.Join(cmd.Args, " "))
	out, err := cmd.CombinedOutput()
	if err != nil {
		err = checkCryptsetupVersion(cryptsetup)
		if err == ErrUnsupportedCryptsetupVersion {
			// Special case of unsupported version of cryptsetup. We return the raw error
			// so it can propagate up and a user-friendly message be displayed. This error
			// should trigger an error at the CLI level.
			return err
		}
		return fmt.Errorf("unable to format crypt device: %s: %s", path, string(out))
	}

	nextCrypt, err := crypt.open(key, path)
	if err != nil {
		logrus.Debugf("Unable to open encrypted device %s: %s", path, err)
		return err
	}

	cmd = exec.Command("mkfs.ext4", "/dev/mapper/"+nextCrypt)
	err = cmd.Run()
	if err != nil {
		return err
	}

	cmd = exec.Command(cryptsetup, "close", nextCrypt)
	logrus.Debugf("Running %s %s", cmd.Path, strings.Join(cmd.Args, " "))
	err = cmd.Run()
	if err != nil {
		return err
	}

	return err
}

func (crypt *CryptDevice) OpenSecureFS(path string, mountPoint string, key []byte) (string, error) {
	nextCrypt, err := crypt.open(key, path)
	if err != nil {
		logrus.Debugf("Unable to open encrypted image %s: %s", path, err)
		return "", err
	}

	cmd := exec.Command("mount", "/dev/mapper/"+nextCrypt, mountPoint)
	logrus.Debugf("Running %s %s", cmd.Path, strings.Join(cmd.Args, " "))
	err = cmd.Run()

	if err != nil {
		// logrus.Debugf("Unable to mount %s: %s", mountPoint, err)
		fmt.Errorf("Unable to mount %s: %v", mountPoint, err)
		cmd = exec.Command("cryptsetup", "close", nextCrypt)
		logrus.Debugf("Running %s %s", cmd.Path, strings.Join(cmd.Args, " "))
		_ = cmd.Run()
		return "", err
	}

	return nextCrypt, err
}

func (crypt *CryptDevice) CloseSecureFS(nextCrypt string, mountPoint string) error {
	cmd := exec.Command("umount", "-l", mountPoint)
	logrus.Debugf("Running %s %s", cmd.Path, strings.Join(cmd.Args, " "))
	err := cmd.Run()
	if err != nil {
		logrus.Debugf("Unable to unmount %s: %s", mountPoint, err)
		return err
	}

	err = crypt.closeCryptDevice(nextCrypt)
	if err != nil {
		return err
	}

	return err
}

// closeCryptDevice closes the crypt device
func (crypt *CryptDevice) closeCryptDevice(path string) error {
	cryptsetup, err := bin.FindBin("cryptsetup")
	if err != nil {
		return err
	}
	if !fs.IsOwner(cryptsetup, 0) {
		return fmt.Errorf("%s must be owned by root", cryptsetup)
	}

	fd, err := lock.Exclusive("/dev/mapper")
	if err != nil {
		return err
	}
	defer lock.Release(fd)

	cmd := exec.Command(cryptsetup, "close", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 0, Gid: 0},
	}
	logrus.Debugf("Running %s %s", cmd.Path, strings.Join(cmd.Args, " "))
	err = cmd.Run()
	if err != nil {
		logrus.Debugf("Unable to delete the crypt device %s", err)
		return err
	}

	return nil
}

func checkCryptsetupVersion(cryptsetup string) error {
	if cryptsetup == "" {
		return fmt.Errorf("binary path not defined")
	}

	cmd := exec.Command(cryptsetup, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to run cryptsetup --version: %s", err)
	}

	if !strings.Contains(string(out), "cryptsetup 2.") {
		return ErrUnsupportedCryptsetupVersion
	}

	// We successfully ran cryptsetup --version and we know that the
	// version is compatible with our needs.
	return nil
}

func getNextAvailableCryptDevice() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("id generation failed: %v", err)
	}

	return id.String(), nil
}

// Open opens the encrypted filesystem specified by path (usually a loop
// device, but any encrypted block device will do) using the given key
// and returns the name assigned to it that can be later used to close
// the device.
func (crypt *CryptDevice) open(key []byte, path string) (string, error) {
	fd, err := lock.Exclusive("/dev/mapper")
	if err != nil {
		return "", fmt.Errorf("unable to acquire lock on /dev/mapper")
	}
	defer lock.Release(fd)

	maxRetries := 3 // Arbitrary number of retries.

	cryptsetup, err := bin.FindBin("cryptsetup")
	if err != nil {
		return "", err
	}
	if !fs.IsOwner(cryptsetup, 0) {
		return "", fmt.Errorf("%s must be owned by root", cryptsetup)
	}

	for i := 0; i < maxRetries; i++ {
		nextCrypt, err := getNextAvailableCryptDevice()
		if err != nil {
			return "", fmt.Errorf("while getting next device: %v", err)
		}
		if nextCrypt == "" {
			return "", errors.New("сrypt device not available")
		}

		cmd := exec.Command(cryptsetup, "open", "--batch-mode", "--type", "luks2", "--key-file", "-", path, nextCrypt)
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: 0, Gid: 0}
		logrus.Debugf("Running %s %s", cmd.Path, strings.Join(cmd.Args, " "))

		cmd.Stdin = bytes.NewBuffer(key)
		out, err := cmd.CombinedOutput()
		if err != nil {
			if strings.Contains(string(out), "Device already exists") {
				continue
			}
			err = checkCryptsetupVersion(cryptsetup)
			if err == ErrUnsupportedCryptsetupVersion {
				// Special case of unsupported version of cryptsetup. We return the raw error
				// so it can propagate up and a user-friendly message be displayed. This error
				// should trigger an error at the CLI level.
				return "", err
			}

			if strings.Contains(string(out), "No key available") {
				logrus.Debugf("Invalid password")
				return "", ErrInvalidPassphrase
			}

			return "", fmt.Errorf("cryptsetup open failed: %s: %v", string(out), err)
		}

		for attempt := 0; true; attempt++ {
			_, err := os.Stat("/dev/mapper/" + nextCrypt)
			if err == nil {
				break
			}
			if !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
			delayNext := 100 * (1 << attempt) * time.Millisecond // power of two exponential back off means
			delaySoFar := delayNext - 1                          // total delay so far is next delay - 1
			if delaySoFar >= 25500*time.Millisecond {
				return "", fmt.Errorf("device /dev/mapper/%s did not show up within %d seconds", nextCrypt, delaySoFar/time.Second)
			}
			time.Sleep(delayNext)
		}

		logrus.Debugf("Successfully opened encrypted device %s", path)
		return nextCrypt, nil
	}

	return "", errors.New("unable to open crypt device")
}
