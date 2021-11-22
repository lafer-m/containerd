package bin

import (
	"github.com/sirupsen/logrus"
	"os"
	"os/exec"
)

const (
	// SysDefaultPath defines default value for PATH environment variable.
	SysDefaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// FindBin returns the path to the named binary, or an error if it is not found.
func FindBin(name string) (path string, err error) {
	return findOnPath(name)
	//switch name {
	//// Basic system executables that we assume are always on PATH
	//case "true", "mkfs.ext3", "cp", "rm", "dd":
	//	return findOnPath(name)
	//// Bootstrap related executables that we assume are on PATH
	//case "mount", "mknod", "debootstrap", "pacstrap", "dnf", "yum", "rpm", "curl", "uname", "zypper", "SUSEConnect", "rpmkeys":
	//	return findOnPath(name)
	//// Configurable executables that are found at build time, can be overridden
	//// in singularity.conf. If config value is "" will look on PATH.
	//case "unsquashfs", "mksquashfs", "go":
	//	// return findFromConfigOrPath(name)
	//	return findOnPath(name)
	//// distro provided setUID executables that are used in the fakeroot flow to setup subuid/subgid mappings
	//case "newuidmap", "newgidmap":
	//	return findOnPath(name)
	//// cryptsetup & nvidia-container-cli paths must be explicitly specified
	//// They are called as root from the RPC server in a setuid install, so this
	//// limits to sysadmin controlled paths.
	//// ldconfig is invoked by nvidia-container-cli, so must be trusted also.
	//case "cryptsetup", "ldconfig", "nvidia-container-cli":
	//	// return findFromConfigOnly(name)
	//}
	//return "", fmt.Errorf("unknown executable name %q", name)
}

// findOnPath performs a simple search on PATH for the named executable, returning its full path.
// env.DefaultPath` is appended to PATH to ensure standard locations are searched. This
// is necessary as some distributions don't include sbin on user PATH etc.
func findOnPath(name string) (path string, err error) {
	oldPath := os.Getenv("PATH")
	defer os.Setenv("PATH", oldPath)
	os.Setenv("PATH", oldPath+":"+SysDefaultPath)

	path, err = exec.LookPath(name)
	if err != nil {
		logrus.Debugf("Found %q at %q", name, path)
	}
	return path, err
}