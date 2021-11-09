package utils

const (
	// Prefix is the common prefix of nerdctl labels
	Prefix = "nerdctl/"

	// Namespace is the containerd namespace such as "default", "k8s.io"
	Namespace = Prefix + "namespace"

	// Name is a human-friendly name.
	// WARNING: multiple containers may have same the name label
	Name = Prefix + "name"

	//Compose Project Name
	ComposeProject = "com.docker.compose.project"

	//Compose Service Name
	ComposeService = "com.docker.compose.service"

	//Compose Network Name
	ComposeNetwork = "com.docker.compose.network"

	//Compose Volume Name
	ComposeVolume = "com.docker.compose.volume"

	// Hostname
	Hostname = Prefix + "hostname"

	// ExtraHosts are HostIPs to appended to /etc/hosts
	ExtraHosts = Prefix + "extraHosts"

	// StateDir is "/var/lib/nerdctl/<ADDRHASH>/containers/<NAMESPACE>/<ID>"
	StateDir = Prefix + "state-dir"

	// Networks is a JSON-marshalled string of []string, e.g. []string{"bridge"}.
	// Currently, the length of the slice must be 1.
	Networks = Prefix + "networks"

	// Ports is a JSON-marshalled string of []gocni.PortMapping .
	Ports = Prefix + "ports"

	// LogURI is the log URI
	LogURI = Prefix + "log-uri"

	// PIDFile is the `nerdctl run --pidfile`
	// (CLI flag is "pidfile", not "pid-file", for Podman compatibility)
	PIDFile = Prefix + "pid-file"

	// AnonymousVolumes is a JSON-marshalled string of []string
	AnonymousVolumes = Prefix + "anonymous-volumes"

	// Platform is the normalized platform string like "linux/ppc64le".
	Platform = Prefix + "platform"
)
