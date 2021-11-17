package proxy

import "net"

type userlandProxy interface {
	Start() error
	Stop() error
}

func NewProxyCommand(proto string, hostIP net.IP, hostPort int, containerIP net.IP, containerPort int, proxyPath string) (userlandProxy, error) {
	return newProxyCommand(proto, hostIP, hostPort, containerIP, containerPort, proxyPath)
}
