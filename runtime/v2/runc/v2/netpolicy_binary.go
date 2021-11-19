package v2

import (
	"os/exec"
)

type netpolicyBinary struct {
	runtime string
	id      string
	policys string
}

func newNetPolicyBinary(id, runtime string, policys string) *netpolicyBinary {
	return &netpolicyBinary{
		runtime: runtime,
		id:      id,
		policys: policys,
	}
}

func (n *netpolicyBinary) start() error {
	cmd := n.newCmd()
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return err
	}
	return nil
}

func (n *netpolicyBinary) newCmd() *exec.Cmd {
	args := []string{
		"iptables",
		"--data", n.policys,
		n.id,
	}
	return exec.Command(n.runtime, args...)
}
