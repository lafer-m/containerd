package v2

import (
	"os/exec"
)

type Action string

const (
	Drop   Action = "drop"
	Accept        = "accept"
	Reject        = "reject"
)

// ReplaceIPTableArg
type ReplaceIPTableArg struct {
	// only support filter table for now
	Table string `json:"table"`

	InputRules  Rules `json:"input_rules"`
	OutputRules Rules `json:"output_rules"`
}

type Rules struct {
	DefaultDrop bool   `json:"default_drop"`
	Rules       []Rule `json:"rules"`
}

type Rule struct {
	// only support tcp/udp for now
	Protocol     string `json:"protocol"`
	Action       Action `json:"action"`
	Dst          string `json:"dst"`
	DstMask      string `json:"dst_mask"`
	Src          string `json:"src"`
	SrcMask      string `json:"src_mask"`
	SrcPortStart uint16 `json:"src_port_start"`
	SrcPortEnd   uint16 `json:"src_port_end"`
	DstPortStart uint16 `json:"dst_port_start"`
	DstPortEnd   uint16 `json:"dst_port_end"`
}

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
