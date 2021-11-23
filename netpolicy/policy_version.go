package netpolicy

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	policy "github.com/containerd/containerd/api/services/auth/proto"
	"github.com/containerd/containerd/log"
)

type policyVersion struct {
	service string
	version string
	changed bool
	applied bool
	policys []*policy.PolicyGroup
}

func (p *policyVersion) marshal() ([]byte, error) {
	req, err := p.parse()
	if err != nil {
		return nil, err
	}
	resp, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (p *policyVersion) parse() (*ReplaceIPTableArg, error) {
	if len(p.policys) == 0 {
		return nil, ErrNoPolicy
	}
	// for now only use the first PolicyGroup
	group := p.policys[0]
	return ParseGroup(group)
}

func ParseGroup(group *policy.PolicyGroup) (*ReplaceIPTableArg, error) {
	defaultDrop := false
	if group.Default == policy.NetPolicyAccessType_Deny {
		defaultDrop = true
	}

	var err error

	inputRules, outputRules := []Rule{}, []Rule{}

	for _, rule := range group.NetworkPolicy {
		if !rule.IsActive {
			continue
		}
		protocol := "tcp"
		switch rule.Protocol {
		case policy.NetPolicyProtocol_TCP:
			protocol = "tcp"
		case policy.NetPolicyProtocol_UDP:
			protocol = "udp"
		default:
			log.L.Warnf("not supported protocol %v", rule.Protocol)
			continue
		}

		var ac Action = Accept
		switch rule.AccessType {
		case policy.NetPolicyAccessType_Deny:
			ac = Drop
		}

		ip, mask := "", ""
		switch rule.Type {
		case policy.NetPolicyType_IP:
			ip = rule.Value
			if ip != "" {
				mask = "255.255.255.255"
			}
		case policy.NetPolicyType_Segment:
			ip, mask, err = parseIP(rule.Value)
			if err != nil {
				return nil, err
			}
		}

		tRule := Rule{
			Protocol: protocol,
			Action:   ac,
		}
		s, e, err := parsePorts(rule.Port)
		if err != nil && err != ErrNoPort {
			return nil, err
		}
		tRule.DstPortStart = s
		tRule.DstPortEnd = e

		if rule.Direction == policy.PolicyDirection_Input {
			tRule.Src = ip
			tRule.SrcMask = mask
			inputRules = append(inputRules, tRule)
			// auto output Rule
			if defaultDrop && ac == Accept {
				outputRules = append(outputRules, generateAutoRule(true, tRule))
			}

		} else {
			tRule.Dst = ip
			tRule.DstMask = mask
			outputRules = append(outputRules, tRule)
			// auto input Rule
			if defaultDrop && ac == Accept {
				inputRules = append(inputRules, generateAutoRule(false, tRule))
			}
		}
	}

	request := &ReplaceIPTableArg{
		Table: "filter",
	}

	if len(inputRules) > 0 {
		request.InputRules = Rules{
			DefaultDrop: defaultDrop,
			Rules:       inputRules,
		}
	}
	if len(outputRules) > 0 {
		request.OutputRules = Rules{
			DefaultDrop: defaultDrop,
			Rules:       outputRules,
		}
	}

	return request, nil
}

func generateAutoRule(input bool, rule Rule) Rule {
	newRule := Rule{
		Action:   Accept,
		Protocol: rule.Protocol,
	}
	if input {
		newRule.Dst = rule.Src
		newRule.DstMask = rule.SrcMask
		newRule.SrcPortStart = rule.DstPortStart
		newRule.SrcPortEnd = rule.DstPortEnd
	} else {
		newRule.Src = rule.Dst
		newRule.SrcMask = rule.DstMask
		newRule.SrcPortStart = rule.DstPortStart
		newRule.SrcPortEnd = rule.DstPortEnd
	}

	return newRule
}

func parseIP(ip string) (string, string, error) {
	newIP, mask := "", ""
	_, ipv4, err := net.ParseCIDR(ip)
	if err != nil {
		return "", "", err
	}
	if len(ipv4.Mask) != 4 {
		return "", "", fmt.Errorf("mask must be 4 byte")
	}

	newIP = ipv4.IP.String()
	mask = fmt.Sprintf("%d.%d.%d.%d", ipv4.Mask[0], ipv4.Mask[1], ipv4.Mask[2], ipv4.Mask[3])
	return newIP, mask, nil
}

func parsePorts(ports string) (uint16, uint16, error) {
	if ports == "" {
		return 0, 0, ErrNoPort
	}
	var err error
	var ps, pe int
	s, e := uint16(0), uint16(0)
	portsStr := strings.Split(ports, "-")
	if len(portsStr) == 1 {
		ps, err = strconv.Atoi(portsStr[0])
		s = uint16(ps)
		e = uint16(ps)
	}
	if len(portsStr) == 2 {
		ps, err = strconv.Atoi(portsStr[0])
		pe, err = strconv.Atoi(portsStr[1])
		s = uint16(ps)
		e = uint16(pe)
	}

	return s, e, err
}

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
