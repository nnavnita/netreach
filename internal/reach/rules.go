package reach

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/nnavnita/netreach/internal/model"
)

type Packet struct {
	SrcIP    netip.Addr
	DstIP    netip.Addr
	Port     int
	Protocol string
}

func portMatches(rulePort string, pkt int) bool {
	rulePort = strings.TrimSpace(rulePort)
	if rulePort == "" || rulePort == "all" || rulePort == "*" {
		return true
	}
	if strings.Contains(rulePort, "-") {
		parts := strings.SplitN(rulePort, "-", 2)
		lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil {
			return false
		}
		return pkt >= lo && pkt <= hi
	}
	n, err := strconv.Atoi(rulePort)
	if err != nil {
		return false
	}
	return n == pkt
}

func protocolMatches(ruleProto, pktProto string) bool {
	rp := strings.ToLower(strings.TrimSpace(ruleProto))
	if rp == "" || rp == "all" || rp == "-1" || rp == "*" {
		return true
	}
	return rp == strings.ToLower(pktProto)
}

func cidrContains(cidr string, ip netip.Addr) (bool, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false, fmt.Errorf("parse cidr %q: %w", cidr, err)
	}
	return prefix.Contains(ip), nil
}

func EvaluateSGIngress(sgs []model.SecurityGroup, sgIDs []string, pkt Packet) (bool, string) {
	if len(sgIDs) == 0 {
		return false, "no security groups attached to destination"
	}
	byID := map[string]model.SecurityGroup{}
	for _, sg := range sgs {
		byID[sg.ID] = sg
	}
	for _, id := range sgIDs {
		sg, ok := byID[id]
		if !ok {
			continue
		}
		for _, r := range sg.Ingress {
			if !protocolMatches(r.Protocol, pkt.Protocol) {
				continue
			}
			if !portMatches(r.Port, pkt.Port) {
				continue
			}
			ok, err := cidrContains(r.From, pkt.SrcIP)
			if err != nil || !ok {
				continue
			}
			return true, fmt.Sprintf("%s ingress allows %s/%d from %s", sg.ID, pkt.Protocol, pkt.Port, r.From)
		}
	}
	return false, fmt.Sprintf("no security group ingress rule allows %s/%d from %s", pkt.Protocol, pkt.Port, pkt.SrcIP)
}

func EvaluateSGEgress(sgs []model.SecurityGroup, sgIDs []string, pkt Packet) (bool, string) {
	if len(sgIDs) == 0 {
		return true, "no security groups on source (default allow)"
	}
	byID := map[string]model.SecurityGroup{}
	for _, sg := range sgs {
		byID[sg.ID] = sg
	}
	for _, id := range sgIDs {
		sg, ok := byID[id]
		if !ok {
			continue
		}
		for _, r := range sg.Egress {
			if !protocolMatches(r.Protocol, pkt.Protocol) {
				continue
			}
			if !portMatches(r.Port, pkt.Port) {
				continue
			}
			ok, err := cidrContains(r.To, pkt.DstIP)
			if err != nil || !ok {
				continue
			}
			return true, fmt.Sprintf("%s egress allows %s/%d to %s", sg.ID, pkt.Protocol, pkt.Port, r.To)
		}
	}
	return false, fmt.Sprintf("no security group egress rule allows %s/%d to %s", pkt.Protocol, pkt.Port, pkt.DstIP)
}

func EvaluateNACL(nacl *model.NACL, direction string, cidrPeer netip.Addr, pkt Packet) (bool, string) {
	if nacl == nil {
		return true, "no NACL attached (default allow)"
	}
	rules := make([]model.NACLRule, 0, len(nacl.Rules))
	for _, r := range nacl.Rules {
		if strings.EqualFold(r.Direction, direction) {
			rules = append(rules, r)
		}
	}
	for i := 0; i < len(rules); i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[j].RuleNo < rules[i].RuleNo {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}
	for _, r := range rules {
		if !protocolMatches(r.Protocol, pkt.Protocol) {
			continue
		}
		if !portMatches(r.Port, pkt.Port) {
			continue
		}
		ok, err := cidrContains(r.CIDR, cidrPeer)
		if err != nil || !ok {
			continue
		}
		if strings.EqualFold(r.Action, "allow") {
			return true, fmt.Sprintf("%s rule %d allows %s %s/%d from/to %s", nacl.ID, r.RuleNo, direction, pkt.Protocol, pkt.Port, r.CIDR)
		}
		return false, fmt.Sprintf("%s rule %d denies %s %s/%d from/to %s", nacl.ID, r.RuleNo, direction, pkt.Protocol, pkt.Port, r.CIDR)
	}
	return false, fmt.Sprintf("%s has no matching %s rule (implicit deny)", nacl.ID, direction)
}

func LookupRoute(rt *model.RouteTable, dst netip.Addr) (*model.Route, error) {
	if rt == nil {
		return nil, fmt.Errorf("route table is nil")
	}
	var best *model.Route
	var bestBits int = -1
	for i := range rt.Routes {
		r := &rt.Routes[i]
		prefix, err := netip.ParsePrefix(r.Dest)
		if err != nil {
			continue
		}
		if prefix.Contains(dst) {
			if prefix.Bits() > bestBits {
				bestBits = prefix.Bits()
				best = r
			}
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no route matches %s", dst)
	}
	return best, nil
}
