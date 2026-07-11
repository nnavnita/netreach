package reach

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/nnavnita/netreach/internal/model"
)

type Result struct {
	Reachable bool
	Path      []string
	Reason    string
}

type Endpoint struct {
	ENI    *model.ENI
	IP     netip.Addr
	Subnet *model.Subnet
	VPC    *model.VPC
}

type Engine struct {
	cfg           *model.Config
	subnetByID    map[string]*model.Subnet
	vpcBySubnet   map[string]*model.VPC
	rtByID        map[string]*model.RouteTable
	naclBySubnet  map[string]*model.NACL
	eniByID       map[string]*model.ENI
}

func NewEngine(cfg *model.Config) *Engine {
	e := &Engine{
		cfg:          cfg,
		subnetByID:   map[string]*model.Subnet{},
		vpcBySubnet:  map[string]*model.VPC{},
		rtByID:       map[string]*model.RouteTable{},
		naclBySubnet: map[string]*model.NACL{},
		eniByID:      map[string]*model.ENI{},
	}
	for i := range cfg.VPCs {
		v := &cfg.VPCs[i]
		for j := range v.Subnets {
			s := &v.Subnets[j]
			e.subnetByID[s.ID] = s
			e.vpcBySubnet[s.ID] = v
		}
	}
	for i := range cfg.RouteTables {
		rt := &cfg.RouteTables[i]
		e.rtByID[rt.ID] = rt
	}
	for i := range cfg.NACLs {
		n := &cfg.NACLs[i]
		e.naclBySubnet[n.Subnet] = n
	}
	for i := range cfg.ENIs {
		en := &cfg.ENIs[i]
		e.eniByID[en.ID] = en
	}
	return e
}

func (e *Engine) resolveEndpoint(ref string) (*Endpoint, error) {
	if eni, ok := e.eniByID[ref]; ok {
		ip, err := netip.ParseAddr(eni.IP)
		if err != nil {
			return nil, fmt.Errorf("eni %s bad ip: %w", eni.ID, err)
		}
		subnet := e.subnetByID[eni.Subnet]
		vpc := e.vpcBySubnet[eni.Subnet]
		return &Endpoint{ENI: eni, IP: ip, Subnet: subnet, VPC: vpc}, nil
	}
	ip, err := netip.ParseAddr(ref)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %q as ENI or IP: %w", ref, err)
	}
	for i := range e.cfg.ENIs {
		en := &e.cfg.ENIs[i]
		if en.IP == ref {
			subnet := e.subnetByID[en.Subnet]
			vpc := e.vpcBySubnet[en.Subnet]
			return &Endpoint{ENI: en, IP: ip, Subnet: subnet, VPC: vpc}, nil
		}
	}
	for i := range e.cfg.VPCs {
		v := &e.cfg.VPCs[i]
		for j := range v.Subnets {
			s := &v.Subnets[j]
			prefix, err := netip.ParsePrefix(s.CIDR)
			if err == nil && prefix.Contains(ip) {
				return &Endpoint{IP: ip, Subnet: s, VPC: v}, nil
			}
		}
	}
	return &Endpoint{IP: ip}, nil
}

func (e *Engine) Analyze(srcRef, dstRef string, port int, protocol string) (*Result, error) {
	src, err := e.resolveEndpoint(srcRef)
	if err != nil {
		return nil, fmt.Errorf("resolve src: %w", err)
	}
	dst, err := e.resolveEndpoint(dstRef)
	if err != nil {
		return nil, fmt.Errorf("resolve dst: %w", err)
	}

	pkt := Packet{SrcIP: src.IP, DstIP: dst.IP, Port: port, Protocol: protocol}
	path := []string{fmt.Sprintf("src=%s", srcRef)}

	if src.ENI != nil {
		ok, why := EvaluateSGEgress(e.cfg.SecurityGroups, src.ENI.SecurityGroups, pkt)
		if !ok {
			return &Result{Reachable: false, Path: path, Reason: fmt.Sprintf("blocked at source SG egress: %s", why)}, nil
		}
		path = append(path, "sg-egress: "+why)
	}

	if src.Subnet != nil {
		if nacl, ok := e.naclBySubnet[src.Subnet.ID]; ok {
			okEg, why := EvaluateNACL(nacl, "egress", dst.IP, pkt)
			if !okEg {
				return &Result{Reachable: false, Path: path, Reason: fmt.Sprintf("blocked at source NACL egress: %s", why)}, nil
			}
			path = append(path, "nacl-egress: "+why)
		}
	}

	if src.Subnet != nil {
		rt := e.rtByID[src.Subnet.RouteTable]
		if rt == nil {
			return &Result{Reachable: false, Path: path, Reason: fmt.Sprintf("source subnet %s has no route table", src.Subnet.ID)}, nil
		}
		route, err := LookupRoute(rt, dst.IP)
		if err != nil {
			return &Result{Reachable: false, Path: path, Reason: fmt.Sprintf("no route from %s to %s: %v", src.Subnet.ID, dst.IP, err)}, nil
		}
		path = append(path, fmt.Sprintf("route: %s -> %s via %s", route.Dest, dst.IP, route.Target))

		if strings.HasPrefix(route.Target, "tgw-") {
			if e.cfg.TransitGateway == nil || e.cfg.TransitGateway.ID != route.Target {
				return &Result{Reachable: false, Path: path, Reason: fmt.Sprintf("route targets tgw %q but no matching transit gateway defined", route.Target)}, nil
			}
			tgwRT := &model.RouteTable{ID: e.cfg.TransitGateway.ID + "-rt", Routes: e.cfg.TransitGateway.RouteTable}
			tgwRoute, err := LookupRoute(tgwRT, dst.IP)
			if err != nil {
				return &Result{Reachable: false, Path: path, Reason: fmt.Sprintf("tgw %s has no route to %s", e.cfg.TransitGateway.ID, dst.IP)}, nil
			}
			path = append(path, fmt.Sprintf("tgw-route: %s -> %s via %s", tgwRoute.Dest, dst.IP, tgwRoute.Target))
		}
	}

	if dst.Subnet != nil {
		if nacl, ok := e.naclBySubnet[dst.Subnet.ID]; ok {
			okIn, why := EvaluateNACL(nacl, "ingress", src.IP, pkt)
			if !okIn {
				return &Result{Reachable: false, Path: path, Reason: fmt.Sprintf("blocked at destination NACL ingress: %s", why)}, nil
			}
			path = append(path, "nacl-ingress: "+why)
		}
	}

	if dst.ENI != nil {
		ok, why := EvaluateSGIngress(e.cfg.SecurityGroups, dst.ENI.SecurityGroups, pkt)
		if !ok {
			return &Result{Reachable: false, Path: path, Reason: fmt.Sprintf("blocked at destination SG ingress: %s", why)}, nil
		}
		path = append(path, "sg-ingress: "+why)
	}

	path = append(path, fmt.Sprintf("dst=%s", dstRef))
	return &Result{Reachable: true, Path: path, Reason: "all checks passed"}, nil
}
