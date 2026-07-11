package model

import (
	"fmt"
	"net/netip"
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml %q: %w", path, err)
	}

	if err := Validate(&cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return &cfg, nil
}

func Validate(cfg *Config) error {
	subnetIDs := map[string]bool{}
	rtIDs := map[string]bool{}
	sgIDs := map[string]bool{}

	for _, v := range cfg.VPCs {
		if _, err := netip.ParsePrefix(v.CIDR); err != nil {
			return fmt.Errorf("vpc %s: bad cidr %q: %w", v.ID, v.CIDR, err)
		}
		for _, s := range v.Subnets {
			if _, err := netip.ParsePrefix(s.CIDR); err != nil {
				return fmt.Errorf("subnet %s: bad cidr %q: %w", s.ID, s.CIDR, err)
			}
			subnetIDs[s.ID] = true
		}
	}

	for _, rt := range cfg.RouteTables {
		rtIDs[rt.ID] = true
		for _, r := range rt.Routes {
			if _, err := netip.ParsePrefix(r.Dest); err != nil {
				return fmt.Errorf("route table %s: bad dest %q: %w", rt.ID, r.Dest, err)
			}
		}
	}

	for _, v := range cfg.VPCs {
		for _, s := range v.Subnets {
			if !rtIDs[s.RouteTable] {
				return fmt.Errorf("subnet %s references unknown route table %q", s.ID, s.RouteTable)
			}
		}
	}

	for _, sg := range cfg.SecurityGroups {
		sgIDs[sg.ID] = true
	}

	for _, n := range cfg.NACLs {
		if !subnetIDs[n.Subnet] {
			return fmt.Errorf("nacl %s references unknown subnet %q", n.ID, n.Subnet)
		}
	}

	for _, e := range cfg.ENIs {
		if !subnetIDs[e.Subnet] {
			return fmt.Errorf("eni %s references unknown subnet %q", e.ID, e.Subnet)
		}
		if _, err := netip.ParseAddr(e.IP); err != nil {
			return fmt.Errorf("eni %s: bad ip %q: %w", e.ID, e.IP, err)
		}
		for _, sgID := range e.SecurityGroups {
			if !sgIDs[sgID] {
				return fmt.Errorf("eni %s references unknown security group %q", e.ID, sgID)
			}
		}
	}
	return nil
}
