package model

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSimple(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "simple.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.VPCs) != 1 {
		t.Fatalf("expected 1 VPC, got %d", len(cfg.VPCs))
	}
	if len(cfg.ENIs) != 2 {
		t.Fatalf("expected 2 ENIs, got %d", len(cfg.ENIs))
	}
	if cfg.VPCs[0].ID != "vpc-a" {
		t.Fatalf("expected vpc-a, got %s", cfg.VPCs[0].ID)
	}
}

func TestLoadMultiVPC(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "multi_vpc.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TransitGateway == nil {
		t.Fatalf("expected transit gateway")
	}
	if cfg.TransitGateway.ID != "tgw-1" {
		t.Fatalf("expected tgw-1, got %s", cfg.TransitGateway.ID)
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load("/nonexistent/path.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateBadCIDR(t *testing.T) {
	tmp, err := os.CreateTemp("", "netreach-*.yaml")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer os.Remove(tmp.Name())
	_, _ = tmp.WriteString("vpcs:\n  - id: v\n    cidr: not-a-cidr\n    subnets: []\n")
	tmp.Close()
	if _, err := Load(tmp.Name()); err == nil {
		t.Fatal("expected validation error")
	}
}
