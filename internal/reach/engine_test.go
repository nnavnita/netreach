package reach

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nnavnita/netreach/internal/model"
)

func loadCfg(t *testing.T, name string) *model.Config {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", name)
	cfg, err := model.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return cfg
}

func TestReachableAcrossInternet(t *testing.T) {
	cfg := loadCfg(t, "simple.yaml")
	e := NewEngine(cfg)
	res, err := e.Analyze("eni-web", "1.1.1.1", 443, "tcp")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !res.Reachable {
		t.Fatalf("expected reachable, got blocked: %s", res.Reason)
	}
}

func TestBlockedBySecurityGroup(t *testing.T) {
	cfg := loadCfg(t, "simple.yaml")
	e := NewEngine(cfg)
	res, err := e.Analyze("eni-web", "eni-app", 22, "tcp")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if res.Reachable {
		t.Fatal("expected blocked by SG ingress on eni-app")
	}
	if !strings.Contains(res.Reason, "SG ingress") && !strings.Contains(res.Reason, "security group") {
		t.Fatalf("expected SG reason, got: %s", res.Reason)
	}
}

func TestBlockedByNACL(t *testing.T) {
	cfg := loadCfg(t, "simple.yaml")
	for i := range cfg.NACLs {
		if cfg.NACLs[i].Subnet == "subnet-a2" {
			cfg.NACLs[i].Rules = []model.NACLRule{
				{RuleNo: 50, Direction: "ingress", Action: "deny", CIDR: "10.0.1.0/24", Port: "all", Protocol: "all"},
				{RuleNo: 100, Direction: "ingress", Action: "allow", CIDR: "0.0.0.0/0", Port: "all", Protocol: "all"},
				{RuleNo: 100, Direction: "egress", Action: "allow", CIDR: "0.0.0.0/0", Port: "all", Protocol: "all"},
			}
		}
	}
	e := NewEngine(cfg)
	res, err := e.Analyze("eni-web", "eni-app", 8080, "tcp")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if res.Reachable {
		t.Fatal("expected blocked by NACL")
	}
	if !strings.Contains(res.Reason, "NACL") && !strings.Contains(res.Reason, "nacl-a2") {
		t.Fatalf("expected NACL reason, got: %s", res.Reason)
	}
}

func TestBlockedByMissingRoute(t *testing.T) {
	cfg := loadCfg(t, "simple.yaml")
	for i := range cfg.RouteTables {
		if cfg.RouteTables[i].ID == "rtb-a1" {
			cfg.RouteTables[i].Routes = []model.Route{
				{Dest: "10.0.0.0/16", Target: "local"},
			}
		}
	}
	e := NewEngine(cfg)
	res, err := e.Analyze("eni-web", "8.8.8.8", 443, "tcp")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if res.Reachable {
		t.Fatal("expected blocked by missing route")
	}
	if !strings.Contains(res.Reason, "no route") {
		t.Fatalf("expected missing route reason, got: %s", res.Reason)
	}
}

func TestReachableAcrossTGW(t *testing.T) {
	cfg := loadCfg(t, "multi_vpc.yaml")
	e := NewEngine(cfg)
	res, err := e.Analyze("eni-web", "eni-db", 5432, "tcp")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !res.Reachable {
		t.Fatalf("expected reachable across TGW, got blocked: %s", res.Reason)
	}
	hasTGW := false
	for _, p := range res.Path {
		if strings.Contains(p, "tgw") {
			hasTGW = true
		}
	}
	if !hasTGW {
		t.Fatalf("expected tgw hop in path, got: %v", res.Path)
	}
}

func TestBlockedByEgressSG(t *testing.T) {
	cfg := loadCfg(t, "simple.yaml")
	for i := range cfg.SecurityGroups {
		if cfg.SecurityGroups[i].ID == "sg-web" {
			cfg.SecurityGroups[i].Egress = []model.SGRule{
				{To: "10.0.0.0/16", Port: "all", Protocol: "all"},
			}
		}
	}
	e := NewEngine(cfg)
	res, err := e.Analyze("eni-web", "1.1.1.1", 443, "tcp")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if res.Reachable {
		t.Fatal("expected blocked by SG egress")
	}
	if !strings.Contains(res.Reason, "egress") {
		t.Fatalf("expected egress reason, got: %s", res.Reason)
	}
}
