package model

type Config struct {
	VPCs           []VPC           `yaml:"vpcs"`
	RouteTables    []RouteTable    `yaml:"route_tables"`
	SecurityGroups []SecurityGroup `yaml:"security_groups"`
	NACLs          []NACL          `yaml:"nacls"`
	ENIs           []ENI           `yaml:"enis"`
	TransitGateway *TransitGateway `yaml:"transit_gateway,omitempty"`
}

type VPC struct {
	ID      string   `yaml:"id"`
	CIDR    string   `yaml:"cidr"`
	Subnets []Subnet `yaml:"subnets"`
}

type Subnet struct {
	ID         string `yaml:"id"`
	CIDR       string `yaml:"cidr"`
	RouteTable string `yaml:"route_table"`
}

type RouteTable struct {
	ID     string  `yaml:"id"`
	Routes []Route `yaml:"routes"`
}

type Route struct {
	Dest   string `yaml:"dest"`
	Target string `yaml:"target"`
}

type SecurityGroup struct {
	ID      string    `yaml:"id"`
	Ingress []SGRule  `yaml:"ingress"`
	Egress  []SGRule  `yaml:"egress"`
}

type SGRule struct {
	From     string `yaml:"from,omitempty"`
	To       string `yaml:"to,omitempty"`
	Port     string `yaml:"port"`
	Protocol string `yaml:"protocol"`
}

type NACL struct {
	ID     string     `yaml:"id"`
	Subnet string     `yaml:"subnet"`
	Rules  []NACLRule `yaml:"rules"`
}

type NACLRule struct {
	RuleNo    int    `yaml:"rule_no"`
	Direction string `yaml:"direction"`
	Action    string `yaml:"action"`
	CIDR      string `yaml:"cidr"`
	Port      string `yaml:"port"`
	Protocol  string `yaml:"protocol"`
}

type ENI struct {
	ID             string   `yaml:"id"`
	Subnet         string   `yaml:"subnet"`
	IP             string   `yaml:"ip"`
	SecurityGroups []string `yaml:"security_groups"`
}

type TransitGateway struct {
	ID          string  `yaml:"id"`
	Attachments []string `yaml:"attachments"`
	RouteTable  []Route `yaml:"route_table"`
}
