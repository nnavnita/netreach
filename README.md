# netreach

[![CI](https://github.com/nnavnita/netreach/actions/workflows/ci.yml/badge.svg)](https://github.com/nnavnita/netreach/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8)

Reachability analyzer for simplified AWS-style network models. Give it a YAML description of your VPCs, subnets, security groups, NACLs, route tables, and transit gateway attachments, and it answers whether a packet from A to B is `REACHABLE` or `BLOCKED` — and if blocked, exactly which rule stopped it. Positioned as the sort of static-analysis tooling AWS Core Networking teams reach for when reviewing a design.

## Install

Requires Go 1.22+.

```
git clone https://github.com/nnavnita/netreach.git
cd netreach
make build
```

Or via Docker:

```
docker build -t netreach .
docker run --rm -v $PWD/testdata:/data netreach analyze --config /data/simple.yaml --src eni-web --dst 1.1.1.1 --port 443 --protocol tcp
```

## Usage

### Analyze reachability

```
./netreach analyze --config testdata/simple.yaml --src eni-web --dst 1.1.1.1 --port 443 --protocol tcp
```

Sample output:

```
REACHABLE
reason: all checks passed
path:
  - src=eni-web
  - sg-egress: sg-web egress allows tcp/443 to 0.0.0.0/0
  - nacl-egress: nacl-a1 rule 100 allows egress tcp/443 from/to 0.0.0.0/0
  - route: 0.0.0.0/0 -> 1.1.1.1 via igw-1
  - dst=1.1.1.1
```

A blocked example:

```
$ ./netreach analyze --config testdata/simple.yaml --src eni-web --dst eni-app --port 22 --protocol tcp
BLOCKED
reason: blocked at destination SG ingress: no security group ingress rule allows tcp/22 from 10.0.1.10
path:
  - src=eni-web
  - sg-egress: sg-web egress allows tcp/22 to 0.0.0.0/0
  - nacl-egress: nacl-a1 rule 100 allows egress tcp/22 from/to 0.0.0.0/0
  - route: 10.0.0.0/16 -> 10.0.2.10 via local
  - nacl-ingress: nacl-a2 rule 100 allows ingress tcp/22 from/to 0.0.0.0/0
```

Exit code is `0` for reachable, `2` for blocked, `1` for usage errors.

### Emit a Graphviz topology

```
./netreach graph --config testdata/multi_vpc.yaml --out topology.dot
dot -Tpng topology.dot -o topology.png
```

## How it works

Reachability is a deterministic packet walk across five stages: source SG egress, source NACL egress, source subnet route table (with optional Transit Gateway hop), destination NACL ingress, destination SG ingress. Every stage cites the specific rule (SG id, NACL rule number, route target) that allowed or denied the packet. See [ARCHITECTURE.md](ARCHITECTURE.md) for the data flow diagram and design decisions.

## Development

```
make test      # go test -race
make lint      # go vet + gofmt
make build     # produce ./netreach
make run-example
```

## Scope

- Simplified AWS model: VPCs, subnets, SGs, NACLs, route tables, single Transit Gateway.
- Not modeled: VPC peering, PrivateLink, load balancers, IAM, IPv6, source/dest NAT, path MTU.
- Longest-prefix match for route lookup. NACL rules evaluated in ascending rule-no order (first match wins).
- Security groups are stateful (return traffic implicitly allowed by the model — we only check the initiating direction).

## Comparison

| Tool                              | Input                | Output          | Offline? | Multi-account |
| --------------------------------- | -------------------- | --------------- | -------- | ------------- |
| AWS VPC Reachability Analyzer     | Live account         | Path + verdict  | No       | Limited       |
| AWS Network Access Analyzer       | Live account         | Findings        | No       | Yes           |
| `terraform plan` + human review   | HCL                  | Diff            | Yes      | Manual        |
| **netreach**                      | YAML (or roll-your-own IR) | REACHABLE / BLOCKED + citing rule | **Yes** | Yes (aggregate across accounts into one YAML) |

netreach is not a replacement for the AWS Reachability Analyzer — it's the
offline, CI-friendly cousin. Point it at a design doc before you apply the
Terraform, not after prod is on fire.

## Roadmap

- [ ] Ingest Terraform state (`terraform.tfstate` JSON) directly
- [ ] Ingest CloudFormation templates
- [ ] VPC peering + PrivateLink
- [ ] IPv6 support
- [ ] `netreach diff` — compute reachability delta between two configs
- [ ] JSON output for CI pipeline integration
- [ ] Web UI (`netreach serve`) for graph exploration

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT.
