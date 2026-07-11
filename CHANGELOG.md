# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-07-11

### Added
- YAML config schema for VPCs, subnets, security groups, NACLs, route
  tables, ENIs, and a single Transit Gateway.
- Reachability engine that walks source SG egress → source NACL egress →
  route table (with optional TGW hop) → destination NACL ingress →
  destination SG ingress, citing the specific rule that allowed or denied
  the packet at every step.
- `netreach analyze` CLI subcommand.
- `netreach graph` CLI subcommand emitting Graphviz DOT of the topology.
- Sample fixtures: `simple.yaml` (single VPC) and `multi_vpc.yaml`
  (two VPCs connected by TGW).
- Unit tests: 3 parser tests + 6 reachability tests covering allow,
  SG-blocked, NACL-blocked, missing-route, cross-VPC via TGW, and SG
  egress denial.
