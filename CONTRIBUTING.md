# Contributing to netreach

Thanks for the interest.

## Dev setup

```
git clone https://github.com/nnavnita/netreach.git
cd netreach
make tidy
make test
```

Requires Go 1.22+. No CGO, no external services — everything runs offline.

## Adding a new rule type

Rule evaluation lives in `internal/reach/rules.go`. Each stage is a function
that returns `(allow bool, why string, err error)`. To add a new stage
(e.g. VPC peering):

1. Extend the YAML schema in `internal/model/model.go`.
2. Add a parser test case in `internal/model/parser_test.go`.
3. Insert the stage into the packet walk in `internal/reach/engine.go`.
4. Cover it with a test in `internal/reach/engine_test.go` for both
   `allow` and `deny` paths — the "which rule blocked it" text is part of
   the contract.
5. Update `ARCHITECTURE.md` if the walk order changes.

## Fixture conventions

Fixtures live in `testdata/`. Keep them minimal — one YAML file per
distinct scenario. Reuse `simple.yaml` when possible; add a new file when
a scenario introduces topology that would confuse existing tests.

## Patch guidelines

- Every reachability decision must cite a specific rule id or rule number
  in the `Reason` field. "Blocked" without attribution is a bug.
- Keep the packet walk deterministic. Rely on longest-prefix match for
  route lookup and ascending rule-no order for NACL evaluation.
- Prefer graph queries via `gonum/graph` over hand-rolled BFS. It's easier
  to reason about, and future features (peering, PrivateLink) will lean on
  it heavily.
- One logical change per PR.

## Commit style

```
netreach: <what>

<why, if not obvious>
```

## Reporting bugs

Include the YAML fixture that reproduces + the `netreach analyze` command
line. Ideally trim the fixture to the minimum still reproducing.
