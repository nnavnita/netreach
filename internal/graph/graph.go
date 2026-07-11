package graph

import (
	"fmt"
	"io"
	"strings"

	"github.com/nnavnita/netreach/internal/model"
	"gonum.org/v1/gonum/graph/simple"
)

type Topology struct {
	G      *simple.DirectedGraph
	NodeID map[string]int64
	IDNode map[int64]string
}

func Build(cfg *model.Config) *Topology {
	t := &Topology{
		G:      simple.NewDirectedGraph(),
		NodeID: map[string]int64{},
		IDNode: map[int64]string{},
	}
	add := func(id string) int64 {
		if v, ok := t.NodeID[id]; ok {
			return v
		}
		n := t.G.NewNode()
		t.G.AddNode(n)
		t.NodeID[id] = n.ID()
		t.IDNode[n.ID()] = id
		return n.ID()
	}
	edge := func(from, to string) {
		f := add(from)
		tt := add(to)
		fn := t.G.Node(f)
		tn := t.G.Node(tt)
		if !t.G.HasEdgeFromTo(fn.ID(), tn.ID()) {
			t.G.SetEdge(t.G.NewEdge(fn, tn))
		}
	}

	for _, v := range cfg.VPCs {
		add(v.ID)
		for _, s := range v.Subnets {
			edge(v.ID, s.ID)
		}
	}
	for _, e := range cfg.ENIs {
		edge(e.Subnet, e.ID)
	}
	if cfg.TransitGateway != nil {
		add(cfg.TransitGateway.ID)
		for _, att := range cfg.TransitGateway.Attachments {
			edge(cfg.TransitGateway.ID, att)
			edge(att, cfg.TransitGateway.ID)
		}
	}
	return t
}

func WriteDOT(w io.Writer, cfg *model.Config) error {
	var b strings.Builder
	b.WriteString("digraph netreach {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [shape=box, style=rounded];\n\n")

	for _, v := range cfg.VPCs {
		fmt.Fprintf(&b, "  subgraph cluster_%s {\n", sanitize(v.ID))
		fmt.Fprintf(&b, "    label=\"%s %s\";\n", v.ID, v.CIDR)
		for _, s := range v.Subnets {
			fmt.Fprintf(&b, "    %q [label=\"%s\\n%s\"];\n", s.ID, s.ID, s.CIDR)
		}
		b.WriteString("  }\n")
	}
	for _, e := range cfg.ENIs {
		fmt.Fprintf(&b, "  %q [shape=ellipse, label=\"%s\\n%s\"];\n", e.ID, e.ID, e.IP)
		fmt.Fprintf(&b, "  %q -> %q;\n", e.Subnet, e.ID)
	}
	if cfg.TransitGateway != nil {
		fmt.Fprintf(&b, "  %q [shape=diamond, label=\"%s\"];\n", cfg.TransitGateway.ID, cfg.TransitGateway.ID)
		for _, att := range cfg.TransitGateway.Attachments {
			fmt.Fprintf(&b, "  %q -> %q [dir=both];\n", cfg.TransitGateway.ID, att)
		}
	}
	b.WriteString("}\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func sanitize(s string) string {
	return strings.NewReplacer("-", "_", ".", "_").Replace(s)
}
