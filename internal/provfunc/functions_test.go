package provfunc

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/function"
)

func TestAll_returnsNonEmpty(t *testing.T) {
	fns := All()
	if len(fns) == 0 {
		t.Fatal("All() returned empty")
	}
	// Verify each function can be instantiated
	for i, fn := range fns {
		f := fn()
		if f == nil {
			t.Errorf("function[%d] returned nil", i)
		}
	}
}

func TestToJSONString(t *testing.T) {
	s, err := toJSONString(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s != "[]" {
		t.Errorf("expected [], got %q", s)
	}
}

func TestAllFunctionNames(t *testing.T) {
	fns := All()
	names := make(map[string]bool)
	for _, fn := range fns {
		f := fn()
		req := function.MetadataRequest{}
		resp := &function.MetadataResponse{}
		f.Metadata(nil, req, resp)
		if resp.Name == "" {
			t.Error("function has empty name")
			continue
		}
		if names[resp.Name] {
			t.Errorf("duplicate function name: %s", resp.Name)
		}
		names[resp.Name] = true
	}
	// Verify key functions exist
	expected := []string{
		"combine", "accept", "drop", "return_verdict", "jump", "goto_chain",
		"counter", "log", "limit", "limit_burst", "reject", "reject_tcp_reset",
		"reject_icmp", "masquerade", "snat", "dnat", "dnat_port", "notrack",
		"set_mark", "set_ct_mark",
		"match_ip_saddr", "match_ip_daddr", "match_ip_protocol", "match_ip_ttl",
		"match_ip6_saddr", "match_ip6_daddr", "match_ip6_hoplimit",
		"match_tcp_dport", "match_tcp_sport", "match_tcp_flags",
		"match_udp_dport", "match_udp_sport",
		"match_icmp_type", "match_icmpv6_type",
		"match_iifname", "match_oifname", "match_mark", "match_nfproto",
		"match_ct_state", "match_ct_mark", "match_ct_status", "match_ct_direction",
		"match_pkttype", "match_skuid", "match_skgid",
		"flow_offload", "redirect", "queue",
	}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("missing expected function: %s", name)
		}
	}
	t.Logf("Total functions: %d", len(names))
}
