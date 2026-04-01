package nfthelper

import (
	"testing"

	"github.com/google/nftables/expr"
)

func assertNonEmpty(t *testing.T, name string, exprs []expr.Any) {
	t.Helper()
	if len(exprs) == 0 {
		t.Errorf("%s returned empty", name)
	}
}

func TestCombine(t *testing.T) {
	a := []expr.Any{&expr.Counter{}}
	b := []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
	result := Combine(a, b)
	if len(result) != 2 {
		t.Fatalf("len=%d, want 2", len(result))
	}
}

// --- IPv4 matchers ---

func TestMatchIPSaddr(t *testing.T) {
	assertNonEmpty(t, "MatchIPSaddr", MatchIPSaddr("10.0.0.1"))
	assertNonEmpty(t, "MatchIPSaddr/CIDR", MatchIPSaddr("10.0.0.0/8"))
}

func TestMatchIPDaddr(t *testing.T) {
	assertNonEmpty(t, "MatchIPDaddr", MatchIPDaddr("192.168.0.0/16"))
	assertNonEmpty(t, "MatchIPDaddr/exact", MatchIPDaddr("192.168.1.1"))
}

func TestMatchIPSaddr_invalid(t *testing.T) {
	result := MatchIPSaddr("not-an-ip")
	if result != nil {
		t.Error("expected nil for invalid IP")
	}
}

// --- IPv6 matchers ---

func TestMatchIP6Saddr(t *testing.T) {
	assertNonEmpty(t, "MatchIP6Saddr", MatchIP6Saddr("::1"))
	assertNonEmpty(t, "MatchIP6Saddr/CIDR", MatchIP6Saddr("fd00::/8"))
}

func TestMatchIP6Daddr(t *testing.T) {
	assertNonEmpty(t, "MatchIP6Daddr", MatchIP6Daddr("2001:db8::1"))
}

// --- Transport matchers ---

func TestMatchTCPDport(t *testing.T) {
	exprs := MatchTCPDport(22)
	// payload dport + cmp port (L4 proto match is separate per pallium design)
	if len(exprs) != 2 {
		t.Errorf("len=%d, want 2", len(exprs))
	}
}

func TestMatchTCPSport(t *testing.T) {
	assertNonEmpty(t, "MatchTCPSport", MatchTCPSport(80))
}

func TestMatchUDPDport(t *testing.T) {
	assertNonEmpty(t, "MatchUDPDport", MatchUDPDport(53))
}

func TestMatchUDPSport(t *testing.T) {
	assertNonEmpty(t, "MatchUDPSport", MatchUDPSport(53))
}

// --- ICMP ---

func TestMatchICMPType(t *testing.T) {
	assertNonEmpty(t, "MatchICMPType/echo-request", MatchICMPType("echo-request"))
	// numeric values are not supported by the name-based helper; use MatchL4Proto + raw payload instead
}

func TestMatchICMPv6Type(t *testing.T) {
	assertNonEmpty(t, "MatchICMPv6Type/echo-request", MatchICMPv6Type("echo-request"))
}

// --- Protocol ---

func TestMatchIPProtocol(t *testing.T) {
	assertNonEmpty(t, "MatchIPProtocol/tcp", MatchIPProtocol("tcp"))
	assertNonEmpty(t, "MatchIPProtocol/udp", MatchIPProtocol("udp"))
	assertNonEmpty(t, "MatchIPProtocol/icmp", MatchIPProtocol("icmp"))
}

func TestMatchL4Proto(t *testing.T) {
	assertNonEmpty(t, "MatchL4Proto", MatchL4Proto(6))
}

// --- Meta ---

func TestMatchIifname(t *testing.T) {
	exprs := MatchIifname("eth0")
	if len(exprs) != 2 {
		t.Errorf("len=%d, want 2", len(exprs))
	}
}

func TestMatchOifname(t *testing.T) {
	assertNonEmpty(t, "MatchOifname", MatchOifname("lo"))
}

func TestMatchMark(t *testing.T) {
	assertNonEmpty(t, "MatchMark", MatchMark(0x42))
}

func TestSetMark(t *testing.T) {
	exprs := SetMark(0x42)
	if len(exprs) != 2 {
		t.Errorf("len=%d, want 2", len(exprs))
	}
	m := exprs[1].(*expr.Meta)
	if !m.SourceRegister {
		t.Error("expected SourceRegister=true")
	}
}

func TestMatchNfproto(t *testing.T) {
	assertNonEmpty(t, "MatchNfproto", MatchNfproto(2))
}

// --- CT ---

func TestMatchCTState(t *testing.T) {
	exprs := MatchCTState("established", "related")
	if len(exprs) != 3 {
		t.Errorf("len=%d, want 3 (ct load + bitwise + cmp)", len(exprs))
	}
}

func TestMatchCTMark(t *testing.T) {
	assertNonEmpty(t, "MatchCTMark", MatchCTMark(0x1))
}

func TestSetCTMark(t *testing.T) {
	exprs := SetCTMark(0x42)
	if len(exprs) != 2 {
		t.Errorf("len=%d, want 2", len(exprs))
	}
}

// --- Verdicts ---

func TestVerdicts(t *testing.T) {
	tests := []struct {
		name string
		fn   func() []expr.Any
		want expr.VerdictKind
	}{
		{"Accept", Accept, expr.VerdictAccept},
		{"Drop", Drop, expr.VerdictDrop},
		{"Return", Return, expr.VerdictReturn},
		{"Continue", Continue, expr.VerdictContinue},
	}
	for _, tc := range tests {
		exprs := tc.fn()
		if len(exprs) != 1 {
			t.Errorf("%s: len=%d, want 1", tc.name, len(exprs))
			continue
		}
		v, ok := exprs[0].(*expr.Verdict)
		if !ok {
			t.Errorf("%s: type=%T, want *expr.Verdict", tc.name, exprs[0])
			continue
		}
		if v.Kind != tc.want {
			t.Errorf("%s: kind=%v, want %v", tc.name, v.Kind, tc.want)
		}
	}
}

func TestJump(t *testing.T) {
	exprs := Jump("mychain")
	v := exprs[0].(*expr.Verdict)
	if v.Kind != expr.VerdictJump || v.Chain != "mychain" {
		t.Errorf("unexpected jump: %+v", v)
	}
}

func TestGoto(t *testing.T) {
	exprs := Goto("mychain")
	v := exprs[0].(*expr.Verdict)
	if v.Kind != expr.VerdictGoto || v.Chain != "mychain" {
		t.Errorf("unexpected goto: %+v", v)
	}
}

// --- Actions ---

func TestCounter(t *testing.T) {
	exprs := Counter()
	if _, ok := exprs[0].(*expr.Counter); !ok {
		t.Errorf("expected Counter, got %T", exprs[0])
	}
}

func TestLog(t *testing.T) {
	assertNonEmpty(t, "Log", Log("test: "))
}

func TestLogLevel(t *testing.T) {
	assertNonEmpty(t, "LogLevel", LogLevel("test: ", "warn"))
}

func TestLimit(t *testing.T) {
	exprs := Limit(10, "second")
	l := exprs[0].(*expr.Limit)
	if l.Rate != 10 || l.Unit != expr.LimitTimeSecond {
		t.Errorf("unexpected limit: %+v", l)
	}
}

func TestLimitBurst(t *testing.T) {
	exprs := LimitBurst(10, "minute", 5)
	l := exprs[0].(*expr.Limit)
	if l.Burst != 5 {
		t.Errorf("burst = %d, want 5", l.Burst)
	}
}

func TestReject(t *testing.T) {
	assertNonEmpty(t, "Reject", Reject())
}

func TestRejectTCPReset(t *testing.T) {
	assertNonEmpty(t, "RejectTCPReset", RejectTCPReset())
}

func TestRejectICMP(t *testing.T) {
	assertNonEmpty(t, "RejectICMP", RejectICMP("port-unreachable"))
}

func TestMasquerade(t *testing.T) {
	assertNonEmpty(t, "Masquerade", Masquerade())
}

func TestMasqueradeRandom(t *testing.T) {
	exprs := MasqueradeRandom()
	m := exprs[0].(*expr.Masq)
	if !m.Random {
		t.Error("expected Random=true")
	}
}

func TestSNAT(t *testing.T) {
	exprs := SNAT("192.168.1.1")
	if len(exprs) < 2 {
		t.Errorf("expected >= 2 exprs, got %d", len(exprs))
	}
}

func TestDNAT(t *testing.T) {
	assertNonEmpty(t, "DNAT", DNAT("10.0.0.1"))
}

func TestDNATPort(t *testing.T) {
	exprs := DNATPort("10.0.0.1", 8080)
	if len(exprs) < 3 {
		t.Errorf("expected >= 3 exprs (addr + port + nat), got %d", len(exprs))
	}
}

func TestNotrack(t *testing.T) {
	assertNonEmpty(t, "Notrack", Notrack())
}

func TestFlowOffload(t *testing.T) {
	exprs := FlowOffload("ft0")
	fo := exprs[0].(*expr.FlowOffload)
	if fo.Name != "ft0" {
		t.Errorf("name = %q, want ft0", fo.Name)
	}
}

// --- Combine full rule ---

func TestCombineFullRule(t *testing.T) {
	rule := Combine(
		MatchIifname("eth0"),
		MatchIPSaddr("10.0.0.0/8"),
		MatchTCPDport(443),
		MatchCTState("new"),
		Counter(),
		Accept(),
	)
	if len(rule) == 0 {
		t.Fatal("expected non-empty rule")
	}
	// Last expression should be Accept verdict
	last := rule[len(rule)-1].(*expr.Verdict)
	if last.Kind != expr.VerdictAccept {
		t.Errorf("last = %+v, want accept", last)
	}
}

func TestExprString(t *testing.T) {
	exprs := Combine(MatchTCPDport(22), Accept())
	s := ExprString(exprs)
	if s == "" {
		t.Error("expected non-empty string")
	}
}
