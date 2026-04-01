package nftexpr

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/google/nftables/expr"
)

func TestFromJSON_payload(t *testing.T) {
	j := `[{"type":"payload","base":"transport","offset":2,"len":2,"dreg":1}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	if len(exprs) != 1 {
		t.Fatalf("expected 1 expr, got %d", len(exprs))
	}
	p, ok := exprs[0].(*expr.Payload)
	if !ok {
		t.Fatalf("expected *expr.Payload, got %T", exprs[0])
	}
	if p.Base != expr.PayloadBaseTransportHeader {
		t.Errorf("base = %v, want transport", p.Base)
	}
	if p.Offset != 2 || p.Len != 2 || p.DestRegister != 1 {
		t.Errorf("unexpected payload fields: %+v", p)
	}
}

func TestFromJSON_cmp(t *testing.T) {
	data := base64.StdEncoding.EncodeToString([]byte{0, 22}) // port 22
	j := `[{"type":"cmp","op":"eq","sreg":1,"data":"` + data + `"}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	c := exprs[0].(*expr.Cmp)
	if c.Op != expr.CmpOpEq || c.Register != 1 {
		t.Errorf("unexpected cmp: %+v", c)
	}
	if len(c.Data) != 2 || c.Data[0] != 0 || c.Data[1] != 22 {
		t.Errorf("data = %v, want [0 22]", c.Data)
	}
}

func TestFromJSON_meta(t *testing.T) {
	j := `[{"type":"meta","key":"l4proto","dreg":1}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	m := exprs[0].(*expr.Meta)
	if m.Key != expr.MetaKeyL4PROTO || m.Register != 1 {
		t.Errorf("unexpected meta: %+v", m)
	}
}

func TestFromJSON_metaSet(t *testing.T) {
	tr := true
	data := base64.StdEncoding.EncodeToString([]byte{1, 0, 0, 0})
	items := []ExprJSON{{Type: "meta", Key: "mark", SReg: 1, SourceRegister: &tr, Data: data}}
	b, _ := json.Marshal(items)
	exprs, err := FromJSON(string(b))
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	m := exprs[0].(*expr.Meta)
	if !m.SourceRegister {
		t.Error("expected SourceRegister=true")
	}
}

func TestFromJSON_immediate(t *testing.T) {
	data := base64.StdEncoding.EncodeToString([]byte{10, 0, 0, 1})
	j := `[{"type":"immediate","dreg":1,"data":"` + data + `"}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	im := exprs[0].(*expr.Immediate)
	if im.Register != 1 {
		t.Errorf("register = %d, want 1", im.Register)
	}
}

func TestFromJSON_bitwise(t *testing.T) {
	mask := base64.StdEncoding.EncodeToString([]byte{255, 255, 255, 0})
	xor := base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0})
	j := `[{"type":"bitwise","sreg":1,"dreg":1,"len":4,"mask":"` + mask + `","xor":"` + xor + `"}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	b := exprs[0].(*expr.Bitwise)
	if b.Len != 4 || b.SourceRegister != 1 || b.DestRegister != 1 {
		t.Errorf("unexpected bitwise: %+v", b)
	}
}

func TestFromJSON_verdict(t *testing.T) {
	verdicts := []struct {
		kind  string
		chain string
		want  expr.VerdictKind
	}{
		{"accept", "", expr.VerdictAccept},
		{"drop", "", expr.VerdictDrop},
		{"return", "", expr.VerdictReturn},
		{"continue", "", expr.VerdictContinue},
		{"jump", "mychain", expr.VerdictJump},
		{"goto", "mychain", expr.VerdictGoto},
	}
	for _, tc := range verdicts {
		chain := ""
		if tc.chain != "" {
			chain = `,"chain":"` + tc.chain + `"`
		}
		j := `[{"type":"verdict","kind":"` + tc.kind + `"` + chain + `}]`
		exprs, err := FromJSON(j)
		if err != nil {
			t.Fatalf("FromJSON(%s) error: %v", tc.kind, err)
		}
		v := exprs[0].(*expr.Verdict)
		if v.Kind != tc.want {
			t.Errorf("kind = %v, want %v", v.Kind, tc.want)
		}
	}
}

func TestFromJSON_counter(t *testing.T) {
	j := `[{"type":"counter"}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	if _, ok := exprs[0].(*expr.Counter); !ok {
		t.Errorf("expected *expr.Counter, got %T", exprs[0])
	}
}

func TestFromJSON_log(t *testing.T) {
	j := `[{"type":"log","prefix":"DROPPED: ","level":"warn"}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	l := exprs[0].(*expr.Log)
	if string(l.Data) != "DROPPED: " {
		t.Errorf("prefix = %q, want DROPPED: ", string(l.Data))
	}
}

func TestFromJSON_nat(t *testing.T) {
	j := `[{"type":"nat","nat_type":"dnat","family":"ip","reg_addr_min":1}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	n := exprs[0].(*expr.NAT)
	if n.Type != expr.NATTypeDestNAT {
		t.Errorf("nat type = %v, want dnat", n.Type)
	}
}

func TestFromJSON_masq(t *testing.T) {
	j := `[{"type":"masq","random":true}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	m := exprs[0].(*expr.Masq)
	if !m.Random {
		t.Error("expected Random=true")
	}
}

func TestFromJSON_reject(t *testing.T) {
	j := `[{"type":"reject","reject_type":0,"code":3}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	r := exprs[0].(*expr.Reject)
	if r.Code != 3 {
		t.Errorf("code = %d, want 3", r.Code)
	}
}

func TestFromJSON_limit(t *testing.T) {
	j := `[{"type":"limit","rate":10,"unit":"second","burst":5,"limit_type":"pkts"}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	l := exprs[0].(*expr.Limit)
	if l.Rate != 10 || l.Unit != expr.LimitTimeSecond || l.Burst != 5 {
		t.Errorf("unexpected limit: %+v", l)
	}
}

func TestFromJSON_ct(t *testing.T) {
	j := `[{"type":"ct","key":"state","dreg":1}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	c := exprs[0].(*expr.Ct)
	if c.Key != expr.CtKeySTATE || c.Register != 1 {
		t.Errorf("unexpected ct: %+v", c)
	}
}

func TestFromJSON_lookup(t *testing.T) {
	j := `[{"type":"lookup","sreg":1,"set_name":"myset"}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	l := exprs[0].(*expr.Lookup)
	if l.SetName != "myset" || l.SourceRegister != 1 {
		t.Errorf("unexpected lookup: %+v", l)
	}
}

func TestFromJSON_notrack(t *testing.T) {
	j := `[{"type":"notrack"}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	if _, ok := exprs[0].(*expr.Notrack); !ok {
		t.Errorf("expected *expr.Notrack, got %T", exprs[0])
	}
}

func TestFromJSON_queue(t *testing.T) {
	j := `[{"type":"queue","num":1,"flag":1}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	q := exprs[0].(*expr.Queue)
	if q.Num != 1 {
		t.Errorf("num = %d, want 1", q.Num)
	}
}

func TestFromJSON_flowOffload(t *testing.T) {
	j := `[{"type":"flow_offload","name":"ft0"}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	f := exprs[0].(*expr.FlowOffload)
	if f.Name != "ft0" {
		t.Errorf("name = %q, want ft0", f.Name)
	}
}

func TestFromJSON_redir(t *testing.T) {
	j := `[{"type":"redir","reg_proto_min":1}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	r := exprs[0].(*expr.Redir)
	if r.RegisterProtoMin != 1 {
		t.Errorf("reg_proto_min = %d, want 1", r.RegisterProtoMin)
	}
}

func TestFromJSON_fib(t *testing.T) {
	j := `[{"type":"fib","dreg":1,"flag_saddr":true,"result_addrtype":true}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	f := exprs[0].(*expr.Fib)
	if !f.FlagSADDR || !f.ResultADDRTYPE {
		t.Errorf("unexpected fib: %+v", f)
	}
}

func TestFromJSON_range(t *testing.T) {
	from := base64.StdEncoding.EncodeToString([]byte{0, 80})
	to := base64.StdEncoding.EncodeToString([]byte{0, 90})
	j := `[{"type":"range","op":"eq","sreg":1,"from":"` + from + `","to":"` + to + `"}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	r := exprs[0].(*expr.Range)
	if r.Op != expr.CmpOpEq || r.Register != 1 {
		t.Errorf("unexpected range: %+v", r)
	}
}

func TestFromJSON_quota(t *testing.T) {
	j := `[{"type":"quota","bytes":1048576,"over":true}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	q := exprs[0].(*expr.Quota)
	if q.Bytes != 1048576 || !q.Over {
		t.Errorf("unexpected quota: %+v", q)
	}
}

func TestFromJSON_connlimit(t *testing.T) {
	j := `[{"type":"connlimit","count":10}]`
	exprs, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	c := exprs[0].(*expr.Connlimit)
	if c.Count != 10 {
		t.Errorf("count = %d, want 10", c.Count)
	}
}

func TestFromJSON_errors(t *testing.T) {
	tests := []string{
		`invalid json`,
		`[{"type":"unknown_type"}]`,
		`[{"type":"payload","base":"bogus"}]`,
		`[{"type":"cmp","op":"bogus","sreg":1,"data":"AA=="}]`,
		`[{"type":"meta","key":"bogus"}]`,
		`[{"type":"verdict","kind":"bogus"}]`,
		`[{"type":"nat","nat_type":"bogus"}]`,
		`[{"type":"limit","rate":1,"unit":"bogus"}]`,
		`[{"type":"ct","key":"bogus"}]`,
		`[{"type":"log","level":"bogus"}]`,
	}
	for _, j := range tests {
		_, err := FromJSON(j)
		if err == nil {
			t.Errorf("expected error for: %s", j)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	// Build a complete rule: match TCP dport 22, accept
	original := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 22}},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}

	jsonStr, err := ToJSON(original)
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}

	restored, err := FromJSON(jsonStr)
	if err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}

	if len(restored) != len(original) {
		t.Fatalf("length mismatch: %d vs %d", len(restored), len(original))
	}

	// Re-serialize and compare
	jsonStr2, err := ToJSON(restored)
	if err != nil {
		t.Fatalf("ToJSON(2) error: %v", err)
	}
	if jsonStr != jsonStr2 {
		t.Errorf("round-trip mismatch:\n  1: %s\n  2: %s", jsonStr, jsonStr2)
	}
}
