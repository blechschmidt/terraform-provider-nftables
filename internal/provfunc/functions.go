// Package provfunc implements Terraform provider-defined functions for
// composing nftables expressions. Each function wraps a corresponding
// nfthelper function and serializes the result to JSON via nftexpr.
//
// Usage in HCL:
//
//	expr = provider::nftables::combine(
//	    provider::nftables::match_tcp_dport(22),
//	    provider::nftables::counter(),
//	    provider::nftables::accept(),
//	)
package provfunc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/blechschmidt/terraform-provider-nftables/internal/nftexpr"
	"github.com/blechschmidt/terraform-provider-nftables/internal/nfthelper"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// All returns all provider functions for registration in the provider.
func All() []func() function.Function {
	return []func() function.Function{
		NewCombineFunction,
		// Verdicts
		NewAcceptFunction,
		NewDropFunction,
		NewReturnVerdictFunction,
		NewJumpFunction,
		NewGotoChainFunction,
		// Actions
		NewCounterFunction,
		NewLogFunction,
		NewLimitFunction,
		NewLimitBurstFunction,
		NewLimitBytesFunction,
		NewRejectFunction,
		NewRejectTCPResetFunction,
		NewRejectICMPFunction,
		NewRejectICMPv6Function,
		NewRejectICMPxFunction,
		NewMasqueradeFunction,
		NewMasqueradeRandomFunction,
		NewMasqueradePersistentFunction,
		NewMasqueradeFullyRandomFunction,
		NewSNATFunction,
		NewSNATPortFunction,
		NewDNATFunction,
		NewDNATPortFunction,
		NewRedirectFunction,
		NewNotrackFunction,
		NewFlowOffloadFunction,
		NewQueueFunction,
		// Setters
		NewSetMarkFunction,
		NewSetCTMarkFunction,
		NewSetPriorityFunction,
		NewSetNftraceFunction,
		// IPv4 matchers
		NewMatchIPSaddrFunction,
		NewMatchIPDaddrFunction,
		NewMatchIPProtocolFunction,
		NewMatchIPTTLFunction,
		NewMatchIPLengthFunction,
		NewMatchIPDscpFunction,
		NewMatchIPIdFunction,
		NewMatchIPVersionFunction,
		NewMatchIPHdrLengthFunction,
		// IPv6 matchers
		NewMatchIP6SaddrFunction,
		NewMatchIP6DaddrFunction,
		NewMatchIP6HopLimitFunction,
		NewMatchIP6NextHdrFunction,
		NewMatchIP6FlowLabelFunction,
		NewMatchIP6LengthFunction,
		NewMatchIP6VersionFunction,
		// Transport matchers
		NewMatchTCPDportFunction,
		NewMatchTCPSportFunction,
		NewMatchTCPFlagsFunction,
		NewMatchTCPSequenceFunction,
		NewMatchTCPWindowFunction,
		NewMatchUDPDportFunction,
		NewMatchUDPSportFunction,
		NewMatchUDPLengthFunction,
		NewMatchSCTPDportFunction,
		NewMatchSCTPSportFunction,
		NewMatchDCCPDportFunction,
		NewMatchDCCPSportFunction,
		// Link-layer matchers
		NewMatchEtherSaddrFunction,
		NewMatchEtherTypeFunction,
		NewMatchVLANIdFunction,
		NewMatchARPOperationFunction,
		NewMatchARPHtypeFunction,
		// ICMP
		NewMatchICMPTypeFunction,
		NewMatchICMPv6TypeFunction,
		// Meta matchers
		NewMatchIifnameFunction,
		NewMatchOifnameFunction,
		NewMatchMarkFunction,
		NewMatchNfprotoFunction,
		NewMatchL4ProtoFunction,
		NewMatchPktTypeFunction,
		NewMatchSkuidFunction,
		NewMatchSkgidFunction,
		NewMatchMetaLengthFunction,
		NewMatchMetaProtocolFunction,
		// CT matchers
		NewMatchCTStateFunction,
		NewMatchCTMarkFunction,
		NewMatchCTStatusFunction,
		NewMatchCTDirectionFunction,
		// Loaders — load field into register without comparing
		NewLoadIPSaddrFunction,
		NewLoadIPDaddrFunction,
		NewLoadIPProtocolFunction,
		NewLoadIPTTLFunction,
		NewLoadIPLengthFunction,
		NewLoadIP6SaddrFunction,
		NewLoadIP6DaddrFunction,
		NewLoadIP6NextHdrFunction,
		NewLoadIP6HopLimitFunction,
		NewLoadTCPDportFunction,
		NewLoadTCPSportFunction,
		NewLoadTCPFlagsFunction,
		NewLoadUDPDportFunction,
		NewLoadUDPSportFunction,
		NewLoadSCTPDportFunction,
		NewLoadSCTPSportFunction,
		NewLoadEtherSaddrFunction,
		NewLoadEtherDaddrFunction,
		NewLoadEtherTypeFunction,
		NewLoadMetaIifnameFunction,
		NewLoadMetaOifnameFunction,
		NewLoadMetaMarkFunction,
		NewLoadMetaNfprotoFunction,
		NewLoadMetaL4protoFunction,
		NewLoadMetaProtocolFunction,
		NewLoadMetaPkttypeFunction,
		NewLoadCTStateFunction,
		NewLoadCTMarkFunction,
		NewLoadCTStatusFunction,
		// Lookup — set membership test on register
		NewLookupFunction,
		NewLookupInvFunction,
		// Comparisons — compare register value
		NewCmpIPv4Function,
		NewCmpIPv6Function,
		NewCmpPortFunction,
	}
}

// ---------------------------------------------------------------------------
// Helper: convert []expr.Any -> JSON string for returning from functions
// ---------------------------------------------------------------------------

func toJSONString(exprs []expr.Any) (string, *function.FuncError) {
	if exprs == nil {
		return "[]", nil
	}
	s, err := nftexpr.ToJSON(exprs)
	if err != nil {
		return "", function.NewFuncError(fmt.Sprintf("failed to serialize expressions: %s", err))
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// combine() — variadic function that merges expression JSON lists
// ---------------------------------------------------------------------------

type CombineFunction struct{}

func NewCombineFunction() function.Function { return &CombineFunction{} }

func (f *CombineFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "combine"
}

func (f *CombineFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:     "Combine multiple expression lists into a single rule expression",
		Description: "Concatenates JSON expression lists produced by matcher and action functions into one list suitable for the expr attribute.",
		VariadicParameter: function.StringParameter{
			Name:        "parts",
			Description: "JSON expression lists to combine",
		},
		Return: function.StringReturn{},
	}
}

func (f *CombineFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var parts []string
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &parts))
	if resp.Error != nil {
		return
	}

	var allExprs []expr.Any
	for _, part := range parts {
		exprs, err := nftexpr.FromJSON(part)
		if err != nil {
			resp.Error = function.NewFuncError(fmt.Sprintf("invalid expression JSON: %s", err))
			return
		}
		allExprs = append(allExprs, exprs...)
	}

	result, funcErr := toJSONString(allExprs)
	if funcErr != nil {
		resp.Error = funcErr
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, result))
}

// ---------------------------------------------------------------------------
// Generic function builders — reduce boilerplate for simple functions
// ---------------------------------------------------------------------------

// noArgFunc creates a function that takes no arguments and returns a fixed expression list.
type noArgFunc struct {
	name    string
	summary string
	fn      func() []expr.Any
}

func (f *noArgFunc) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = f.name
}

func (f *noArgFunc) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: f.summary,
		Return:  function.StringReturn{},
	}
}

func (f *noArgFunc) Run(ctx context.Context, _ function.RunRequest, resp *function.RunResponse) {
	result, funcErr := toJSONString(f.fn())
	if funcErr != nil {
		resp.Error = funcErr
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, result))
}

// stringArgFunc creates a function that takes one string argument.
type stringArgFunc struct {
	name      string
	summary   string
	paramName string
	paramDesc string
	fn        func(string) []expr.Any
}

func (f *stringArgFunc) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = f.name
}

func (f *stringArgFunc) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:    f.summary,
		Parameters: []function.Parameter{function.StringParameter{Name: f.paramName, Description: f.paramDesc}},
		Return:     function.StringReturn{},
	}
}

func (f *stringArgFunc) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var arg string
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &arg))
	if resp.Error != nil {
		return
	}
	result, funcErr := toJSONString(f.fn(arg))
	if funcErr != nil {
		resp.Error = funcErr
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, result))
}

// numberArgFunc creates a function that takes one int64 argument.
type numberArgFunc struct {
	name      string
	summary   string
	paramName string
	paramDesc string
	fn        func(int64) []expr.Any
}

func (f *numberArgFunc) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = f.name
}

func (f *numberArgFunc) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:    f.summary,
		Parameters: []function.Parameter{function.Int64Parameter{Name: f.paramName, Description: f.paramDesc}},
		Return:     function.StringReturn{},
	}
}

func (f *numberArgFunc) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var arg int64
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &arg))
	if resp.Error != nil {
		return
	}
	result, funcErr := toJSONString(f.fn(arg))
	if funcErr != nil {
		resp.Error = funcErr
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, result))
}

// ---------------------------------------------------------------------------
// Verdict functions
// ---------------------------------------------------------------------------

func NewAcceptFunction() function.Function {
	return &noArgFunc{name: "accept", summary: "Accept the packet", fn: nfthelper.Accept}
}
func NewDropFunction() function.Function {
	return &noArgFunc{name: "drop", summary: "Drop the packet", fn: nfthelper.Drop}
}
func NewReturnVerdictFunction() function.Function {
	return &noArgFunc{name: "return_verdict", summary: "Return from current chain", fn: nfthelper.Return}
}
func NewJumpFunction() function.Function {
	return &stringArgFunc{name: "jump", summary: "Jump to another chain", paramName: "chain", paramDesc: "Target chain name", fn: nfthelper.Jump}
}
func NewGotoChainFunction() function.Function {
	return &stringArgFunc{name: "goto_chain", summary: "Goto another chain (no return)", paramName: "chain", paramDesc: "Target chain name", fn: nfthelper.Goto}
}

// ---------------------------------------------------------------------------
// Action functions
// ---------------------------------------------------------------------------

func NewCounterFunction() function.Function {
	return &noArgFunc{name: "counter", summary: "Inline packet/byte counter", fn: nfthelper.Counter}
}

func NewNotrackFunction() function.Function {
	return &noArgFunc{name: "notrack", summary: "Disable connection tracking", fn: nfthelper.Notrack}
}

func NewRejectFunction() function.Function {
	return &noArgFunc{name: "reject", summary: "Reject with default ICMP error", fn: nfthelper.Reject}
}

func NewRejectTCPResetFunction() function.Function {
	return &noArgFunc{name: "reject_tcp_reset", summary: "Reject with TCP RST", fn: nfthelper.RejectTCPReset}
}

func NewRejectICMPFunction() function.Function {
	return &stringArgFunc{name: "reject_icmp", summary: "Reject with ICMP code", paramName: "code", paramDesc: "ICMP code: port-unreachable, host-unreachable, net-unreachable, admin-prohibited, etc.", fn: nfthelper.RejectICMP}
}

func NewRejectICMPv6Function() function.Function {
	return &stringArgFunc{name: "reject_icmpv6", summary: "Reject with ICMPv6 code", paramName: "code", paramDesc: "ICMPv6 code: no-route, admin-prohibited, addr-unreachable, port-unreachable", fn: nfthelper.RejectICMPv6}
}

func NewRejectICMPxFunction() function.Function {
	return &stringArgFunc{name: "reject_icmpx", summary: "Reject with ICMPx code (inet family)", paramName: "code", paramDesc: "ICMPx code: port-unreachable, admin-prohibited, no-route, host-unreachable", fn: nfthelper.RejectICMPx}
}

func NewMasqueradeFunction() function.Function {
	return &noArgFunc{name: "masquerade", summary: "Masquerade (auto source NAT)", fn: nfthelper.Masquerade}
}

func NewMasqueradeRandomFunction() function.Function {
	return &noArgFunc{name: "masquerade_random", summary: "Masquerade with random port selection", fn: nfthelper.MasqueradeRandom}
}

func NewMasqueradePersistentFunction() function.Function {
	return &noArgFunc{name: "masquerade_persistent", summary: "Masquerade with persistent mapping", fn: nfthelper.MasqueradePersistent}
}

func NewMasqueradeFullyRandomFunction() function.Function {
	return &noArgFunc{name: "masquerade_fully_random", summary: "Masquerade with fully random port selection", fn: nfthelper.MasqueradeFullyRandom}
}

func NewSNATFunction() function.Function {
	return &stringArgFunc{name: "snat", summary: "Source NAT to address", paramName: "addr", paramDesc: "Target IPv4 address", fn: nfthelper.SNAT}
}

func NewDNATFunction() function.Function {
	return &stringArgFunc{name: "dnat", summary: "Destination NAT to address", paramName: "addr", paramDesc: "Target IPv4 address", fn: nfthelper.DNAT}
}

func NewFlowOffloadFunction() function.Function {
	return &stringArgFunc{name: "flow_offload", summary: "Offload flow to named flowtable", paramName: "name", paramDesc: "Flowtable name", fn: nfthelper.FlowOffload}
}

func NewSetMarkFunction() function.Function {
	return &numberArgFunc{name: "set_mark", summary: "Set packet mark", paramName: "mark", paramDesc: "Mark value", fn: func(v int64) []expr.Any { return nfthelper.SetMark(uint32(v)) }}
}

func NewSetCTMarkFunction() function.Function {
	return &numberArgFunc{name: "set_ct_mark", summary: "Set conntrack mark", paramName: "mark", paramDesc: "CT mark value", fn: func(v int64) []expr.Any { return nfthelper.SetCTMark(uint32(v)) }}
}

// ---------------------------------------------------------------------------
// Functions with custom signatures
// ---------------------------------------------------------------------------

// --- log(prefix, level) ---

type LogFunction struct{}

func NewLogFunction() function.Function { return &LogFunction{} }
func (f *LogFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "log"
}
func (f *LogFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "Log matching packets",
		Parameters: []function.Parameter{
			function.StringParameter{Name: "prefix", Description: "Log prefix string"},
			function.StringParameter{Name: "level", Description: "Log level: emerg, alert, crit, err, warn, notice, info, debug"},
		},
		Return: function.StringReturn{},
	}
}
func (f *LogFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var prefix, level string
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &prefix, &level))
	if resp.Error != nil {
		return
	}
	result, funcErr := toJSONString(nfthelper.LogLevel(prefix, level))
	if funcErr != nil {
		resp.Error = funcErr
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, result))
}

// --- limit(rate, unit) ---

type LimitFunction struct{}

func NewLimitFunction() function.Function { return &LimitFunction{} }
func (f *LimitFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "limit"
}
func (f *LimitFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "Rate limit packets",
		Parameters: []function.Parameter{
			function.Int64Parameter{Name: "rate", Description: "Rate value"},
			function.StringParameter{Name: "unit", Description: "Time unit: second, minute, hour, day, week"},
		},
		Return: function.StringReturn{},
	}
}
func (f *LimitFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var rate int64
	var unit string
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &rate, &unit))
	if resp.Error != nil {
		return
	}
	result, funcErr := toJSONString(nfthelper.Limit(uint64(rate), unit))
	if funcErr != nil {
		resp.Error = funcErr
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, result))
}

// --- limit_burst(rate, unit, burst) ---

type LimitBurstFunction struct{}

func NewLimitBurstFunction() function.Function { return &LimitBurstFunction{} }
func (f *LimitBurstFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "limit_burst"
}
func (f *LimitBurstFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "Rate limit packets with burst",
		Parameters: []function.Parameter{
			function.Int64Parameter{Name: "rate", Description: "Rate value"},
			function.StringParameter{Name: "unit", Description: "Time unit: second, minute, hour, day, week"},
			function.Int64Parameter{Name: "burst", Description: "Burst value"},
		},
		Return: function.StringReturn{},
	}
}
func (f *LimitBurstFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var rate, burst int64
	var unit string
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &rate, &unit, &burst))
	if resp.Error != nil {
		return
	}
	result, funcErr := toJSONString(nfthelper.LimitBurst(uint64(rate), unit, uint32(burst)))
	if funcErr != nil {
		resp.Error = funcErr
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, result))
}

// --- limit_bytes(rate, unit) ---

type LimitBytesFunction struct{}

func NewLimitBytesFunction() function.Function { return &LimitBytesFunction{} }
func (f *LimitBytesFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "limit_bytes"
}
func (f *LimitBytesFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "Rate limit bytes",
		Parameters: []function.Parameter{
			function.Int64Parameter{Name: "rate", Description: "Rate in bytes"},
			function.StringParameter{Name: "unit", Description: "Time unit: second, minute, hour, day, week"},
		},
		Return: function.StringReturn{},
	}
}
func (f *LimitBytesFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var rate int64
	var unit string
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &rate, &unit))
	if resp.Error != nil {
		return
	}
	result, funcErr := toJSONString(nfthelper.LimitBytes(uint64(rate), unit))
	if funcErr != nil {
		resp.Error = funcErr
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, result))
}

// --- snat_port(addr, port) / dnat_port(addr, port) / redirect(port) ---

type SNATPortFunction struct{}

func NewSNATPortFunction() function.Function { return &SNATPortFunction{} }
func (f *SNATPortFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "snat_port"
}
func (f *SNATPortFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "Source NAT to address and port",
		Parameters: []function.Parameter{
			function.StringParameter{Name: "addr", Description: "Target IPv4 address"},
			function.Int64Parameter{Name: "port", Description: "Target port"},
		},
		Return: function.StringReturn{},
	}
}
func (f *SNATPortFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var addr string
	var port int64
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &addr, &port))
	if resp.Error != nil {
		return
	}
	result, funcErr := toJSONString(nfthelper.SNATPort(addr, uint16(port)))
	if funcErr != nil {
		resp.Error = funcErr
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, result))
}

type DNATPortFunction struct{}

func NewDNATPortFunction() function.Function { return &DNATPortFunction{} }
func (f *DNATPortFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "dnat_port"
}
func (f *DNATPortFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "Destination NAT to address and port",
		Parameters: []function.Parameter{
			function.StringParameter{Name: "addr", Description: "Target IPv4 address"},
			function.Int64Parameter{Name: "port", Description: "Target port"},
		},
		Return: function.StringReturn{},
	}
}
func (f *DNATPortFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var addr string
	var port int64
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &addr, &port))
	if resp.Error != nil {
		return
	}
	result, funcErr := toJSONString(nfthelper.DNATPort(addr, uint16(port)))
	if funcErr != nil {
		resp.Error = funcErr
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, result))
}

type RedirectFunction struct{}

func NewRedirectFunction() function.Function { return &RedirectFunction{} }
func (f *RedirectFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "redirect"
}
func (f *RedirectFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:    "Redirect to local port",
		Parameters: []function.Parameter{function.Int64Parameter{Name: "port", Description: "Target port"}},
		Return:     function.StringReturn{},
	}
}
func (f *RedirectFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var port int64
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &port))
	if resp.Error != nil {
		return
	}
	result, funcErr := toJSONString(nfthelper.Redirect(uint16(port)))
	if funcErr != nil {
		resp.Error = funcErr
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, result))
}

type QueueFunction struct{}

func NewQueueFunction() function.Function { return &QueueFunction{} }
func (f *QueueFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "queue"
}
func (f *QueueFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:    "Queue to userspace",
		Parameters: []function.Parameter{function.Int64Parameter{Name: "num", Description: "Queue number"}},
		Return:     function.StringReturn{},
	}
}
func (f *QueueFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var num int64
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &num))
	if resp.Error != nil {
		return
	}
	result, funcErr := toJSONString(nfthelper.Queue(uint16(num)))
	if funcErr != nil {
		resp.Error = funcErr
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, result))
}

// --- set_priority / set_nftrace ---

func NewSetPriorityFunction() function.Function {
	return &numberArgFunc{name: "set_priority", summary: "Set packet priority", paramName: "priority", paramDesc: "Priority value", fn: func(v int64) []expr.Any { return nfthelper.SetPriority(uint32(v)) }}
}

func NewSetNftraceFunction() function.Function {
	return &noArgFunc{name: "set_nftrace", summary: "Enable nftrace for debugging", fn: func() []expr.Any { return nfthelper.SetNftrace(true) }}
}

// ---------------------------------------------------------------------------
// IPv4 / IPv6 matchers
// ---------------------------------------------------------------------------

func NewMatchIPSaddrFunction() function.Function {
	return &stringArgFunc{name: "match_ip_saddr", summary: "Match IPv4 source address (IP or CIDR)", paramName: "addr", paramDesc: "IPv4 address or CIDR", fn: nfthelper.MatchIPSaddr}
}
func NewMatchIPDaddrFunction() function.Function {
	return &stringArgFunc{name: "match_ip_daddr", summary: "Match IPv4 destination address (IP or CIDR)", paramName: "addr", paramDesc: "IPv4 address or CIDR", fn: nfthelper.MatchIPDaddr}
}
func NewMatchIPProtocolFunction() function.Function {
	return &stringArgFunc{name: "match_ip_protocol", summary: "Match IP protocol (tcp, udp, icmp, ...)", paramName: "proto", paramDesc: "Protocol name", fn: nfthelper.MatchIPProtocol}
}
func NewMatchIPTTLFunction() function.Function {
	return &numberArgFunc{name: "match_ip_ttl", summary: "Match IP TTL", paramName: "ttl", paramDesc: "TTL value", fn: func(v int64) []expr.Any { return nfthelper.MatchIPTTL(uint8(v)) }}
}
func NewMatchIPLengthFunction() function.Function {
	return &numberArgFunc{name: "match_ip_length", summary: "Match IP total length", paramName: "length", paramDesc: "Length value", fn: func(v int64) []expr.Any { return nfthelper.MatchIPLength(uint16(v)) }}
}
func NewMatchIP6SaddrFunction() function.Function {
	return &stringArgFunc{name: "match_ip6_saddr", summary: "Match IPv6 source address (IP or CIDR)", paramName: "addr", paramDesc: "IPv6 address or CIDR", fn: nfthelper.MatchIP6Saddr}
}
func NewMatchIP6DaddrFunction() function.Function {
	return &stringArgFunc{name: "match_ip6_daddr", summary: "Match IPv6 destination address (IP or CIDR)", paramName: "addr", paramDesc: "IPv6 address or CIDR", fn: nfthelper.MatchIP6Daddr}
}
func NewMatchIP6HopLimitFunction() function.Function {
	return &numberArgFunc{name: "match_ip6_hoplimit", summary: "Match IPv6 hop limit", paramName: "hoplimit", paramDesc: "Hop limit value", fn: func(v int64) []expr.Any { return nfthelper.MatchIP6HopLimit(uint8(v)) }}
}
func NewMatchIP6NextHdrFunction() function.Function {
	return &stringArgFunc{name: "match_ip6_nexthdr", summary: "Match IPv6 next header protocol", paramName: "proto", paramDesc: "Protocol name (tcp, udp, icmpv6, ...)", fn: nfthelper.MatchIP6NextHdr}
}

// ---------------------------------------------------------------------------
// Transport matchers
// ---------------------------------------------------------------------------

func NewMatchTCPDportFunction() function.Function {
	return &numberArgFunc{name: "match_tcp_dport", summary: "Match TCP destination port", paramName: "port", paramDesc: "Port number", fn: func(v int64) []expr.Any { return nfthelper.MatchTCPDport(uint16(v)) }}
}
func NewMatchTCPSportFunction() function.Function {
	return &numberArgFunc{name: "match_tcp_sport", summary: "Match TCP source port", paramName: "port", paramDesc: "Port number", fn: func(v int64) []expr.Any { return nfthelper.MatchTCPSport(uint16(v)) }}
}
func NewMatchTCPFlagsFunction() function.Function {
	return &stringArgFunc{name: "match_tcp_flags", summary: "Match TCP flags", paramName: "flags", paramDesc: "Pipe-separated flags: syn|ack|fin|rst|psh|urg|ecn|cwr", fn: nfthelper.MatchTCPFlags}
}
func NewMatchUDPDportFunction() function.Function {
	return &numberArgFunc{name: "match_udp_dport", summary: "Match UDP destination port", paramName: "port", paramDesc: "Port number", fn: func(v int64) []expr.Any { return nfthelper.MatchUDPDport(uint16(v)) }}
}
func NewMatchUDPSportFunction() function.Function {
	return &numberArgFunc{name: "match_udp_sport", summary: "Match UDP source port", paramName: "port", paramDesc: "Port number", fn: func(v int64) []expr.Any { return nfthelper.MatchUDPSport(uint16(v)) }}
}
func NewMatchSCTPDportFunction() function.Function {
	return &numberArgFunc{name: "match_sctp_dport", summary: "Match SCTP destination port", paramName: "port", paramDesc: "Port number", fn: func(v int64) []expr.Any { return nfthelper.MatchSCTPDport(uint16(v)) }}
}
func NewMatchSCTPSportFunction() function.Function {
	return &numberArgFunc{name: "match_sctp_sport", summary: "Match SCTP source port", paramName: "port", paramDesc: "Port number", fn: func(v int64) []expr.Any { return nfthelper.MatchSCTPSport(uint16(v)) }}
}
func NewMatchDCCPDportFunction() function.Function {
	return &numberArgFunc{name: "match_dccp_dport", summary: "Match DCCP destination port", paramName: "port", paramDesc: "Port number", fn: func(v int64) []expr.Any { return nfthelper.MatchDCCPDport(uint16(v)) }}
}
func NewMatchDCCPSportFunction() function.Function {
	return &numberArgFunc{name: "match_dccp_sport", summary: "Match DCCP source port", paramName: "port", paramDesc: "Port number", fn: func(v int64) []expr.Any { return nfthelper.MatchDCCPSport(uint16(v)) }}
}

// ---------------------------------------------------------------------------
// ICMP matchers
// ---------------------------------------------------------------------------

func NewMatchICMPTypeFunction() function.Function {
	return &stringArgFunc{name: "match_icmp_type", summary: "Match ICMP type", paramName: "type_name", paramDesc: "ICMP type: echo-request, echo-reply, destination-unreachable, etc.", fn: nfthelper.MatchICMPType}
}
func NewMatchICMPv6TypeFunction() function.Function {
	return &stringArgFunc{name: "match_icmpv6_type", summary: "Match ICMPv6 type", paramName: "type_name", paramDesc: "ICMPv6 type: echo-request, echo-reply, nd-neighbor-solicit, etc.", fn: nfthelper.MatchICMPv6Type}
}

// ---------------------------------------------------------------------------
// Meta matchers
// ---------------------------------------------------------------------------

func NewMatchIifnameFunction() function.Function {
	return &stringArgFunc{name: "match_iifname", summary: "Match input interface name", paramName: "name", paramDesc: "Interface name (e.g., eth0, lo)", fn: nfthelper.MatchIifname}
}
func NewMatchOifnameFunction() function.Function {
	return &stringArgFunc{name: "match_oifname", summary: "Match output interface name", paramName: "name", paramDesc: "Interface name", fn: nfthelper.MatchOifname}
}
func NewMatchMarkFunction() function.Function {
	return &numberArgFunc{name: "match_mark", summary: "Match packet mark", paramName: "mark", paramDesc: "Mark value", fn: func(v int64) []expr.Any { return nfthelper.MatchMark(uint32(v)) }}
}
func NewMatchNfprotoFunction() function.Function {
	return &stringArgFunc{name: "match_nfproto", summary: "Match nfproto (ipv4 or ipv6)", paramName: "proto", paramDesc: "Protocol: ipv4 or ipv6", fn: func(proto string) []expr.Any {
		switch proto {
		case "ipv4", "ip":
			return nfthelper.MatchNfproto(2)
		case "ipv6", "ip6":
			return nfthelper.MatchNfproto(10)
		default:
			return nil
		}
	}}
}
func NewMatchL4ProtoFunction() function.Function {
	return &stringArgFunc{name: "match_l4proto", summary: "Match L4 protocol by name", paramName: "proto", paramDesc: "Protocol: tcp, udp, icmp, icmpv6, sctp, dccp, etc.", fn: nfthelper.MatchIPProtocol}
}
func NewMatchPktTypeFunction() function.Function {
	return &stringArgFunc{name: "match_pkttype", summary: "Match packet type", paramName: "pkttype", paramDesc: "Packet type: host, broadcast, multicast, other", fn: nfthelper.MatchPktType}
}
func NewMatchSkuidFunction() function.Function {
	return &numberArgFunc{name: "match_skuid", summary: "Match socket UID", paramName: "uid", paramDesc: "UID value", fn: func(v int64) []expr.Any { return nfthelper.MatchSkuid(uint32(v)) }}
}
func NewMatchSkgidFunction() function.Function {
	return &numberArgFunc{name: "match_skgid", summary: "Match socket GID", paramName: "gid", paramDesc: "GID value", fn: func(v int64) []expr.Any { return nfthelper.MatchSkgid(uint32(v)) }}
}

// ---------------------------------------------------------------------------
// CT matchers
// ---------------------------------------------------------------------------

// match_ct_state takes a list of state names
type MatchCTStateFunction struct{}

func NewMatchCTStateFunction() function.Function { return &MatchCTStateFunction{} }
func (f *MatchCTStateFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "match_ct_state"
}
func (f *MatchCTStateFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "Match conntrack state",
		Parameters: []function.Parameter{
			function.ListParameter{
				Name:        "states",
				Description: "List of states: new, established, related, invalid, untracked",
				ElementType: types.StringType,
			},
		},
		Return: function.StringReturn{},
	}
}
func (f *MatchCTStateFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var states []string
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &states))
	if resp.Error != nil {
		return
	}
	result, funcErr := toJSONString(nfthelper.MatchCTState(states...))
	if funcErr != nil {
		resp.Error = funcErr
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, result))
}

func NewMatchCTMarkFunction() function.Function {
	return &numberArgFunc{name: "match_ct_mark", summary: "Match conntrack mark", paramName: "mark", paramDesc: "CT mark value", fn: func(v int64) []expr.Any { return nfthelper.MatchCTMark(uint32(v)) }}
}

// match_ct_status takes a list of status names
type MatchCTStatusFunction struct{}

func NewMatchCTStatusFunction() function.Function { return &MatchCTStatusFunction{} }
func (f *MatchCTStatusFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "match_ct_status"
}
func (f *MatchCTStatusFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "Match conntrack status",
		Parameters: []function.Parameter{
			function.ListParameter{
				Name:        "statuses",
				Description: "List of statuses: expected, seen-reply, assured, confirmed, snat, dnat, dying",
				ElementType: types.StringType,
			},
		},
		Return: function.StringReturn{},
	}
}
func (f *MatchCTStatusFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var statuses []string
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &statuses))
	if resp.Error != nil {
		return
	}
	result, funcErr := toJSONString(nfthelper.MatchCTStatus(statuses...))
	if funcErr != nil {
		resp.Error = funcErr
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, result))
}

func NewMatchCTDirectionFunction() function.Function {
	return &stringArgFunc{name: "match_ct_direction", summary: "Match conntrack direction", paramName: "direction", paramDesc: "Direction: original or reply", fn: nfthelper.MatchCTDirection}
}

// ---------------------------------------------------------------------------
// Loaders — load a field into register 1 without comparing
// ---------------------------------------------------------------------------

func NewLoadIPSaddrFunction() function.Function {
	return &noArgFunc{name: "load_ip_saddr", summary: "Load IPv4 source address into register", fn: nfthelper.LoadIPSaddr}
}
func NewLoadIPDaddrFunction() function.Function {
	return &noArgFunc{name: "load_ip_daddr", summary: "Load IPv4 destination address into register", fn: nfthelper.LoadIPDaddr}
}
func NewLoadIPProtocolFunction() function.Function {
	return &noArgFunc{name: "load_ip_protocol", summary: "Load IP protocol field into register", fn: nfthelper.LoadIPProtocol}
}
func NewLoadIPTTLFunction() function.Function {
	return &noArgFunc{name: "load_ip_ttl", summary: "Load IP TTL into register", fn: nfthelper.LoadIPTTL}
}
func NewLoadIPLengthFunction() function.Function {
	return &noArgFunc{name: "load_ip_length", summary: "Load IP total length into register", fn: nfthelper.LoadIPLength}
}
func NewLoadIP6SaddrFunction() function.Function {
	return &noArgFunc{name: "load_ip6_saddr", summary: "Load IPv6 source address into register", fn: nfthelper.LoadIP6Saddr}
}
func NewLoadIP6DaddrFunction() function.Function {
	return &noArgFunc{name: "load_ip6_daddr", summary: "Load IPv6 destination address into register", fn: nfthelper.LoadIP6Daddr}
}
func NewLoadIP6NextHdrFunction() function.Function {
	return &noArgFunc{name: "load_ip6_nexthdr", summary: "Load IPv6 next header into register", fn: nfthelper.LoadIP6NextHdr}
}
func NewLoadIP6HopLimitFunction() function.Function {
	return &noArgFunc{name: "load_ip6_hoplimit", summary: "Load IPv6 hop limit into register", fn: nfthelper.LoadIP6HopLimit}
}
func NewLoadTCPDportFunction() function.Function {
	return &noArgFunc{name: "load_tcp_dport", summary: "Load TCP destination port into register", fn: nfthelper.LoadTCPDport}
}
func NewLoadTCPSportFunction() function.Function {
	return &noArgFunc{name: "load_tcp_sport", summary: "Load TCP source port into register", fn: nfthelper.LoadTCPSport}
}
func NewLoadTCPFlagsFunction() function.Function {
	return &noArgFunc{name: "load_tcp_flags", summary: "Load TCP flags byte into register", fn: nfthelper.LoadTCPFlags}
}
func NewLoadUDPDportFunction() function.Function {
	return &noArgFunc{name: "load_udp_dport", summary: "Load UDP destination port into register", fn: nfthelper.LoadUDPDport}
}
func NewLoadUDPSportFunction() function.Function {
	return &noArgFunc{name: "load_udp_sport", summary: "Load UDP source port into register", fn: nfthelper.LoadUDPSport}
}
func NewLoadSCTPDportFunction() function.Function {
	return &noArgFunc{name: "load_sctp_dport", summary: "Load SCTP destination port into register", fn: nfthelper.LoadSCTPDport}
}
func NewLoadSCTPSportFunction() function.Function {
	return &noArgFunc{name: "load_sctp_sport", summary: "Load SCTP source port into register", fn: nfthelper.LoadSCTPSport}
}
func NewLoadEtherSaddrFunction() function.Function {
	return &noArgFunc{name: "load_ether_saddr", summary: "Load Ethernet source MAC into register", fn: nfthelper.LoadEtherSaddr}
}
func NewLoadEtherDaddrFunction() function.Function {
	return &noArgFunc{name: "load_ether_daddr", summary: "Load Ethernet destination MAC into register", fn: nfthelper.LoadEtherDaddr}
}
func NewLoadEtherTypeFunction() function.Function {
	return &noArgFunc{name: "load_ether_type", summary: "Load Ethernet type into register", fn: nfthelper.LoadEtherType}
}
func NewLoadMetaIifnameFunction() function.Function {
	return &noArgFunc{name: "load_meta_iifname", summary: "Load input interface name into register", fn: nfthelper.LoadMetaIifname}
}
func NewLoadMetaOifnameFunction() function.Function {
	return &noArgFunc{name: "load_meta_oifname", summary: "Load output interface name into register", fn: nfthelper.LoadMetaOifname}
}
func NewLoadMetaMarkFunction() function.Function {
	return &noArgFunc{name: "load_meta_mark", summary: "Load packet mark into register", fn: nfthelper.LoadMetaMark}
}
func NewLoadMetaNfprotoFunction() function.Function {
	return &noArgFunc{name: "load_meta_nfproto", summary: "Load nfproto into register", fn: nfthelper.LoadMetaNfproto}
}
func NewLoadMetaL4protoFunction() function.Function {
	return &noArgFunc{name: "load_meta_l4proto", summary: "Load L4 protocol into register", fn: nfthelper.LoadMetaL4proto}
}
func NewLoadMetaProtocolFunction() function.Function {
	return &noArgFunc{name: "load_meta_protocol", summary: "Load EtherType protocol into register", fn: nfthelper.LoadMetaProtocol}
}
func NewLoadMetaPkttypeFunction() function.Function {
	return &noArgFunc{name: "load_meta_pkttype", summary: "Load packet type into register", fn: nfthelper.LoadMetaPkttype}
}
func NewLoadCTStateFunction() function.Function {
	return &noArgFunc{name: "load_ct_state", summary: "Load conntrack state into register", fn: nfthelper.LoadCTState}
}
func NewLoadCTMarkFunction() function.Function {
	return &noArgFunc{name: "load_ct_mark", summary: "Load conntrack mark into register", fn: nfthelper.LoadCTMark}
}
func NewLoadCTStatusFunction() function.Function {
	return &noArgFunc{name: "load_ct_status", summary: "Load conntrack status into register", fn: nfthelper.LoadCTStatus}
}

// ---------------------------------------------------------------------------
// Lookup — set membership test on register value
// ---------------------------------------------------------------------------

func NewLookupFunction() function.Function {
	return &stringArgFunc{name: "lookup", summary: "Check if register value is in named set", paramName: "set_name", paramDesc: "Name of the nftables set", fn: nfthelper.Lookup}
}
func NewLookupInvFunction() function.Function {
	return &stringArgFunc{name: "lookup_inv", summary: "Check if register value is NOT in named set", paramName: "set_name", paramDesc: "Name of the nftables set", fn: nfthelper.LookupInv}
}

// ---------------------------------------------------------------------------
// Comparisons — compare register value against constants or CIDRs
// ---------------------------------------------------------------------------

func NewCmpIPv4Function() function.Function {
	return &stringArgFunc{name: "cmp_ipv4", summary: "Compare register against IPv4 address or CIDR", paramName: "addr", paramDesc: "IPv4 address or CIDR (e.g., 10.0.0.0/8)", fn: nfthelper.CmpIPv4}
}
func NewCmpIPv6Function() function.Function {
	return &stringArgFunc{name: "cmp_ipv6", summary: "Compare register against IPv6 address or CIDR", paramName: "addr", paramDesc: "IPv6 address or CIDR (e.g., fd00::/8)", fn: nfthelper.CmpIPv6}
}
func NewCmpPortFunction() function.Function {
	return &numberArgFunc{name: "cmp_port", summary: "Compare register against port number", paramName: "port", paramDesc: "Port number", fn: func(v int64) []expr.Any { return nfthelper.CmpPort(uint16(v)) }}
}

// ---------------------------------------------------------------------------
// Additional header-field matchers (quick-reference coverage)
// ---------------------------------------------------------------------------

func NewMatchIPDscpFunction() function.Function {
	return &numberArgFunc{name: "match_ip_dscp", summary: "Match IPv4 DSCP value (0-63)", paramName: "dscp", paramDesc: "DSCP value (e.g. 0 for cs0, 8 for cs1, 46 for ef)", fn: func(v int64) []expr.Any { return nfthelper.MatchIPDSCP(uint8(v)) }}
}
func NewMatchIPIdFunction() function.Function {
	return &numberArgFunc{name: "match_ip_id", summary: "Match IPv4 identification field", paramName: "id", paramDesc: "IP id value", fn: func(v int64) []expr.Any { return nfthelper.MatchIPId(uint16(v)) }}
}
func NewMatchIPVersionFunction() function.Function {
	return &numberArgFunc{name: "match_ip_version", summary: "Match IP version field", paramName: "version", paramDesc: "Version (4 for IPv4, 6 for IPv6)", fn: func(v int64) []expr.Any { return nfthelper.MatchIPVersion(uint8(v)) }}
}
func NewMatchIPHdrLengthFunction() function.Function {
	return &numberArgFunc{name: "match_ip_hdrlength", summary: "Match IPv4 header length (in 32-bit words)", paramName: "hdrlength", paramDesc: "Header length value", fn: func(v int64) []expr.Any { return nfthelper.MatchIPHdrLength(uint8(v)) }}
}
func NewMatchIP6FlowLabelFunction() function.Function {
	return &numberArgFunc{name: "match_ip6_flowlabel", summary: "Match IPv6 flow label", paramName: "flowlabel", paramDesc: "Flow label value (20 bits)", fn: func(v int64) []expr.Any { return nfthelper.MatchIP6FlowLabel(uint32(v)) }}
}
func NewMatchIP6LengthFunction() function.Function {
	return &numberArgFunc{name: "match_ip6_length", summary: "Match IPv6 payload length", paramName: "length", paramDesc: "Length value", fn: func(v int64) []expr.Any { return nfthelper.MatchIP6Length(uint16(v)) }}
}
func NewMatchIP6VersionFunction() function.Function {
	return &numberArgFunc{name: "match_ip6_version", summary: "Match IPv6 version field", paramName: "version", paramDesc: "Version (usually 6)", fn: func(v int64) []expr.Any { return nfthelper.MatchIP6Version(uint8(v)) }}
}
func NewMatchTCPSequenceFunction() function.Function {
	return &numberArgFunc{name: "match_tcp_sequence", summary: "Match TCP sequence number", paramName: "seq", paramDesc: "Sequence number", fn: func(v int64) []expr.Any { return nfthelper.MatchTCPSequence(uint32(v)) }}
}
func NewMatchTCPWindowFunction() function.Function {
	return &numberArgFunc{name: "match_tcp_window", summary: "Match TCP window size", paramName: "window", paramDesc: "Window value", fn: func(v int64) []expr.Any { return nfthelper.MatchTCPWindow(uint16(v)) }}
}
func NewMatchUDPLengthFunction() function.Function {
	return &numberArgFunc{name: "match_udp_length", summary: "Match UDP datagram length", paramName: "length", paramDesc: "Length value", fn: func(v int64) []expr.Any { return nfthelper.MatchUDPLength(uint16(v)) }}
}
func NewMatchEtherSaddrFunction() function.Function {
	return &stringArgFunc{name: "match_ether_saddr", summary: "Match Ethernet source MAC address", paramName: "mac", paramDesc: "MAC address (e.g. 00:11:22:33:44:55)", fn: nfthelper.MatchEtherSaddr}
}
func NewMatchEtherTypeFunction() function.Function {
	return &numberArgFunc{name: "match_ether_type", summary: "Match Ethernet type (EtherType value)", paramName: "ethertype", paramDesc: "EtherType (e.g. 0x0800 for IP, 0x86dd for IPv6, 0x0806 for ARP)", fn: func(v int64) []expr.Any { return nfthelper.MatchEtherType(uint16(v)) }}
}
func NewMatchVLANIdFunction() function.Function {
	return &numberArgFunc{name: "match_vlan_id", summary: "Match VLAN identifier (0-4094)", paramName: "id", paramDesc: "VLAN ID", fn: func(v int64) []expr.Any { return nfthelper.MatchVLANId(uint16(v)) }}
}
func NewMatchARPOperationFunction() function.Function {
	return &stringArgFunc{name: "match_arp_operation", summary: "Match ARP operation", paramName: "op", paramDesc: "Operation name: request, reply, rrequest, rreply, inrequest, inreply, nak", fn: nfthelper.MatchARPOperation}
}
func NewMatchARPHtypeFunction() function.Function {
	return &numberArgFunc{name: "match_arp_htype", summary: "Match ARP hardware type", paramName: "htype", paramDesc: "Hardware type value (1 for Ethernet)", fn: func(v int64) []expr.Any { return nfthelper.MatchARPHtype(uint16(v)) }}
}
func NewMatchMetaLengthFunction() function.Function {
	return &numberArgFunc{name: "match_meta_length", summary: "Match total packet length", paramName: "length", paramDesc: "Length in bytes", fn: func(v int64) []expr.Any { return nfthelper.MatchMetaLength(uint32(v)) }}
}
func NewMatchMetaProtocolFunction() function.Function {
	return &numberArgFunc{name: "match_meta_protocol", summary: "Match EtherType via meta protocol", paramName: "ethertype", paramDesc: "EtherType (e.g. 0x0800 for IPv4, 0x86dd for IPv6)", fn: func(v int64) []expr.Any { return nfthelper.MatchMetaProtocol(uint16(v)) }}
}

// Ensure all generic function types implement the interface
var (
	_ function.Function = (*noArgFunc)(nil)
	_ function.Function = (*stringArgFunc)(nil)
	_ function.Function = (*numberArgFunc)(nil)
	_ function.Function = (*CombineFunction)(nil)
	_ function.Function = (*LogFunction)(nil)
	_ function.Function = (*LimitFunction)(nil)
	_ function.Function = (*LimitBurstFunction)(nil)
	_ function.Function = (*LimitBytesFunction)(nil)
	_ function.Function = (*SNATPortFunction)(nil)
	_ function.Function = (*DNATPortFunction)(nil)
	_ function.Function = (*RedirectFunction)(nil)
	_ function.Function = (*QueueFunction)(nil)
	_ function.Function = (*MatchCTStateFunction)(nil)
	_ function.Function = (*MatchCTStatusFunction)(nil)
)

// Suppress unused import warnings
var _ = json.Marshal
