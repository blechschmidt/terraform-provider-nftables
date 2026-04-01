// Package nftexpr provides bidirectional conversion between JSON-encoded
// netlink VM expression lists and google/nftables expr.Any slices.
//
// The JSON format maps one-to-one with nftables netlink expressions.
// Each element is an object with a "type" field identifying the expression
// kind, plus type-specific data fields. Binary data (comparison values,
// IP addresses, masks) is base64-encoded.
//
// Example JSON:
//
//	[
//	  {"type": "meta", "key": "l4proto", "dreg": 1},
//	  {"type": "cmp", "op": "eq", "sreg": 1, "data": "Bg=="},
//	  {"type": "payload", "base": "transport", "offset": 2, "len": 2, "dreg": 1},
//	  {"type": "cmp", "op": "eq", "sreg": 1, "data": "AFY="},
//	  {"type": "verdict", "kind": "accept"}
//	]
package nftexpr

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// ExprJSON is the JSON representation of a single nftables expression.
type ExprJSON struct {
	Type string `json:"type"`

	// Payload fields
	Base   string `json:"base,omitempty"`   // "link", "network", "transport"
	Offset uint32 `json:"offset,omitempty"` // byte offset within header
	Len    uint32 `json:"len,omitempty"`    // bytes to load

	// Register fields (used by payload, cmp, meta, immediate, bitwise, etc.)
	DReg uint32 `json:"dreg,omitempty"` // destination register
	SReg uint32 `json:"sreg,omitempty"` // source register

	// Cmp / Range fields
	Op   string `json:"op,omitempty"`   // "eq", "neq", "lt", "lte", "gt", "gte"
	Data string `json:"data,omitempty"` // base64-encoded bytes

	// Range fields
	From string `json:"from,omitempty"` // base64-encoded
	To   string `json:"to,omitempty"`   // base64-encoded

	// Meta fields
	Key            string `json:"key,omitempty"` // meta key name
	SourceRegister *bool  `json:"source_register,omitempty"`

	// Bitwise fields
	Mask string `json:"mask,omitempty"` // base64-encoded
	Xor  string `json:"xor,omitempty"`  // base64-encoded

	// Verdict fields
	Kind  string `json:"kind,omitempty"`  // "accept", "drop", "return", "continue", "jump", "goto"
	Chain string `json:"chain,omitempty"` // for jump/goto

	// Counter fields (no additional fields needed)

	// Log fields
	Prefix     string `json:"prefix,omitempty"`
	Level      string `json:"level,omitempty"`
	Group      uint16 `json:"group,omitempty"`
	Snaplen    uint32 `json:"snaplen,omitempty"`
	QThreshold uint16 `json:"queue_threshold,omitempty"`

	// NAT fields
	NATType     string `json:"nat_type,omitempty"` // "snat", "dnat"
	Family      string `json:"family,omitempty"`   // "ip", "ip6"
	RegAddrMin  uint32 `json:"reg_addr_min,omitempty"`
	RegAddrMax  uint32 `json:"reg_addr_max,omitempty"`
	RegProtoMin uint32 `json:"reg_proto_min,omitempty"`
	RegProtoMax uint32 `json:"reg_proto_max,omitempty"`
	Random      bool   `json:"random,omitempty"`
	FullyRandom bool   `json:"fully_random,omitempty"`
	Persistent  bool   `json:"persistent,omitempty"`

	// Masquerade fields (uses Random, FullyRandom, Persistent, RegProtoMin, RegProtoMax)
	ToPorts bool `json:"to_ports,omitempty"`

	// Reject fields
	RejectType uint32 `json:"reject_type,omitempty"`
	Code       uint8  `json:"code,omitempty"`

	// Limit fields
	Rate      uint64 `json:"rate,omitempty"`
	Unit      string `json:"unit,omitempty"` // "second", "minute", "hour", "day", "week"
	Burst     uint32 `json:"burst,omitempty"`
	LimitType string `json:"limit_type,omitempty"` // "pkts", "bytes"
	Over      bool   `json:"over,omitempty"`

	// Lookup fields
	SetName string `json:"set_name,omitempty"`
	SetID   uint32 `json:"set_id,omitempty"`
	Invert  bool   `json:"invert,omitempty"`

	// CT fields
	Direction uint32 `json:"direction,omitempty"`

	// Queue fields
	Num  uint16 `json:"num,omitempty"`
	Flag uint16 `json:"flag,omitempty"`

	// Fib fields
	FlagSADDR      bool   `json:"flag_saddr,omitempty"`
	FlagDADDR      bool   `json:"flag_daddr,omitempty"`
	FlagMARK       bool   `json:"flag_mark,omitempty"`
	FlagIIF        bool   `json:"flag_iif,omitempty"`
	FlagOIF        bool   `json:"flag_oif,omitempty"`
	ResultOIF      bool   `json:"result_oif,omitempty"`
	ResultOIFNAME  bool   `json:"result_oifname,omitempty"`
	ResultADDRTYPE bool   `json:"result_addrtype,omitempty"`

	// Redir fields (uses RegProtoMin, RegProtoMax)

	// FlowOffload fields
	Name string `json:"name,omitempty"`

	// Quota fields
	Bytes    uint64 `json:"bytes,omitempty"`
	Consumed uint64 `json:"consumed,omitempty"`

	// Connlimit fields
	Count    uint32 `json:"count,omitempty"`
	ConnFlag uint32 `json:"conn_flag,omitempty"`
}

// FromJSON deserializes a JSON array of expression objects into a slice
// of google/nftables expr.Any values.
func FromJSON(jsonData string) ([]expr.Any, error) {
	var items []ExprJSON
	if err := json.Unmarshal([]byte(jsonData), &items); err != nil {
		return nil, fmt.Errorf("invalid expression JSON: %w", err)
	}

	var result []expr.Any
	for i, item := range items {
		e, err := convertExpr(item)
		if err != nil {
			return nil, fmt.Errorf("expression[%d] (type=%q): %w", i, item.Type, err)
		}
		result = append(result, e)
	}
	return result, nil
}

// ToJSON serializes a slice of expr.Any values back to JSON.
func ToJSON(exprs []expr.Any) (string, error) {
	var items []ExprJSON
	for _, e := range exprs {
		item, err := serializeExpr(e)
		if err != nil {
			return "", err
		}
		items = append(items, item)
	}
	data, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodeBase64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func encodeBase64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func convertExpr(j ExprJSON) (expr.Any, error) {
	switch j.Type {
	case "payload":
		return convertPayload(j)
	case "cmp":
		return convertCmp(j)
	case "meta":
		return convertMeta(j)
	case "immediate":
		return convertImmediate(j)
	case "bitwise":
		return convertBitwise(j)
	case "verdict":
		return convertVerdict(j)
	case "counter":
		return &expr.Counter{}, nil
	case "log":
		return convertLog(j)
	case "nat":
		return convertNAT(j)
	case "masq", "masquerade":
		return convertMasq(j)
	case "reject":
		return &expr.Reject{Type: j.RejectType, Code: j.Code}, nil
	case "limit":
		return convertLimit(j)
	case "ct":
		return convertCT(j)
	case "lookup":
		return convertLookup(j)
	case "range":
		return convertRange(j)
	case "redir", "redirect":
		return &expr.Redir{
			RegisterProtoMin: j.RegProtoMin,
			RegisterProtoMax: j.RegProtoMax,
		}, nil
	case "queue":
		return &expr.Queue{Num: j.Num, Flag: expr.QueueFlag(j.Flag)}, nil
	case "notrack":
		return &expr.Notrack{}, nil
	case "flow_offload":
		return &expr.FlowOffload{Name: j.Name}, nil
	case "fib":
		return convertFib(j)
	case "quota":
		return &expr.Quota{Bytes: j.Bytes, Consumed: j.Consumed, Over: j.Over}, nil
	case "connlimit":
		return &expr.Connlimit{Count: j.Count, Flags: j.ConnFlag}, nil
	default:
		return nil, fmt.Errorf("unknown expression type: %q", j.Type)
	}
}

func convertPayload(j ExprJSON) (*expr.Payload, error) {
	base, err := parsePayloadBase(j.Base)
	if err != nil {
		return nil, err
	}
	return &expr.Payload{
		Base:         base,
		Offset:       j.Offset,
		Len:          j.Len,
		DestRegister: j.DReg,
	}, nil
}

func convertCmp(j ExprJSON) (*expr.Cmp, error) {
	op, err := parseCmpOp(j.Op)
	if err != nil {
		return nil, err
	}
	data, err := decodeBase64(j.Data)
	if err != nil {
		return nil, fmt.Errorf("invalid cmp data: %w", err)
	}
	return &expr.Cmp{
		Op:       op,
		Register: j.SReg,
		Data:     data,
	}, nil
}

func convertMeta(j ExprJSON) (*expr.Meta, error) {
	key, err := parseMetaKey(j.Key)
	if err != nil {
		return nil, err
	}
	m := &expr.Meta{Key: key}
	if j.SourceRegister != nil && *j.SourceRegister {
		m.SourceRegister = true
		m.Register = j.SReg
	} else {
		m.Register = j.DReg
	}
	return m, nil
}

func convertImmediate(j ExprJSON) (*expr.Immediate, error) {
	data, err := decodeBase64(j.Data)
	if err != nil {
		return nil, fmt.Errorf("invalid immediate data: %w", err)
	}
	return &expr.Immediate{
		Register: j.DReg,
		Data:     data,
	}, nil
}

func convertBitwise(j ExprJSON) (*expr.Bitwise, error) {
	mask, err := decodeBase64(j.Mask)
	if err != nil {
		return nil, fmt.Errorf("invalid bitwise mask: %w", err)
	}
	xor, err := decodeBase64(j.Xor)
	if err != nil {
		return nil, fmt.Errorf("invalid bitwise xor: %w", err)
	}
	return &expr.Bitwise{
		SourceRegister: j.SReg,
		DestRegister:   j.DReg,
		Len:            j.Len,
		Mask:           mask,
		Xor:            xor,
	}, nil
}

func convertVerdict(j ExprJSON) (*expr.Verdict, error) {
	kind, err := parseVerdictKind(j.Kind)
	if err != nil {
		return nil, err
	}
	return &expr.Verdict{Kind: kind, Chain: j.Chain}, nil
}

func convertLog(j ExprJSON) (*expr.Log, error) {
	l := &expr.Log{}
	if j.Prefix != "" {
		l.Data = []byte(j.Prefix)
		l.Key |= unix.NFTA_LOG_PREFIX
	}
	if j.Level != "" {
		level, err := parseLogLevel(j.Level)
		if err != nil {
			return nil, err
		}
		l.Level = level
		l.Key |= unix.NFTA_LOG_LEVEL
	}
	if j.Group > 0 {
		l.Group = j.Group
		l.Key |= unix.NFTA_LOG_GROUP
	}
	l.Snaplen = j.Snaplen
	l.QThreshold = j.QThreshold
	return l, nil
}

func convertNAT(j ExprJSON) (*expr.NAT, error) {
	natType, err := parseNATType(j.NATType)
	if err != nil {
		return nil, err
	}
	family := uint32(unix.NFPROTO_IPV4)
	if j.Family == "ip6" || j.Family == "ipv6" {
		family = uint32(unix.NFPROTO_IPV6)
	}
	return &expr.NAT{
		Type:        natType,
		Family:      family,
		RegAddrMin:  j.RegAddrMin,
		RegAddrMax:  j.RegAddrMax,
		RegProtoMin: j.RegProtoMin,
		RegProtoMax: j.RegProtoMax,
		Random:      j.Random,
		FullyRandom: j.FullyRandom,
		Persistent:  j.Persistent,
	}, nil
}

func convertMasq(j ExprJSON) (*expr.Masq, error) {
	return &expr.Masq{
		Random:      j.Random,
		FullyRandom: j.FullyRandom,
		Persistent:  j.Persistent,
		ToPorts:     j.ToPorts,
		RegProtoMin: j.RegProtoMin,
		RegProtoMax: j.RegProtoMax,
	}, nil
}

func convertLimit(j ExprJSON) (*expr.Limit, error) {
	unit, err := parseLimitUnit(j.Unit)
	if err != nil {
		return nil, err
	}
	limitType := expr.LimitTypePkts
	if j.LimitType == "bytes" {
		limitType = expr.LimitTypePktBytes
	}
	return &expr.Limit{
		Type:  limitType,
		Rate:  j.Rate,
		Unit:  unit,
		Burst: j.Burst,
		Over:  j.Over,
	}, nil
}

func convertCT(j ExprJSON) (*expr.Ct, error) {
	key, err := parseCTKey(j.Key)
	if err != nil {
		return nil, err
	}
	ct := &expr.Ct{Key: key, Direction: j.Direction}
	if j.SourceRegister != nil && *j.SourceRegister {
		ct.SourceRegister = true
		ct.Register = j.SReg
	} else {
		ct.Register = j.DReg
	}
	return ct, nil
}

func convertLookup(j ExprJSON) (*expr.Lookup, error) {
	return &expr.Lookup{
		SourceRegister: j.SReg,
		SetName:        j.SetName,
		SetID:          j.SetID,
		Invert:         j.Invert,
	}, nil
}

func convertRange(j ExprJSON) (*expr.Range, error) {
	op, err := parseCmpOp(j.Op)
	if err != nil {
		return nil, err
	}
	from, err := decodeBase64(j.From)
	if err != nil {
		return nil, fmt.Errorf("invalid range from: %w", err)
	}
	to, err := decodeBase64(j.To)
	if err != nil {
		return nil, fmt.Errorf("invalid range to: %w", err)
	}
	return &expr.Range{
		Op:       op,
		Register: j.SReg,
		FromData: from,
		ToData:   to,
	}, nil
}

func convertFib(j ExprJSON) (*expr.Fib, error) {
	return &expr.Fib{
		Register:       j.DReg,
		FlagSADDR:      j.FlagSADDR,
		FlagDADDR:      j.FlagDADDR,
		FlagMARK:       j.FlagMARK,
		FlagIIF:        j.FlagIIF,
		FlagOIF:        j.FlagOIF,
		ResultOIF:      j.ResultOIF,
		ResultOIFNAME:  j.ResultOIFNAME,
		ResultADDRTYPE: j.ResultADDRTYPE,
	}, nil
}

// --- Enum parsers ---

func parsePayloadBase(s string) (expr.PayloadBase, error) {
	switch s {
	case "link", "ll":
		return expr.PayloadBaseLLHeader, nil
	case "network", "net":
		return expr.PayloadBaseNetworkHeader, nil
	case "transport", "th":
		return expr.PayloadBaseTransportHeader, nil
	default:
		return 0, fmt.Errorf("unknown payload base: %q (valid: link, network, transport)", s)
	}
}

func parseCmpOp(s string) (expr.CmpOp, error) {
	switch s {
	case "eq", "==":
		return expr.CmpOpEq, nil
	case "neq", "!=":
		return expr.CmpOpNeq, nil
	case "lt", "<":
		return expr.CmpOpLt, nil
	case "lte", "<=":
		return expr.CmpOpLte, nil
	case "gt", ">":
		return expr.CmpOpGt, nil
	case "gte", ">=":
		return expr.CmpOpGte, nil
	default:
		return 0, fmt.Errorf("unknown cmp op: %q (valid: eq, neq, lt, lte, gt, gte)", s)
	}
}

func parseMetaKey(s string) (expr.MetaKey, error) {
	keys := map[string]expr.MetaKey{
		"len": expr.MetaKeyLEN, "length": expr.MetaKeyLEN,
		"protocol": expr.MetaKeyPROTOCOL,
		"priority": expr.MetaKeyPRIORITY,
		"mark": expr.MetaKeyMARK,
		"iif": expr.MetaKeyIIF, "oif": expr.MetaKeyOIF,
		"iifname": expr.MetaKeyIIFNAME, "oifname": expr.MetaKeyOIFNAME,
		"iiftype": expr.MetaKeyIIFTYPE, "oiftype": expr.MetaKeyOIFTYPE,
		"skuid": expr.MetaKeySKUID, "skgid": expr.MetaKeySKGID,
		"nftrace": expr.MetaKeyNFTRACE,
		"rtclassid": expr.MetaKeyRTCLASSID,
		"secmark": expr.MetaKeySECMARK,
		"nfproto": expr.MetaKeyNFPROTO,
		"l4proto": expr.MetaKeyL4PROTO,
		"bri_iifname": expr.MetaKeyBRIIIFNAME, "bri_oifname": expr.MetaKeyBRIOIFNAME,
		"pkttype": expr.MetaKeyPKTTYPE,
		"cpu": expr.MetaKeyCPU,
		"iifgroup": expr.MetaKeyIIFGROUP, "oifgroup": expr.MetaKeyOIFGROUP,
		"cgroup": expr.MetaKeyCGROUP,
		"prandom": expr.MetaKeyPRANDOM,
	}
	if k, ok := keys[s]; ok {
		return k, nil
	}
	return 0, fmt.Errorf("unknown meta key: %q", s)
}

func parseVerdictKind(s string) (expr.VerdictKind, error) {
	switch s {
	case "accept":
		return expr.VerdictAccept, nil
	case "drop":
		return expr.VerdictDrop, nil
	case "return":
		return expr.VerdictReturn, nil
	case "continue":
		return expr.VerdictContinue, nil
	case "jump":
		return expr.VerdictJump, nil
	case "goto":
		return expr.VerdictGoto, nil
	default:
		return 0, fmt.Errorf("unknown verdict kind: %q", s)
	}
}

func parseLogLevel(s string) (expr.LogLevel, error) {
	levels := map[string]expr.LogLevel{
		"emerg": expr.LogLevelEmerg, "alert": expr.LogLevelAlert,
		"crit": expr.LogLevelCrit, "err": expr.LogLevelErr,
		"warn": expr.LogLevelWarning, "warning": expr.LogLevelWarning,
		"notice": expr.LogLevelNotice, "info": expr.LogLevelInfo,
		"debug": expr.LogLevelDebug,
	}
	if l, ok := levels[s]; ok {
		return l, nil
	}
	return 0, fmt.Errorf("unknown log level: %q", s)
}

func parseNATType(s string) (expr.NATType, error) {
	switch s {
	case "snat":
		return expr.NATTypeSourceNAT, nil
	case "dnat":
		return expr.NATTypeDestNAT, nil
	default:
		return 0, fmt.Errorf("unknown NAT type: %q (valid: snat, dnat)", s)
	}
}

func parseLimitUnit(s string) (expr.LimitTime, error) {
	switch s {
	case "second", "sec", "s":
		return expr.LimitTimeSecond, nil
	case "minute", "min", "m":
		return expr.LimitTimeMinute, nil
	case "hour", "h":
		return expr.LimitTimeHour, nil
	case "day", "d":
		return expr.LimitTimeDay, nil
	case "week", "w":
		return expr.LimitTimeWeek, nil
	default:
		return 0, fmt.Errorf("unknown limit unit: %q", s)
	}
}

func parseCTKey(s string) (expr.CtKey, error) {
	keys := map[string]expr.CtKey{
		"state": expr.CtKeySTATE, "direction": expr.CtKeyDIRECTION,
		"status": expr.CtKeySTATUS, "mark": expr.CtKeyMARK,
		"expiration": expr.CtKeyEXPIRATION, "helper": expr.CtKeyHELPER,
		"l3protocol": expr.CtKeyL3PROTOCOL, "l3proto": expr.CtKeyL3PROTOCOL,
		"src": expr.CtKeySRC, "dst": expr.CtKeyDST,
		"protocol": expr.CtKeyPROTOCOL,
		"proto-src": expr.CtKeyPROTOSRC, "proto-dst": expr.CtKeyPROTODST,
		"zone": expr.CtKeyZONE,
	}
	if k, ok := keys[s]; ok {
		return k, nil
	}
	return 0, fmt.Errorf("unknown ct key: %q", s)
}

// --- Serialization (expr.Any → ExprJSON) ---

func serializeExpr(e expr.Any) (ExprJSON, error) {
	switch v := e.(type) {
	case *expr.Payload:
		return ExprJSON{
			Type:   "payload",
			Base:   payloadBaseString(v.Base),
			Offset: v.Offset,
			Len:    v.Len,
			DReg:   v.DestRegister,
		}, nil
	case *expr.Cmp:
		return ExprJSON{
			Type: "cmp",
			Op:   cmpOpString(v.Op),
			SReg: v.Register,
			Data: encodeBase64(v.Data),
		}, nil
	case *expr.Meta:
		j := ExprJSON{Type: "meta", Key: metaKeyString(v.Key)}
		if v.SourceRegister {
			sr := true
			j.SourceRegister = &sr
			j.SReg = v.Register
		} else {
			j.DReg = v.Register
		}
		return j, nil
	case *expr.Immediate:
		return ExprJSON{
			Type: "immediate",
			DReg: v.Register,
			Data: encodeBase64(v.Data),
		}, nil
	case *expr.Bitwise:
		return ExprJSON{
			Type: "bitwise",
			SReg: v.SourceRegister,
			DReg: v.DestRegister,
			Len:  v.Len,
			Mask: encodeBase64(v.Mask),
			Xor:  encodeBase64(v.Xor),
		}, nil
	case *expr.Verdict:
		return ExprJSON{
			Type:  "verdict",
			Kind:  verdictKindString(v.Kind),
			Chain: v.Chain,
		}, nil
	case *expr.Counter:
		return ExprJSON{Type: "counter"}, nil
	case *expr.Log:
		j := ExprJSON{Type: "log"}
		if len(v.Data) > 0 {
			j.Prefix = string(v.Data)
		}
		j.Level = logLevelString(v.Level)
		j.Group = v.Group
		j.Snaplen = v.Snaplen
		j.QThreshold = v.QThreshold
		return j, nil
	case *expr.NAT:
		return ExprJSON{
			Type:        "nat",
			NATType:     natTypeString(v.Type),
			Family:      natFamilyString(v.Family),
			RegAddrMin:  v.RegAddrMin,
			RegAddrMax:  v.RegAddrMax,
			RegProtoMin: v.RegProtoMin,
			RegProtoMax: v.RegProtoMax,
			Random:      v.Random,
			FullyRandom: v.FullyRandom,
			Persistent:  v.Persistent,
		}, nil
	case *expr.Masq:
		return ExprJSON{
			Type:        "masq",
			Random:      v.Random,
			FullyRandom: v.FullyRandom,
			Persistent:  v.Persistent,
			ToPorts:     v.ToPorts,
			RegProtoMin: v.RegProtoMin,
			RegProtoMax: v.RegProtoMax,
		}, nil
	case *expr.Reject:
		return ExprJSON{Type: "reject", RejectType: v.Type, Code: v.Code}, nil
	case *expr.Limit:
		return ExprJSON{
			Type:      "limit",
			Rate:      v.Rate,
			Unit:      limitUnitString(v.Unit),
			Burst:     v.Burst,
			LimitType: limitTypeString(v.Type),
			Over:      v.Over,
		}, nil
	case *expr.Ct:
		j := ExprJSON{Type: "ct", Key: ctKeyString(v.Key), Direction: v.Direction}
		if v.SourceRegister {
			sr := true
			j.SourceRegister = &sr
			j.SReg = v.Register
		} else {
			j.DReg = v.Register
		}
		return j, nil
	case *expr.Lookup:
		return ExprJSON{
			Type:    "lookup",
			SReg:    v.SourceRegister,
			SetName: v.SetName,
			SetID:   v.SetID,
			Invert:  v.Invert,
		}, nil
	case *expr.Range:
		return ExprJSON{
			Type: "range",
			Op:   cmpOpString(v.Op),
			SReg: v.Register,
			From: encodeBase64(v.FromData),
			To:   encodeBase64(v.ToData),
		}, nil
	case *expr.Redir:
		return ExprJSON{
			Type:        "redir",
			RegProtoMin: v.RegisterProtoMin,
			RegProtoMax: v.RegisterProtoMax,
		}, nil
	case *expr.Queue:
		return ExprJSON{Type: "queue", Num: v.Num, Flag: uint16(v.Flag)}, nil
	case *expr.Notrack:
		return ExprJSON{Type: "notrack"}, nil
	case *expr.FlowOffload:
		return ExprJSON{Type: "flow_offload", Name: v.Name}, nil
	case *expr.Fib:
		return ExprJSON{
			Type:           "fib",
			DReg:           v.Register,
			FlagSADDR:      v.FlagSADDR,
			FlagDADDR:      v.FlagDADDR,
			FlagMARK:       v.FlagMARK,
			FlagIIF:        v.FlagIIF,
			FlagOIF:        v.FlagOIF,
			ResultOIF:      v.ResultOIF,
			ResultOIFNAME:  v.ResultOIFNAME,
			ResultADDRTYPE: v.ResultADDRTYPE,
		}, nil
	case *expr.Quota:
		return ExprJSON{Type: "quota", Bytes: v.Bytes, Consumed: v.Consumed, Over: v.Over}, nil
	case *expr.Connlimit:
		return ExprJSON{Type: "connlimit", Count: v.Count, ConnFlag: v.Flags}, nil
	default:
		return ExprJSON{}, fmt.Errorf("unsupported expression type for serialization: %T", e)
	}
}

// --- String converters for serialization ---

func payloadBaseString(b expr.PayloadBase) string {
	switch b {
	case expr.PayloadBaseLLHeader:
		return "link"
	case expr.PayloadBaseNetworkHeader:
		return "network"
	case expr.PayloadBaseTransportHeader:
		return "transport"
	default:
		return "unknown"
	}
}

func cmpOpString(op expr.CmpOp) string {
	switch op {
	case expr.CmpOpEq:
		return "eq"
	case expr.CmpOpNeq:
		return "neq"
	case expr.CmpOpLt:
		return "lt"
	case expr.CmpOpLte:
		return "lte"
	case expr.CmpOpGt:
		return "gt"
	case expr.CmpOpGte:
		return "gte"
	default:
		return "eq"
	}
}

func metaKeyString(k expr.MetaKey) string {
	keys := map[expr.MetaKey]string{
		expr.MetaKeyLEN: "len", expr.MetaKeyPROTOCOL: "protocol",
		expr.MetaKeyPRIORITY: "priority", expr.MetaKeyMARK: "mark",
		expr.MetaKeyIIF: "iif", expr.MetaKeyOIF: "oif",
		expr.MetaKeyIIFNAME: "iifname", expr.MetaKeyOIFNAME: "oifname",
		expr.MetaKeyIIFTYPE: "iiftype", expr.MetaKeyOIFTYPE: "oiftype",
		expr.MetaKeySKUID: "skuid", expr.MetaKeySKGID: "skgid",
		expr.MetaKeyNFTRACE: "nftrace", expr.MetaKeyRTCLASSID: "rtclassid",
		expr.MetaKeySECMARK: "secmark", expr.MetaKeyNFPROTO: "nfproto",
		expr.MetaKeyL4PROTO: "l4proto",
		expr.MetaKeyBRIIIFNAME: "bri_iifname", expr.MetaKeyBRIOIFNAME: "bri_oifname",
		expr.MetaKeyPKTTYPE: "pkttype", expr.MetaKeyCPU: "cpu",
		expr.MetaKeyIIFGROUP: "iifgroup", expr.MetaKeyOIFGROUP: "oifgroup",
		expr.MetaKeyCGROUP: "cgroup", expr.MetaKeyPRANDOM: "prandom",
	}
	if s, ok := keys[k]; ok {
		return s
	}
	return "unknown"
}

func verdictKindString(k expr.VerdictKind) string {
	switch k {
	case expr.VerdictAccept:
		return "accept"
	case expr.VerdictDrop:
		return "drop"
	case expr.VerdictReturn:
		return "return"
	case expr.VerdictContinue:
		return "continue"
	case expr.VerdictJump:
		return "jump"
	case expr.VerdictGoto:
		return "goto"
	default:
		return "accept"
	}
}

func logLevelString(l expr.LogLevel) string {
	levels := map[expr.LogLevel]string{
		expr.LogLevelEmerg: "emerg", expr.LogLevelAlert: "alert",
		expr.LogLevelCrit: "crit", expr.LogLevelErr: "err",
		expr.LogLevelWarning: "warn", expr.LogLevelNotice: "notice",
		expr.LogLevelInfo: "info", expr.LogLevelDebug: "debug",
	}
	if s, ok := levels[l]; ok {
		return s
	}
	return "info"
}

func natTypeString(t expr.NATType) string {
	switch t {
	case expr.NATTypeSourceNAT:
		return "snat"
	case expr.NATTypeDestNAT:
		return "dnat"
	default:
		return "snat"
	}
}

func natFamilyString(f uint32) string {
	if f == uint32(unix.NFPROTO_IPV6) {
		return "ip6"
	}
	return "ip"
}

func limitUnitString(u expr.LimitTime) string {
	switch u {
	case expr.LimitTimeSecond:
		return "second"
	case expr.LimitTimeMinute:
		return "minute"
	case expr.LimitTimeHour:
		return "hour"
	case expr.LimitTimeDay:
		return "day"
	case expr.LimitTimeWeek:
		return "week"
	default:
		return "second"
	}
}

func limitTypeString(t expr.LimitType) string {
	if t == expr.LimitTypePktBytes {
		return "bytes"
	}
	return "pkts"
}

func ctKeyString(k expr.CtKey) string {
	keys := map[expr.CtKey]string{
		expr.CtKeySTATE: "state", expr.CtKeyDIRECTION: "direction",
		expr.CtKeySTATUS: "status", expr.CtKeyMARK: "mark",
		expr.CtKeyEXPIRATION: "expiration", expr.CtKeyHELPER: "helper",
		expr.CtKeyL3PROTOCOL: "l3proto",
		expr.CtKeySRC: "src", expr.CtKeyDST: "dst",
		expr.CtKeyPROTOCOL: "protocol",
		expr.CtKeyPROTOSRC: "proto-src", expr.CtKeyPROTODST: "proto-dst",
		expr.CtKeyZONE: "zone",
	}
	if s, ok := keys[k]; ok {
		return s
	}
	return "state"
}
