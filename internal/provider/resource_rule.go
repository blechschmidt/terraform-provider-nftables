package provider

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/sys/unix"
)

var (
	_ resource.Resource                = &RuleResource{}
	_ resource.ResourceWithImportState = &RuleResource{}
)

type RuleResource struct {
	data *NftablesProviderData
}

type RuleModel struct {
	Family     types.String `tfsdk:"family"`
	Table      types.String `tfsdk:"table"`
	Chain      types.String `tfsdk:"chain"`
	Handle     types.Int64  `tfsdk:"handle"`
	Position   types.Int64  `tfsdk:"position"`
	Expression types.String `tfsdk:"expression"`
}

func NewRuleResource() resource.Resource {
	return &RuleResource{}
}

func (r *RuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_rule"
}

func (r *RuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an nftables rule. The expression attribute uses nft rule syntax.",
		Attributes: map[string]schema.Attribute{
			"family": schema.StringAttribute{
				Required:    true,
				Description: "Address family.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"table": schema.StringAttribute{
				Required:    true,
				Description: "Table name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"chain": schema.StringAttribute{
				Required:    true,
				Description: "Chain name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"handle": schema.Int64Attribute{
				Computed:    true,
				Description: "Rule handle assigned by the kernel.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"position": schema.Int64Attribute{
				Optional:    true,
				Description: "Position (handle of the rule before which to insert).",
			},
			"expression": schema.StringAttribute{
				Required:    true,
				Description: "Rule expression in nft syntax, e.g. 'tcp dport 22 accept', 'ip saddr 10.0.0.0/8 drop'.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *RuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	data, ok := req.ProviderData.(*NftablesProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type", "")
		return
	}
	r.data = data
}

func (r *RuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan RuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, err := parseFamily(plan.Family.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid family", err.Error())
		return
	}

	table := &nftables.Table{Family: family, Name: plan.Table.ValueString()}
	chain := &nftables.Chain{Name: plan.Chain.ValueString(), Table: table}

	exprs, err := parseRuleExpression(plan.Expression.ValueString(), family)
	if err != nil {
		resp.Diagnostics.AddError("Failed to parse expression", err.Error())
		return
	}

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: exprs,
	}

	if !plan.Position.IsNull() && !plan.Position.IsUnknown() {
		rule.Position = uint64(plan.Position.ValueInt64())
	}

	rule = r.data.Conn.AddRule(rule)

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to create rule", err.Error())
		return
	}

	// Re-read to get the handle
	rules, err := r.data.Conn.GetRules(table, chain)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read rules", err.Error())
		return
	}

	// Find our rule - it should be the last one added (or at position)
	if len(rules) > 0 {
		// Get the last rule's handle as our best match
		found := rules[len(rules)-1]
		plan.Handle = types.Int64Value(int64(found.Handle))
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state RuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, err := parseFamily(state.Family.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid family", err.Error())
		return
	}

	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}
	chain := &nftables.Chain{Name: state.Chain.ValueString(), Table: table}

	rules, err := r.data.Conn.GetRules(table, chain)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	handle := uint64(state.Handle.ValueInt64())
	found := false
	for _, rule := range rules {
		if rule.Handle == handle {
			found = true
			break
		}
	}

	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *RuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Rules are replaced via RequiresReplace on expression, so updates only happen
	// for non-expression fields like position. In practice, expression changes
	// trigger a replace (delete + create).
	var plan RuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state RuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, err := parseFamily(state.Family.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid family", err.Error())
		return
	}

	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}
	chain := &nftables.Chain{Name: state.Chain.ValueString(), Table: table}

	err = r.data.Conn.DelRule(&nftables.Rule{
		Table:  table,
		Chain:  chain,
		Handle: uint64(state.Handle.ValueInt64()),
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to delete rule", err.Error())
		return
	}

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to flush delete", err.Error())
		return
	}
}

func (r *RuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Format: family|table|chain|handle
	parts := strings.SplitN(req.ID, "|", 4)
	if len(parts) != 4 {
		resp.Diagnostics.AddError("Invalid import ID", "Expected format: family|table|chain|handle")
		return
	}
	handle, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid handle", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("family"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("table"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("chain"), parts[2])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("handle"), handle)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("expression"), "imported")...)
}

// parseRuleExpression parses a simplified nft rule expression string into
// a slice of nftables expressions. This supports a practical subset of nft syntax.
func parseRuleExpression(expression string, family nftables.TableFamily) ([]expr.Any, error) {
	tokens := tokenize(expression)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty expression")
	}

	var exprs []expr.Any
	i := 0

	for i < len(tokens) {
		remaining := tokens[i:]
		parsed, consumed, err := parseExprTokens(remaining, family)
		if err != nil {
			return nil, fmt.Errorf("at token %q (position %d): %w", tokens[i], i, err)
		}
		exprs = append(exprs, parsed...)
		i += consumed
	}

	return exprs, nil
}

func tokenize(s string) []string {
	var tokens []string
	var current strings.Builder
	inBraces := 0

	for _, ch := range s {
		switch {
		case ch == '{':
			inBraces++
			current.WriteRune(ch)
		case ch == '}':
			inBraces--
			current.WriteRune(ch)
		case ch == ' ' || ch == '\t':
			if inBraces > 0 {
				current.WriteRune(ch)
			} else if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(ch)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

func parseExprTokens(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	if len(tokens) == 0 {
		return nil, 0, fmt.Errorf("unexpected end of expression")
	}

	switch tokens[0] {
	// Verdicts
	case "accept":
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}, 1, nil
	case "drop":
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}, 1, nil
	case "return":
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictReturn}}, 1, nil
	case "continue":
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictContinue}}, 1, nil
	case "jump":
		if len(tokens) < 2 {
			return nil, 0, fmt.Errorf("jump requires chain name")
		}
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: tokens[1]}}, 2, nil
	case "goto":
		if len(tokens) < 2 {
			return nil, 0, fmt.Errorf("goto requires chain name")
		}
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictGoto, Chain: tokens[1]}}, 2, nil

	// Counter
	case "counter":
		return []expr.Any{&expr.Counter{}}, 1, nil

	// Log
	case "log":
		return parseLog(tokens)

	// Reject
	case "reject":
		return parseReject(tokens, family)

	// Notrack
	case "notrack":
		return []expr.Any{&expr.Notrack{}}, 1, nil

	// Masquerade
	case "masquerade":
		return parseMasquerade(tokens)

	// Redirect
	case "redirect":
		return parseRedirect(tokens)

	// Limit
	case "limit":
		return parseLimit(tokens)

	// Queue
	case "queue":
		return parseQueue(tokens)

	// Protocol matches
	case "ip":
		return parseIPMatch(tokens, family)
	case "ip6":
		return parseIP6Match(tokens, family)
	case "tcp":
		return parseTCPMatch(tokens, family)
	case "udp":
		return parseUDPMatch(tokens, family)
	case "icmp":
		return parseICMPMatch(tokens, family)
	case "icmpv6":
		return parseICMPv6Match(tokens, family)
	case "ether":
		return parseEtherMatch(tokens)
	case "arp":
		return parseARPMatch(tokens)
	case "sctp":
		return parseSCTPMatch(tokens, family)
	case "dccp":
		return parseDCCPMatch(tokens, family)
	case "esp":
		return parseESPMatch(tokens, family)
	case "ah":
		return parseAHMatch(tokens, family)
	case "comp":
		return parseCompMatch(tokens, family)
	case "udplite":
		return parseUDPLiteMatch(tokens, family)
	case "vlan":
		return parseVLANMatch(tokens)

	// Meta
	case "meta":
		return parseMetaMatch(tokens)
	case "iif", "iifname", "oif", "oifname", "iiftype", "oiftype":
		return parseMetaShorthand(tokens)

	// Connection tracking
	case "ct":
		return parseCTMatch(tokens)

	// NAT
	case "snat":
		return parseSNAT(tokens, family)
	case "dnat":
		return parseDNAT(tokens, family)

	// Mark mangling
	case "mark":
		return parseMarkSet(tokens)

	// Flow offload
	case "flow":
		return parseFlowOffload(tokens)

	// Fib
	case "fib":
		return parseFib(tokens)

	// Dup
	case "dup":
		return parseDup(tokens, family)

	default:
		return nil, 0, fmt.Errorf("unknown expression: %q", tokens[0])
	}
}

// --- Verdict/Statement parsers ---

func parseLog(tokens []string) ([]expr.Any, int, error) {
	l := &expr.Log{}
	i := 1
	for i < len(tokens) {
		switch tokens[i] {
		case "prefix":
			if i+1 >= len(tokens) {
				return nil, 0, fmt.Errorf("log prefix requires value")
			}
			i++
			l.Key |= unix.NFTA_LOG_PREFIX
			prefix := strings.Trim(tokens[i], "\"")
			l.Data = []byte(prefix)
			i++
		case "level":
			if i+1 >= len(tokens) {
				return nil, 0, fmt.Errorf("log level requires value")
			}
			i++
			level, err := parseLogLevel(tokens[i])
			if err != nil {
				return nil, 0, err
			}
			l.Level = level
			l.Key |= unix.NFTA_LOG_LEVEL
			i++
		case "group":
			if i+1 >= len(tokens) {
				return nil, 0, fmt.Errorf("log group requires value")
			}
			i++
			g, err := strconv.ParseUint(tokens[i], 10, 16)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid log group: %s", tokens[i])
			}
			l.Group = uint16(g)
			l.Key |= unix.NFTA_LOG_GROUP
			i++
		case "snaplen":
			if i+1 >= len(tokens) {
				return nil, 0, fmt.Errorf("log snaplen requires value")
			}
			i++
			s, err := strconv.ParseUint(tokens[i], 10, 32)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid log snaplen: %s", tokens[i])
			}
			l.Snaplen = uint32(s)
			l.Key |= unix.NFTA_LOG_FLAGS
			i++
		case "queue-threshold":
			if i+1 >= len(tokens) {
				return nil, 0, fmt.Errorf("log queue-threshold requires value")
			}
			i++
			q, err := strconv.ParseUint(tokens[i], 10, 16)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid log queue-threshold: %s", tokens[i])
			}
			l.QThreshold = uint16(q)
			l.Key |= unix.NFTA_LOG_FLAGS
			i++
		default:
			return []expr.Any{l}, i, nil
		}
	}
	return []expr.Any{l}, i, nil
}

func parseLogLevel(s string) (expr.LogLevel, error) {
	switch strings.ToLower(s) {
	case "emerg":
		return expr.LogLevelEmerg, nil
	case "alert":
		return expr.LogLevelAlert, nil
	case "crit":
		return expr.LogLevelCrit, nil
	case "err":
		return expr.LogLevelErr, nil
	case "warn", "warning":
		return expr.LogLevelWarning, nil
	case "notice":
		return expr.LogLevelNotice, nil
	case "info":
		return expr.LogLevelInfo, nil
	case "debug":
		return expr.LogLevelDebug, nil
	default:
		return 0, fmt.Errorf("unknown log level: %q", s)
	}
}

func parseReject(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	r := &expr.Reject{}
	i := 1

	if i < len(tokens) && tokens[i] == "with" {
		i++
		if i >= len(tokens) {
			return nil, 0, fmt.Errorf("reject with requires type")
		}

		switch tokens[i] {
		case "tcp":
			i++
			if i < len(tokens) && tokens[i] == "reset" {
				i++
			}
			r.Type = unix.NFT_REJECT_TCP_RST
			r.Code = 0
		case "icmp":
			i++
			if i < len(tokens) && tokens[i] == "type" {
				i++
				if i >= len(tokens) {
					return nil, 0, fmt.Errorf("reject with icmp type requires code")
				}
				code, err := parseICMPRejectCode(tokens[i])
				if err != nil {
					return nil, 0, err
				}
				r.Code = code
				i++
			}
			r.Type = unix.NFT_REJECT_ICMP_UNREACH
		case "icmpv6":
			i++
			if i < len(tokens) && tokens[i] == "type" {
				i++
				if i >= len(tokens) {
					return nil, 0, fmt.Errorf("reject with icmpv6 type requires code")
				}
				code, err := parseICMPv6RejectCode(tokens[i])
				if err != nil {
					return nil, 0, err
				}
				r.Code = code
				i++
			}
			r.Type = unix.NFT_REJECT_ICMP_UNREACH
		case "icmpx":
			i++
			if i < len(tokens) && tokens[i] == "type" {
				i++
				if i >= len(tokens) {
					return nil, 0, fmt.Errorf("reject with icmpx type requires code")
				}
				code, err := parseICMPxRejectCode(tokens[i])
				if err != nil {
					return nil, 0, err
				}
				r.Code = code
				i++
			}
			r.Type = unix.NFT_REJECT_ICMPX_UNREACH
		}
	} else {
		// Default reject
		switch family {
		case nftables.TableFamilyIPv4:
			r.Type = unix.NFT_REJECT_ICMP_UNREACH
			r.Code = 3 // port-unreachable
		case nftables.TableFamilyIPv6:
			r.Type = unix.NFT_REJECT_ICMP_UNREACH
			r.Code = 4 // port-unreachable
		case nftables.TableFamilyINet:
			r.Type = unix.NFT_REJECT_ICMPX_UNREACH
			r.Code = unix.NFT_REJECT_ICMPX_PORT_UNREACH
		default:
			r.Type = unix.NFT_REJECT_ICMPX_UNREACH
			r.Code = unix.NFT_REJECT_ICMPX_PORT_UNREACH
		}
	}

	return []expr.Any{r}, i, nil
}

func parseICMPRejectCode(s string) (uint8, error) {
	codes := map[string]uint8{
		"host-unreachable":    1,
		"net-unreachable":     0,
		"prot-unreachable":    2,
		"port-unreachable":    3,
		"net-prohibited":      9,
		"host-prohibited":     10,
		"admin-prohibited":    13,
	}
	if code, ok := codes[s]; ok {
		return code, nil
	}
	return 0, fmt.Errorf("unknown ICMP reject code: %q", s)
}

func parseICMPv6RejectCode(s string) (uint8, error) {
	codes := map[string]uint8{
		"no-route":          0,
		"admin-prohibited":  1,
		"addr-unreachable":  3,
		"port-unreachable":  4,
	}
	if code, ok := codes[s]; ok {
		return code, nil
	}
	return 0, fmt.Errorf("unknown ICMPv6 reject code: %q", s)
}

func parseICMPxRejectCode(s string) (uint8, error) {
	codes := map[string]uint8{
		"port-unreachable":   unix.NFT_REJECT_ICMPX_PORT_UNREACH,
		"admin-prohibited":   unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED,
		"no-route":           unix.NFT_REJECT_ICMPX_NO_ROUTE,
		"host-unreachable":   unix.NFT_REJECT_ICMPX_HOST_UNREACH,
	}
	if code, ok := codes[s]; ok {
		return code, nil
	}
	return 0, fmt.Errorf("unknown ICMPx reject code: %q", s)
}

func parseMasquerade(tokens []string) ([]expr.Any, int, error) {
	m := &expr.Masq{}
	i := 1
	for i < len(tokens) {
		switch tokens[i] {
		case "random":
			m.Random = true
			i++
		case "fully-random":
			m.FullyRandom = true
			i++
		case "persistent":
			m.Persistent = true
			i++
		case "to":
			i++
			if i < len(tokens) && strings.HasPrefix(tokens[i], ":") {
				m.ToPorts = true
				portStr := strings.TrimPrefix(tokens[i], ":")
				ports := strings.SplitN(portStr, "-", 2)
				portMin, err := strconv.ParseUint(ports[0], 10, 16)
				if err != nil {
					return nil, 0, fmt.Errorf("invalid masquerade port: %s", ports[0])
				}
				m.RegProtoMin = uint32(portMin)
				if len(ports) == 2 {
					portMax, err := strconv.ParseUint(ports[1], 10, 16)
					if err != nil {
						return nil, 0, fmt.Errorf("invalid masquerade port: %s", ports[1])
					}
					m.RegProtoMax = uint32(portMax)
				}
				i++
			}
		default:
			return []expr.Any{m}, i, nil
		}
	}
	return []expr.Any{m}, i, nil
}

func parseRedirect(tokens []string) ([]expr.Any, int, error) {
	r := &expr.Redir{}
	i := 1
	if i < len(tokens) && tokens[i] == "to" {
		i++
		if i < len(tokens) && strings.HasPrefix(tokens[i], ":") {
			portStr := strings.TrimPrefix(tokens[i], ":")
			ports := strings.SplitN(portStr, "-", 2)
			portMin, err := strconv.ParseUint(ports[0], 10, 16)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid redirect port: %s", ports[0])
			}
			_ = portMin
			// For redirect we need to use immediate + redir
			var exprs []expr.Any
			exprs = append(exprs, &expr.Immediate{
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(uint16(portMin)),
			})
			r.RegisterProtoMin = 1
			if len(ports) == 2 {
				portMax, err := strconv.ParseUint(ports[1], 10, 16)
				if err != nil {
					return nil, 0, fmt.Errorf("invalid redirect port: %s", ports[1])
				}
				exprs = append(exprs, &expr.Immediate{
					Register: 2,
					Data:     binaryutil.BigEndian.PutUint16(uint16(portMax)),
				})
				r.RegisterProtoMax = 2
			}
			exprs = append(exprs, r)
			i++
			return exprs, i, nil
		}
	}
	return []expr.Any{r}, i, nil
}

func parseLimit(tokens []string) ([]expr.Any, int, error) {
	// limit rate [over] <value> <unit> [burst <value> <unit>]
	// limit rate [over] <value> bytes/second
	i := 1
	if i >= len(tokens) || tokens[i] != "rate" {
		return nil, 0, fmt.Errorf("limit requires 'rate' keyword")
	}
	i++

	l := &expr.Limit{Type: expr.LimitTypePkts}
	if i < len(tokens) && tokens[i] == "over" {
		l.Over = true
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("limit rate requires value")
	}

	// Check for bytes rate (e.g., "10 mbytes/second")
	rateStr := tokens[i]
	i++

	// Check if it's a byte rate like "10 mbytes/second" or "10/second"
	if i < len(tokens) {
		unitStr := tokens[i]
		if strings.Contains(unitStr, "bytes/") {
			// Byte-based rate
			l.Type = expr.LimitTypePktBytes
			rate, err := strconv.ParseUint(rateStr, 10, 64)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid limit rate: %s", rateStr)
			}
			parts := strings.SplitN(unitStr, "/", 2)
			multiplier := parseByteMultiplier(parts[0])
			l.Rate = rate * multiplier
			unit, err := parseLimitUnit(parts[1])
			if err != nil {
				return nil, 0, err
			}
			l.Unit = unit
			i++
		} else if strings.HasPrefix(unitStr, "/") {
			// Packet rate with /unit
			rate, err := strconv.ParseUint(rateStr, 10, 64)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid limit rate: %s", rateStr)
			}
			l.Rate = rate
			unit, err := parseLimitUnit(strings.TrimPrefix(unitStr, "/"))
			if err != nil {
				return nil, 0, err
			}
			l.Unit = unit
			i++
		} else {
			// Try rate/unit format
			if strings.Contains(rateStr, "/") {
				parts := strings.SplitN(rateStr, "/", 2)
				rate, err := strconv.ParseUint(parts[0], 10, 64)
				if err != nil {
					return nil, 0, fmt.Errorf("invalid limit rate: %s", rateStr)
				}
				l.Rate = rate
				unit, err := parseLimitUnit(parts[1])
				if err != nil {
					return nil, 0, err
				}
				l.Unit = unit
			} else {
				rate, err := strconv.ParseUint(rateStr, 10, 64)
				if err != nil {
					return nil, 0, fmt.Errorf("invalid limit rate: %s", rateStr)
				}
				l.Rate = rate
				unit, err := parseLimitUnit(unitStr)
				if err != nil {
					return nil, 0, err
				}
				l.Unit = unit
				i++
			}
		}
	}

	// Check for burst
	if i < len(tokens) && tokens[i] == "burst" {
		i++
		if i >= len(tokens) {
			return nil, 0, fmt.Errorf("limit burst requires value")
		}
		burst, err := strconv.ParseUint(tokens[i], 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid burst value: %s", tokens[i])
		}
		l.Burst = uint32(burst)
		i++
		// Optional burst unit (e.g., "packets" or "bytes")
		if i < len(tokens) && (tokens[i] == "packets" || strings.HasSuffix(tokens[i], "bytes")) {
			i++
		}
	}

	return []expr.Any{l}, i, nil
}

func parseLimitUnit(s string) (expr.LimitTime, error) {
	switch strings.ToLower(s) {
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

func parseByteMultiplier(s string) uint64 {
	switch strings.ToLower(s) {
	case "bytes":
		return 1
	case "kbytes":
		return 1024
	case "mbytes":
		return 1024 * 1024
	default:
		return 1
	}
}

func parseQueue(tokens []string) ([]expr.Any, int, error) {
	q := &expr.Queue{}
	i := 1
	for i < len(tokens) {
		switch tokens[i] {
		case "num":
			i++
			if i >= len(tokens) {
				return nil, 0, fmt.Errorf("queue num requires value")
			}
			num, err := strconv.ParseUint(tokens[i], 10, 16)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid queue num: %s", tokens[i])
			}
			q.Num = uint16(num)
			i++
		case "bypass":
			q.Flag |= unix.NFT_QUEUE_FLAG_BYPASS
			i++
		case "fanout":
			q.Flag |= unix.NFT_QUEUE_FLAG_CPU_FANOUT
			i++
		default:
			return []expr.Any{q}, i, nil
		}
	}
	return []expr.Any{q}, i, nil
}

// --- Protocol match parsers ---

func parseIPMatch(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("ip match requires field and value")
	}

	field := tokens[1]
	i := 2

	// Parse operator
	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("ip %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "saddr":
		return parseIPAddrMatch(value, 12, 4, op)
	case "daddr":
		return parseIPAddrMatch(value, 16, 4, op)
	case "protocol":
		proto, err := parseProtocol(value)
		if err != nil {
			return nil, 0, err
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{proto}},
		}, i, nil
	case "ttl":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid ttl: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 1, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{byte(val)}},
		}, i, nil
	case "dscp":
		val, err := strconv.ParseUint(value, 0, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid dscp: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 1, Len: 1, DestRegister: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1,
				Mask: []byte{0xfc}, Xor: []byte{0x00}},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{byte(val << 2)}},
		}, i, nil
	case "length":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid length: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		}, i, nil
	case "id":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid id: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 4, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		}, i, nil
	case "frag-off":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid frag-off: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 6, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		}, i, nil
	case "version":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid version: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 1, DestRegister: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1,
				Mask: []byte{0xf0}, Xor: []byte{0x00}},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{byte(val << 4)}},
		}, i, nil
	case "hdrlength":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid hdrlength: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 1, DestRegister: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1,
				Mask: []byte{0x0f}, Xor: []byte{0x00}},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{byte(val)}},
		}, i, nil
	case "checksum":
		val, err := strconv.ParseUint(value, 0, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid checksum: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 10, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		}, i, nil
	default:
		return nil, 0, fmt.Errorf("unknown ip field: %q", field)
	}
}

func parseIPAddrMatch(value string, offset, length uint32, op expr.CmpOp) ([]expr.Any, int, error) {
	var exprs []expr.Any
	exprs = append(exprs, &expr.Payload{
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,
		Len:          length,
		DestRegister: 1,
	})

	if strings.Contains(value, "/") {
		// CIDR match
		_, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid CIDR: %s", value)
		}
		exprs = append(exprs,
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            length,
				Mask:           []byte(ipNet.Mask),
				Xor:            make([]byte, length),
			},
			&expr.Cmp{
				Op:       op,
				Register: 1,
				Data:     ipNet.IP.To4(),
			},
		)
	} else {
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, 0, fmt.Errorf("invalid IP: %s", value)
		}
		if ip4 := ip.To4(); ip4 != nil {
			exprs = append(exprs, &expr.Cmp{Op: op, Register: 1, Data: ip4})
		} else {
			exprs = append(exprs, &expr.Cmp{Op: op, Register: 1, Data: ip.To16()})
		}
	}

	return exprs, 0, nil // consumed count handled by caller
}

func parseIP6Match(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("ip6 match requires field and value")
	}

	field := tokens[1]
	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("ip6 %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "saddr":
		return parseIP6AddrMatch(value, 8, 16, op, i)
	case "daddr":
		return parseIP6AddrMatch(value, 24, 16, op, i)
	case "nexthdr":
		proto, err := parseProtocol(value)
		if err != nil {
			return nil, 0, err
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 6, Len: 1, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{proto}},
		}, i, nil
	case "hoplimit":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid hoplimit: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 7, Len: 1, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{byte(val)}},
		}, i, nil
	case "flowlabel":
		val, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid flowlabel: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 4, DestRegister: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binaryutil.BigEndian.PutUint32(0x000fffff),
				Xor:  make([]byte, 4)},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(val))},
		}, i, nil
	case "length":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid length: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 4, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		}, i, nil
	case "version":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid version: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 1, DestRegister: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1,
				Mask: []byte{0xf0}, Xor: []byte{0x00}},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{byte(val << 4)}},
		}, i, nil
	case "dscp":
		val, err := strconv.ParseUint(value, 0, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid dscp: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 2, DestRegister: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 2,
				Mask: binaryutil.BigEndian.PutUint16(0x0fc0),
				Xor:  make([]byte, 2)},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val) << 6)},
		}, i, nil
	default:
		return nil, 0, fmt.Errorf("unknown ip6 field: %q", field)
	}
}

func parseIP6AddrMatch(value string, offset, length uint32, op expr.CmpOp, consumed int) ([]expr.Any, int, error) {
	var exprs []expr.Any
	exprs = append(exprs, &expr.Payload{
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,
		Len:          length,
		DestRegister: 1,
	})

	if strings.Contains(value, "/") {
		_, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid CIDR: %s", value)
		}
		exprs = append(exprs,
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            length,
				Mask:           []byte(ipNet.Mask),
				Xor:            make([]byte, length),
			},
			&expr.Cmp{Op: op, Register: 1, Data: ipNet.IP.To16()},
		)
	} else {
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, 0, fmt.Errorf("invalid IPv6: %s", value)
		}
		exprs = append(exprs, &expr.Cmp{Op: op, Register: 1, Data: ip.To16()})
	}

	return exprs, consumed, nil
}

func parseTCPMatch(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("tcp match requires field and value")
	}

	// First, add the L4 protocol match for TCP
	var protoExprs []expr.Any
	protoExprs = append(protoExprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
	)

	field := tokens[1]
	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("tcp %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "sport":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid port: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
		), i, nil
	case "dport":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid port: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
		), i, nil
	case "flags":
		flags, err := parseTCPFlags(value)
		if err != nil {
			return nil, 0, err
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1, DestRegister: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1,
				Mask: []byte{flags}, Xor: []byte{0x00}},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00}},
		), i, nil
	case "sequence":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid sequence: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 4, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(val))},
		), i, nil
	case "ackseq":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid ackseq: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 8, Len: 4, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(val))},
		), i, nil
	case "doff":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid doff: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 12, Len: 1, DestRegister: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1,
				Mask: []byte{0xf0}, Xor: []byte{0x00}},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{byte(val << 4)}},
		), i, nil
	case "window":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid window: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 14, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	case "checksum":
		val, err := strconv.ParseUint(value, 0, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid checksum: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 16, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	case "urgptr":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid urgptr: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 18, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	default:
		return nil, 0, fmt.Errorf("unknown tcp field: %q", field)
	}
}

func parseTCPFlags(s string) (byte, error) {
	var flags byte
	for _, part := range strings.Split(s, "|") {
		switch strings.TrimSpace(part) {
		case "fin":
			flags |= 0x01
		case "syn":
			flags |= 0x02
		case "rst":
			flags |= 0x04
		case "psh":
			flags |= 0x08
		case "ack":
			flags |= 0x10
		case "urg":
			flags |= 0x20
		case "ecn":
			flags |= 0x40
		case "cwr":
			flags |= 0x80
		default:
			return 0, fmt.Errorf("unknown tcp flag: %q", part)
		}
	}
	return flags, nil
}

func parseUDPMatch(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("udp match requires field and value")
	}

	var protoExprs []expr.Any
	protoExprs = append(protoExprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
	)

	field := tokens[1]
	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("udp %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "sport":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid port: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
		), i, nil
	case "dport":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid port: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
		), i, nil
	case "length":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid length: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	case "checksum":
		val, err := strconv.ParseUint(value, 0, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid checksum: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 6, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	default:
		return nil, 0, fmt.Errorf("unknown udp field: %q", field)
	}
}

func parseICMPMatch(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("icmp match requires field and value")
	}

	var protoExprs []expr.Any
	protoExprs = append(protoExprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMP}},
	)

	field := tokens[1]
	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("icmp %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "type":
		t, err := parseICMPType(value)
		if err != nil {
			return nil, 0, err
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{t}},
		), i, nil
	case "code":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid icmp code: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 1, Len: 1, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{byte(val)}},
		), i, nil
	case "checksum":
		val, err := strconv.ParseUint(value, 0, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid checksum: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	case "id":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid icmp id: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	case "sequence":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid icmp sequence: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 6, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	case "mtu":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid icmp mtu: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 6, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	case "gateway":
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, 0, fmt.Errorf("invalid gateway IP: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 4, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: ip.To4()},
		), i, nil
	default:
		return nil, 0, fmt.Errorf("unknown icmp field: %q", field)
	}
}

func parseICMPType(s string) (byte, error) {
	types := map[string]byte{
		"echo-reply":              0,
		"destination-unreachable": 3,
		"source-quench":           4,
		"redirect":                5,
		"echo-request":            8,
		"router-advertisement":    9,
		"router-solicitation":     10,
		"time-exceeded":           11,
		"parameter-problem":       12,
		"timestamp-request":       13,
		"timestamp-reply":         14,
		"info-request":            15,
		"info-reply":              16,
		"address-mask-request":    17,
		"address-mask-reply":      18,
	}
	if t, ok := types[s]; ok {
		return t, nil
	}
	// Try numeric
	val, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("unknown ICMP type: %q", s)
	}
	return byte(val), nil
}

func parseICMPv6Match(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("icmpv6 match requires field and value")
	}

	var protoExprs []expr.Any
	protoExprs = append(protoExprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
	)

	field := tokens[1]
	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("icmpv6 %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "type":
		t, err := parseICMPv6Type(value)
		if err != nil {
			return nil, 0, err
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{t}},
		), i, nil
	case "code":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid icmpv6 code: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 1, Len: 1, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{byte(val)}},
		), i, nil
	case "checksum":
		val, err := strconv.ParseUint(value, 0, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid checksum: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	case "id":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid icmpv6 id: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	case "sequence":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid icmpv6 sequence: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 6, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	case "mtu":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid icmpv6 mtu: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 4, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(val))},
		), i, nil
	case "max-delay":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid icmpv6 max-delay: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	default:
		return nil, 0, fmt.Errorf("unknown icmpv6 field: %q", field)
	}
}

func parseICMPv6Type(s string) (byte, error) {
	types := map[string]byte{
		"destination-unreachable": 1,
		"packet-too-big":          2,
		"time-exceeded":           3,
		"parameter-problem":       4,
		"echo-request":            128,
		"echo-reply":              129,
		"mld-listener-query":      130,
		"mld-listener-report":     131,
		"mld-listener-done":       132,
		"nd-router-solicit":       133,
		"nd-router-advert":        134,
		"nd-neighbor-solicit":     135,
		"nd-neighbor-advert":      136,
		"nd-redirect":             137,
	}
	if t, ok := types[s]; ok {
		return t, nil
	}
	val, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("unknown ICMPv6 type: %q", s)
	}
	return byte(val), nil
}

func parseEtherMatch(tokens []string) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("ether match requires field and value")
	}

	field := tokens[1]
	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("ether %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "saddr":
		mac, err := net.ParseMAC(value)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid MAC: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 6, Len: 6, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: mac},
		}, i, nil
	case "daddr":
		mac, err := net.ParseMAC(value)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid MAC: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 0, Len: 6, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: mac},
		}, i, nil
	case "type":
		val, err := strconv.ParseUint(value, 0, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid ether type: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 12, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		}, i, nil
	default:
		return nil, 0, fmt.Errorf("unknown ether field: %q", field)
	}
}

func parseVLANMatch(tokens []string) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("vlan match requires field and value")
	}

	field := tokens[1]
	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("vlan %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "id":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid vlan id: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 14, Len: 2, DestRegister: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 2,
				Mask: binaryutil.BigEndian.PutUint16(0x0fff),
				Xor:  make([]byte, 2)},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		}, i, nil
	case "cfi":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid vlan cfi: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 14, Len: 2, DestRegister: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 2,
				Mask: binaryutil.BigEndian.PutUint16(0x1000),
				Xor:  make([]byte, 2)},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val) << 12)},
		}, i, nil
	case "pcp":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid vlan pcp: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 14, Len: 2, DestRegister: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 2,
				Mask: binaryutil.BigEndian.PutUint16(0xe000),
				Xor:  make([]byte, 2)},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val) << 13)},
		}, i, nil
	default:
		return nil, 0, fmt.Errorf("unknown vlan field: %q", field)
	}
}

func parseARPMatch(tokens []string) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("arp match requires field and value")
	}

	field := tokens[1]
	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("arp %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "htype":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid arp htype: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		}, i, nil
	case "ptype":
		val, err := strconv.ParseUint(value, 0, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid arp ptype: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		}, i, nil
	case "hlen":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid arp hlen: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 4, Len: 1, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{byte(val)}},
		}, i, nil
	case "plen":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid arp plen: %s", value)
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 5, Len: 1, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{byte(val)}},
		}, i, nil
	case "operation":
		val, err := parseARPOperation(value)
		if err != nil {
			return nil, 0, err
		}
		return []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 6, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(val)},
		}, i, nil
	default:
		return nil, 0, fmt.Errorf("unknown arp field: %q", field)
	}
}

func parseARPOperation(s string) (uint16, error) {
	ops := map[string]uint16{
		"request":   1,
		"reply":     2,
		"rrequest":  3,
		"rreply":    4,
		"inrequest": 8,
		"inreply":   9,
		"nak":       10,
	}
	if v, ok := ops[s]; ok {
		return v, nil
	}
	val, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("unknown ARP operation: %q", s)
	}
	return uint16(val), nil
}

func parseSCTPMatch(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("sctp match requires field and value")
	}

	var protoExprs []expr.Any
	protoExprs = append(protoExprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_SCTP}},
	)

	field := tokens[1]
	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("sctp %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "sport":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid port: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
		), i, nil
	case "dport":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid port: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
		), i, nil
	case "vtag":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid vtag: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 4, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(val))},
		), i, nil
	case "checksum":
		val, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid checksum: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 8, Len: 4, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(val))},
		), i, nil
	default:
		return nil, 0, fmt.Errorf("unknown sctp field: %q", field)
	}
}

func parseDCCPMatch(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("dccp match requires field and value")
	}

	var protoExprs []expr.Any
	protoExprs = append(protoExprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_DCCP}},
	)

	field := tokens[1]
	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("dccp %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "sport":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid port: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
		), i, nil
	case "dport":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid port: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
		), i, nil
	case "type":
		t, err := parseDCCPType(value)
		if err != nil {
			return nil, 0, err
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 8, Len: 1, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{t}},
		), i, nil
	default:
		return nil, 0, fmt.Errorf("unknown dccp field: %q", field)
	}
}

func parseDCCPType(s string) (byte, error) {
	types := map[string]byte{
		"request":  0,
		"response": 1,
		"data":     2,
		"ack":      3,
		"dataack":  4,
		"closereq": 5,
		"close":    6,
		"reset":    7,
		"sync":     8,
		"syncack":  9,
	}
	if t, ok := types[s]; ok {
		return t, nil
	}
	val, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("unknown DCCP type: %q", s)
	}
	return byte(val), nil
}

func parseESPMatch(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("esp match requires field and value")
	}

	var protoExprs []expr.Any
	protoExprs = append(protoExprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ESP}},
	)

	field := tokens[1]
	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("esp %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "spi":
		val, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid spi: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 4, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(val))},
		), i, nil
	case "sequence":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid sequence: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 4, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(val))},
		), i, nil
	default:
		return nil, 0, fmt.Errorf("unknown esp field: %q", field)
	}
}

func parseAHMatch(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("ah match requires field and value")
	}

	var protoExprs []expr.Any
	protoExprs = append(protoExprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_AH}},
	)

	field := tokens[1]
	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("ah %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "hdrlength":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid hdrlength: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 1, Len: 1, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{byte(val)}},
		), i, nil
	case "reserved":
		val, err := strconv.ParseUint(value, 0, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid reserved: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	case "spi":
		val, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid spi: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 4, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(val))},
		), i, nil
	case "sequence":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid sequence: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 8, Len: 4, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(val))},
		), i, nil
	default:
		return nil, 0, fmt.Errorf("unknown ah field: %q", field)
	}
}

func parseCompMatch(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("comp match requires field and value")
	}

	var protoExprs []expr.Any
	protoExprs = append(protoExprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_COMP}},
	)

	field := tokens[1]
	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("comp %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "nexthdr":
		proto, err := parseProtocol(value)
		if err != nil {
			return nil, 0, err
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{proto}},
		), i, nil
	case "flags":
		val, err := strconv.ParseUint(value, 0, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid flags: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 1, Len: 1, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{byte(val)}},
		), i, nil
	case "cpi":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid cpi: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	default:
		return nil, 0, fmt.Errorf("unknown comp field: %q", field)
	}
}

func parseUDPLiteMatch(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("udplite match requires field and value")
	}

	var protoExprs []expr.Any
	protoExprs = append(protoExprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDPLITE}},
	)

	field := tokens[1]
	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("udplite %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "sport":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid port: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
		), i, nil
	case "dport":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid port: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
		), i, nil
	case "checksum":
		val, err := strconv.ParseUint(value, 0, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid checksum: %s", value)
		}
		return append(protoExprs,
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 6, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		), i, nil
	default:
		return nil, 0, fmt.Errorf("unknown udplite field: %q", field)
	}
}

// --- Meta match parser ---

func parseMetaMatch(tokens []string) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("meta match requires field and value")
	}

	field := tokens[1]

	// Handle "meta mark set <value>"
	if len(tokens) >= 4 && tokens[2] == "set" {
		return parseMetaSet(tokens)
	}

	i := 2

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("meta %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "iif":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid iif index: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIF, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		}, i, nil
	case "iifname":
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: ifnameBytes(value)},
		}, i, nil
	case "iiftype":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid iiftype: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFTYPE, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		}, i, nil
	case "iifkind":
		return []expr.Any{
			&expr.Meta{Key: 20, Register: 1}, // NFT_META_IIFKIND
			&expr.Cmp{Op: op, Register: 1, Data: ifnameBytes(value)},
		}, i, nil
	case "iifgroup":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid iifgroup: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFGROUP, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		}, i, nil
	case "oif":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid oif index: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIF, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		}, i, nil
	case "oifname":
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: ifnameBytes(value)},
		}, i, nil
	case "oiftype":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid oiftype: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFTYPE, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		}, i, nil
	case "oifkind":
		return []expr.Any{
			&expr.Meta{Key: 21, Register: 1}, // NFT_META_OIFKIND
			&expr.Cmp{Op: op, Register: 1, Data: ifnameBytes(value)},
		}, i, nil
	case "oifgroup":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid oifgroup: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFGROUP, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		}, i, nil
	case "length":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid length: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyLEN, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		}, i, nil
	case "protocol":
		val, err := strconv.ParseUint(value, 0, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid protocol: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyPROTOCOL, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(val))},
		}, i, nil
	case "nfproto":
		val, err := parseNFProto(value)
		if err != nil {
			return nil, 0, err
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{val}},
		}, i, nil
	case "l4proto":
		proto, err := parseProtocol(value)
		if err != nil {
			return nil, 0, err
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{proto}},
		}, i, nil
	case "mark":
		val, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid mark: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		}, i, nil
	case "priority":
		val, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid priority: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyPRIORITY, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		}, i, nil
	case "skuid":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid skuid: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		}, i, nil
	case "skgid":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid skgid: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeySKGID, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		}, i, nil
	case "pkttype":
		val, err := parsePktType(value)
		if err != nil {
			return nil, 0, err
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyPKTTYPE, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{val}},
		}, i, nil
	case "cpu":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid cpu: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyCPU, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		}, i, nil
	case "cgroup":
		val, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid cgroup: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyCGROUP, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		}, i, nil
	case "nftrace":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid nftrace: %s", value)
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFTRACE, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{byte(val)}},
		}, i, nil
	default:
		return nil, 0, fmt.Errorf("unknown meta field: %q", field)
	}
}

func parseMetaShorthand(tokens []string) ([]expr.Any, int, error) {
	// Convert shorthand like "iifname eth0" to "meta iifname eth0"
	newTokens := append([]string{"meta"}, tokens...)
	return parseMetaMatch(newTokens)
}

func parseMetaSet(tokens []string) ([]expr.Any, int, error) {
	// meta <field> set <value>
	if len(tokens) < 4 {
		return nil, 0, fmt.Errorf("meta set requires field and value")
	}

	field := tokens[1]
	value := tokens[3]
	i := 4

	switch field {
	case "mark":
		val, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid mark: %s", value)
		}
		return []expr.Any{
			&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
		}, i, nil
	case "priority":
		val, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid priority: %s", value)
		}
		return []expr.Any{
			&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
			&expr.Meta{Key: expr.MetaKeyPRIORITY, Register: 1, SourceRegister: true},
		}, i, nil
	case "nftrace":
		val, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid nftrace: %s", value)
		}
		return []expr.Any{
			&expr.Immediate{Register: 1, Data: []byte{byte(val)}},
			&expr.Meta{Key: expr.MetaKeyNFTRACE, Register: 1, SourceRegister: true},
		}, i, nil
	case "pkttype":
		val, err := parsePktType(value)
		if err != nil {
			return nil, 0, err
		}
		return []expr.Any{
			&expr.Immediate{Register: 1, Data: []byte{val}},
			&expr.Meta{Key: expr.MetaKeyPKTTYPE, Register: 1, SourceRegister: true},
		}, i, nil
	default:
		return nil, 0, fmt.Errorf("cannot set meta field: %q", field)
	}
}

func parsePktType(s string) (byte, error) {
	types := map[string]byte{
		"host":      0,
		"broadcast": 1,
		"multicast": 2,
		"other":     3,
	}
	if v, ok := types[s]; ok {
		return v, nil
	}
	val, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("unknown packet type: %q", s)
	}
	return byte(val), nil
}

func parseNFProto(s string) (byte, error) {
	switch strings.ToLower(s) {
	case "ipv4", "ip":
		return unix.NFPROTO_IPV4, nil
	case "ipv6", "ip6":
		return unix.NFPROTO_IPV6, nil
	default:
		val, err := strconv.ParseUint(s, 10, 8)
		if err != nil {
			return 0, fmt.Errorf("unknown nfproto: %q", s)
		}
		return byte(val), nil
	}
}

// --- CT match parser ---

func parseCTMatch(tokens []string) ([]expr.Any, int, error) {
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("ct match requires field and value")
	}

	field := tokens[1]

	// Handle "ct mark set <value>"
	if len(tokens) >= 4 && tokens[2] == "set" {
		return parseCTSet(tokens)
	}

	i := 2

	// Handle ct direction fields: ct original/reply saddr/daddr/proto-src/proto-dst
	var direction uint32 // 0 = original
	if field == "original" || field == "reply" {
		if field == "reply" {
			direction = 1 // IP_CT_DIR_REPLY
		}
		if i >= len(tokens) {
			return nil, 0, fmt.Errorf("ct %s requires subfield", field)
		}
		field = tokens[i]
		i++
	}

	op := expr.CmpOpEq
	if i < len(tokens) && tokens[i] == "!=" {
		op = expr.CmpOpNeq
		i++
	}

	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("ct %s requires value", field)
	}
	value := tokens[i]
	i++

	switch field {
	case "state":
		state, err := parseCTState(value)
		if err != nil {
			return nil, 0, err
		}
		return []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binaryutil.NativeEndian.PutUint32(state),
				Xor:  make([]byte, 4)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
		}, i, nil
	case "direction":
		var d uint8
		switch value {
		case "original":
			d = 0
		case "reply":
			d = 1
		default:
			return nil, 0, fmt.Errorf("unknown ct direction: %q", value)
		}
		return []expr.Any{
			&expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{d}},
		}, i, nil
	case "status":
		status, err := parseCTStatus(value)
		if err != nil {
			return nil, 0, err
		}
		return []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATUS, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binaryutil.NativeEndian.PutUint32(status),
				Xor:  make([]byte, 4)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
		}, i, nil
	case "mark":
		val, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid ct mark: %s", value)
		}
		return []expr.Any{
			&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		}, i, nil
	case "zone":
		val, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid ct zone: %s", value)
		}
		return []expr.Any{
			&expr.Ct{Key: expr.CtKeyZONE, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint16(uint16(val))},
		}, i, nil
	case "l3proto":
		val, err := parseNFProto(value)
		if err != nil {
			return nil, 0, err
		}
		return []expr.Any{
			&expr.Ct{Key: expr.CtKeyL3PROTOCOL, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{val}},
		}, i, nil
	case "protocol":
		proto, err := parseProtocol(value)
		if err != nil {
			return nil, 0, err
		}
		return []expr.Any{
			&expr.Ct{Key: expr.CtKeyPROTOCOL, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: []byte{proto}},
		}, i, nil
	case "saddr":
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, 0, fmt.Errorf("invalid IP: %s", value)
		}
		key := expr.CtKeySRC
		if ip4 := ip.To4(); ip4 != nil {
			return []expr.Any{
				&expr.Ct{Key: key, Register: 1, Direction: direction},
				&expr.Cmp{Op: op, Register: 1, Data: ip4},
			}, i, nil
		}
		return []expr.Any{
			&expr.Ct{Key: key, Register: 1, Direction: direction},
			&expr.Cmp{Op: op, Register: 1, Data: ip.To16()},
		}, i, nil
	case "daddr":
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, 0, fmt.Errorf("invalid IP: %s", value)
		}
		key := expr.CtKeyDST
		if ip4 := ip.To4(); ip4 != nil {
			return []expr.Any{
				&expr.Ct{Key: key, Register: 1, Direction: direction},
				&expr.Cmp{Op: op, Register: 1, Data: ip4},
			}, i, nil
		}
		return []expr.Any{
			&expr.Ct{Key: key, Register: 1, Direction: direction},
			&expr.Cmp{Op: op, Register: 1, Data: ip.To16()},
		}, i, nil
	case "proto-src":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid port: %s", value)
		}
		return []expr.Any{
			&expr.Ct{Key: expr.CtKeyPROTOSRC, Register: 1, Direction: direction},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
		}, i, nil
	case "proto-dst":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid port: %s", value)
		}
		return []expr.Any{
			&expr.Ct{Key: expr.CtKeyPROTODST, Register: 1, Direction: direction},
			&expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
		}, i, nil
	case "helper":
		return []expr.Any{
			&expr.Ct{Key: expr.CtKeyHELPER, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: ifnameBytes(value)},
		}, i, nil
	default:
		return nil, 0, fmt.Errorf("unknown ct field: %q", field)
	}
}

func parseCTSet(tokens []string) ([]expr.Any, int, error) {
	if len(tokens) < 4 {
		return nil, 0, fmt.Errorf("ct set requires field and value")
	}

	field := tokens[1]
	value := tokens[3]
	i := 4

	switch field {
	case "mark":
		val, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid ct mark: %s", value)
		}
		return []expr.Any{
			&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
			&expr.Ct{Key: expr.CtKeyMARK, Register: 1, SourceRegister: true},
		}, i, nil
	default:
		return nil, 0, fmt.Errorf("cannot set ct field: %q", field)
	}
}

func parseCTState(s string) (uint32, error) {
	var state uint32
	for _, part := range strings.Split(s, ",") {
		switch strings.TrimSpace(part) {
		case "new":
			state |= expr.CtStateBitNEW
		case "established":
			state |= expr.CtStateBitESTABLISHED
		case "related":
			state |= expr.CtStateBitRELATED
		case "invalid":
			state |= expr.CtStateBitINVALID
		case "untracked":
			state |= expr.CtStateBitUNTRACKED
		default:
			return 0, fmt.Errorf("unknown ct state: %q", part)
		}
	}
	return state, nil
}

func parseCTStatus(s string) (uint32, error) {
	statuses := map[string]uint32{
		"expected":  1,
		"seen-reply": 2,
		"assured":   4,
		"confirmed": 8,
		"snat":      16,
		"dnat":      32,
		"dying":     512,
	}
	var result uint32
	for _, part := range strings.Split(s, ",") {
		if v, ok := statuses[strings.TrimSpace(part)]; ok {
			result |= v
		} else {
			return 0, fmt.Errorf("unknown ct status: %q", part)
		}
	}
	return result, nil
}

// --- NAT parsers ---

func parseSNAT(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	// snat to <addr>[:<port>[-<port>]]
	if len(tokens) < 3 || tokens[1] != "to" {
		return nil, 0, fmt.Errorf("snat requires 'to <addr>'")
	}

	i := 2
	addrPort := tokens[i]
	i++

	return parseNATAddrPort(addrPort, expr.NATTypeSourceNAT, family, i)
}

func parseDNAT(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	// dnat to <addr>[:<port>[-<port>]]
	if len(tokens) < 3 || tokens[1] != "to" {
		return nil, 0, fmt.Errorf("dnat requires 'to <addr>'")
	}

	i := 2
	addrPort := tokens[i]
	i++

	return parseNATAddrPort(addrPort, expr.NATTypeDestNAT, family, i)
}

func parseNATAddrPort(s string, natType expr.NATType, family nftables.TableFamily, consumed int) ([]expr.Any, int, error) {
	var exprs []expr.Any
	nat := &expr.NAT{
		Type:   natType,
		Family: uint32(family),
	}

	// Split addr:port
	var addrStr, portStr string
	if idx := strings.LastIndex(s, ":"); idx != -1 {
		addrStr = s[:idx]
		portStr = s[idx+1:]
	} else {
		addrStr = s
	}

	// Parse address
	ip := net.ParseIP(addrStr)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid NAT address: %s", addrStr)
	}

	var ipData []byte
	if ip4 := ip.To4(); ip4 != nil {
		ipData = ip4
		nat.Family = uint32(nftables.TableFamilyIPv4)
	} else {
		ipData = ip.To16()
		nat.Family = uint32(nftables.TableFamilyIPv6)
	}

	exprs = append(exprs, &expr.Immediate{Register: 1, Data: ipData})
	nat.RegAddrMin = 1

	if portStr != "" {
		ports := strings.SplitN(portStr, "-", 2)
		portMin, err := strconv.ParseUint(ports[0], 10, 16)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid NAT port: %s", ports[0])
		}
		exprs = append(exprs, &expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(uint16(portMin))})
		nat.RegProtoMin = 2

		if len(ports) == 2 {
			portMax, err := strconv.ParseUint(ports[1], 10, 16)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid NAT port: %s", ports[1])
			}
			exprs = append(exprs, &expr.Immediate{Register: 3, Data: binaryutil.BigEndian.PutUint16(uint16(portMax))})
			nat.RegProtoMax = 3
		}
	}

	exprs = append(exprs, nat)
	return exprs, consumed, nil
}

// --- Mark set ---

func parseMarkSet(tokens []string) ([]expr.Any, int, error) {
	// mark set <value>
	if len(tokens) < 3 || tokens[1] != "set" {
		return nil, 0, fmt.Errorf("mark requires 'set <value>'")
	}
	val, err := strconv.ParseUint(tokens[2], 0, 32)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid mark value: %s", tokens[2])
	}
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
	}, 3, nil
}

// --- Flow offload ---

func parseFlowOffload(tokens []string) ([]expr.Any, int, error) {
	// flow add @<flowtable>
	if len(tokens) < 3 || tokens[1] != "add" {
		return nil, 0, fmt.Errorf("flow requires 'add @<flowtable>'")
	}
	name := strings.TrimPrefix(tokens[2], "@")
	return []expr.Any{&expr.FlowOffload{Name: name}}, 3, nil
}

// --- Fib ---

func parseFib(tokens []string) ([]expr.Any, int, error) {
	// fib saddr . iif oif [!= 0]
	// fib daddr type { local, broadcast, multicast }
	// Simplified: fib <flags> <result> [<op> <value>]
	if len(tokens) < 3 {
		return nil, 0, fmt.Errorf("fib requires flags and result")
	}

	f := &expr.Fib{Register: 1}
	i := 1

	// Parse flags with dot concatenation
	for i < len(tokens) {
		switch tokens[i] {
		case "saddr":
			f.FlagSADDR = true
			i++
		case "daddr":
			f.FlagDADDR = true
			i++
		case "mark":
			f.FlagMARK = true
			i++
		case "iif":
			f.FlagIIF = true
			i++
		case "oif":
			f.FlagOIF = true
			i++
		case ".":
			i++ // skip concatenation operator
		default:
			goto parseResult
		}
	}

parseResult:
	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("fib requires result type")
	}

	switch tokens[i] {
	case "oif":
		f.ResultOIF = true
		i++
	case "oifname":
		f.ResultOIFNAME = true
		i++
	case "type":
		f.ResultADDRTYPE = true
		i++
	default:
		return nil, 0, fmt.Errorf("unknown fib result: %q", tokens[i])
	}

	var result []expr.Any
	result = append(result, f)

	// Optional comparison
	if i < len(tokens) {
		op := expr.CmpOpEq
		if tokens[i] == "!=" {
			op = expr.CmpOpNeq
			i++
		}
		if i < len(tokens) {
			val, err := strconv.ParseUint(tokens[i], 10, 32)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid fib value: %s", tokens[i])
			}
			result = append(result, &expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(val))})
			i++
		}
	}

	return result, i, nil
}

// --- Dup ---

func parseDup(tokens []string, family nftables.TableFamily) ([]expr.Any, int, error) {
	// dup to <addr> device <dev>
	if len(tokens) < 3 || tokens[1] != "to" {
		return nil, 0, fmt.Errorf("dup requires 'to <addr>'")
	}

	ip := net.ParseIP(tokens[2])
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid dup address: %s", tokens[2])
	}

	var ipData []byte
	if ip4 := ip.To4(); ip4 != nil {
		ipData = ip4
	} else {
		ipData = ip.To16()
	}

	exprs := []expr.Any{
		&expr.Immediate{Register: 1, Data: ipData},
	}

	d := &expr.Dup{RegAddr: 1}
	i := 3

	if i+1 < len(tokens) && tokens[i] == "device" {
		i++
		// Device index would need to be resolved
		devIdx, err := strconv.ParseUint(tokens[i], 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid device index: %s (use numeric index)", tokens[i])
		}
		exprs = append(exprs, &expr.Immediate{Register: 2, Data: binaryutil.NativeEndian.PutUint32(uint32(devIdx))})
		d.RegDev = 2
		i++
	}

	exprs = append(exprs, d)
	return exprs, i, nil
}

// --- Helpers ---

func parseProtocol(s string) (byte, error) {
	protos := map[string]byte{
		"tcp":     unix.IPPROTO_TCP,
		"udp":     unix.IPPROTO_UDP,
		"icmp":    unix.IPPROTO_ICMP,
		"icmpv6":  unix.IPPROTO_ICMPV6,
		"sctp":    unix.IPPROTO_SCTP,
		"dccp":    unix.IPPROTO_DCCP,
		"gre":     unix.IPPROTO_GRE,
		"esp":     unix.IPPROTO_ESP,
		"ah":      unix.IPPROTO_AH,
		"comp":    unix.IPPROTO_COMP,
		"udplite": unix.IPPROTO_UDPLITE,
		"ipip":    unix.IPPROTO_IPIP,
		"ipv6":    unix.IPPROTO_IPV6,
	}
	if p, ok := protos[strings.ToLower(s)]; ok {
		return p, nil
	}
	val, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("unknown protocol: %q", s)
	}
	return byte(val), nil
}

func ifnameBytes(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}

// binaryutil helper for native endian uint16
func nativeEndianUint16(v uint16) []byte {
	b := make([]byte, 2)
	binary.NativeEndian.PutUint16(b, v)
	return b
}
