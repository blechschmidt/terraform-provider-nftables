package provider

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &ChainResource{}
	_ resource.ResourceWithImportState = &ChainResource{}
)

type ChainResource struct {
	data *NftablesProviderData
}

type ChainModel struct {
	Family   types.String `tfsdk:"family"`
	Table    types.String `tfsdk:"table"`
	Name     types.String `tfsdk:"name"`
	Type     types.String `tfsdk:"type"`
	Hook     types.String `tfsdk:"hook"`
	Priority types.Int32  `tfsdk:"priority"`
	Policy   types.String `tfsdk:"policy"`
	Device   types.String `tfsdk:"device"`
}

func NewChainResource() resource.Resource {
	return &ChainResource{}
}

func (r *ChainResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_chain"
}

func (r *ChainResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an nftables chain.",
		Attributes: map[string]schema.Attribute{
			"family": schema.StringAttribute{
				Required:    true,
				Description: "Address family of the table.",
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
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Chain name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Optional:    true,
				Description: "Chain type: filter, route, or nat. Required for base chains.",
			},
			"hook": schema.StringAttribute{
				Optional:    true,
				Description: "Netfilter hook: prerouting, input, forward, output, postrouting, ingress, egress.",
			},
			"priority": schema.Int32Attribute{
				Optional:    true,
				Description: "Chain priority. Required for base chains.",
			},
			"policy": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Default policy: accept or drop. Default: accept.",
			},
			"device": schema.StringAttribute{
				Optional:    true,
				Description: "Device for netdev family ingress/egress hooks.",
			},
		},
	}
}

func (r *ChainResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ChainResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ChainModel
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

	chain := &nftables.Chain{
		Name:  plan.Name.ValueString(),
		Table: table,
	}

	if !plan.Type.IsNull() && !plan.Type.IsUnknown() {
		chainType, err := parseChainType(plan.Type.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid chain type", err.Error())
			return
		}
		chain.Type = chainType
	}

	if !plan.Hook.IsNull() && !plan.Hook.IsUnknown() {
		hooknum, err := parseChainHook(plan.Hook.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid hook", err.Error())
			return
		}
		chain.Hooknum = hooknum
	}

	if !plan.Priority.IsNull() && !plan.Priority.IsUnknown() {
		prio := nftables.ChainPriority(plan.Priority.ValueInt32())
		chain.Priority = &prio
	}

	if !plan.Policy.IsNull() && !plan.Policy.IsUnknown() {
		policy, err := parseChainPolicy(plan.Policy.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid policy", err.Error())
			return
		}
		chain.Policy = policy
	}

	if !plan.Device.IsNull() && !plan.Device.IsUnknown() {
		chain.Device = plan.Device.ValueString()
	}

	r.data.Conn.AddChain(chain)

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to create chain", err.Error())
		return
	}

	// Set computed defaults
	if plan.Policy.IsNull() || plan.Policy.IsUnknown() {
		if chain.Hooknum != nil {
			plan.Policy = types.StringValue("accept")
		} else {
			plan.Policy = types.StringNull()
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ChainResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ChainModel
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

	chains, err := r.data.Conn.ListChainsOfTableFamily(family)
	if err != nil {
		resp.Diagnostics.AddError("Failed to list chains", err.Error())
		return
	}

	var found *nftables.Chain
	for _, c := range chains {
		if c.Table.Name == table.Name && c.Name == state.Name.ValueString() {
			found = c
			break
		}
	}

	if found == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	if found.Type != "" {
		state.Type = types.StringValue(string(found.Type))
	}
	if found.Hooknum != nil {
		state.Hook = types.StringValue(hookString(*found.Hooknum))
	}
	if found.Priority != nil {
		state.Priority = types.Int32Value(int32(*found.Priority))
	}
	if found.Policy != nil {
		state.Policy = types.StringValue(policyString(*found.Policy))
	}
	if found.Device != "" {
		state.Device = types.StringValue(found.Device)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ChainResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ChainModel
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

	chain := &nftables.Chain{
		Name:  plan.Name.ValueString(),
		Table: table,
	}

	if !plan.Type.IsNull() && !plan.Type.IsUnknown() {
		chainType, _ := parseChainType(plan.Type.ValueString())
		chain.Type = chainType
	}
	if !plan.Hook.IsNull() && !plan.Hook.IsUnknown() {
		hooknum, _ := parseChainHook(plan.Hook.ValueString())
		chain.Hooknum = hooknum
	}
	if !plan.Priority.IsNull() && !plan.Priority.IsUnknown() {
		prio := nftables.ChainPriority(plan.Priority.ValueInt32())
		chain.Priority = &prio
	}
	if !plan.Policy.IsNull() && !plan.Policy.IsUnknown() {
		policy, _ := parseChainPolicy(plan.Policy.ValueString())
		chain.Policy = policy
	}
	if !plan.Device.IsNull() && !plan.Device.IsUnknown() {
		chain.Device = plan.Device.ValueString()
	}

	r.data.Conn.AddChain(chain)

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to update chain", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ChainResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ChainModel
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
	chain := &nftables.Chain{
		Name:  state.Name.ValueString(),
		Table: table,
	}

	// Flush all rules in the chain before deleting to avoid "device busy"
	r.data.Conn.FlushChain(chain)
	if err := r.data.Conn.Flush(); err != nil {
		// Ignore flush errors - chain may already be empty
	}

	r.data.Conn.DelChain(chain)
	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to delete chain", err.Error())
		return
	}
}

func (r *ChainResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, "|", 3)
	if len(parts) != 3 {
		resp.Diagnostics.AddError("Invalid import ID", "Expected format: family|table|chain")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("family"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("table"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[2])...)
}

func parseChainType(s string) (nftables.ChainType, error) {
	switch strings.ToLower(s) {
	case "filter":
		return nftables.ChainTypeFilter, nil
	case "route":
		return nftables.ChainTypeRoute, nil
	case "nat":
		return nftables.ChainTypeNAT, nil
	default:
		return "", fmt.Errorf("unknown chain type: %q (valid: filter, route, nat)", s)
	}
}

func parseChainHook(s string) (*nftables.ChainHook, error) {
	switch strings.ToLower(s) {
	case "prerouting":
		return nftables.ChainHookPrerouting, nil
	case "input":
		return nftables.ChainHookInput, nil
	case "forward":
		return nftables.ChainHookForward, nil
	case "output":
		return nftables.ChainHookOutput, nil
	case "postrouting":
		return nftables.ChainHookPostrouting, nil
	case "ingress":
		return nftables.ChainHookIngress, nil
	case "egress":
		return nftables.ChainHookEgress, nil
	default:
		return nil, fmt.Errorf("unknown hook: %q (valid: prerouting, input, forward, output, postrouting, ingress, egress)", s)
	}
}

func parseChainPolicy(s string) (*nftables.ChainPolicy, error) {
	var p nftables.ChainPolicy
	switch strings.ToLower(s) {
	case "accept":
		p = nftables.ChainPolicyAccept
	case "drop":
		p = nftables.ChainPolicyDrop
	default:
		return nil, fmt.Errorf("unknown policy: %q (valid: accept, drop)", s)
	}
	return &p, nil
}

func hookString(h nftables.ChainHook) string {
	switch h {
	case *nftables.ChainHookPrerouting:
		return "prerouting"
	case *nftables.ChainHookInput:
		return "input"
	case *nftables.ChainHookForward:
		return "forward"
	case *nftables.ChainHookOutput:
		return "output"
	case *nftables.ChainHookPostrouting:
		return "postrouting"
	case *nftables.ChainHookIngress:
		return "ingress"
	case *nftables.ChainHookEgress:
		return "egress"
	default:
		return strconv.Itoa(int(h))
	}
}

func policyString(p nftables.ChainPolicy) string {
	switch p {
	case nftables.ChainPolicyAccept:
		return "accept"
	case nftables.ChainPolicyDrop:
		return "drop"
	default:
		return "unknown"
	}
}

func parsePriority(s string) (*nftables.ChainPriority, error) {
	// Try named priorities first
	named := map[string]int32{
		"raw":          -300,
		"mangle":       -150,
		"dstnat":       -100,
		"filter":       0,
		"security":     50,
		"srcnat":       100,
		"conntrack":    -200,
		"out":          100,
	}

	lower := strings.ToLower(strings.TrimSpace(s))

	// Check for "name + offset" or "name - offset" format
	for name, base := range named {
		if strings.HasPrefix(lower, name) {
			rest := strings.TrimSpace(lower[len(name):])
			if rest == "" {
				prio := nftables.ChainPriority(base)
				return &prio, nil
			}
			if rest[0] == '+' || rest[0] == '-' {
				offset, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 32)
				if err != nil {
					return nil, fmt.Errorf("invalid priority offset: %s", rest)
				}
				val := int64(base) + offset
				if val > math.MaxInt32 || val < math.MinInt32 {
					return nil, fmt.Errorf("priority overflow: %d", val)
				}
				prio := nftables.ChainPriority(int32(val))
				return &prio, nil
			}
		}
	}

	// Try numeric
	val, err := strconv.ParseInt(lower, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid priority: %q", s)
	}
	prio := nftables.ChainPriority(int32(val))
	return &prio, nil
}
