package provider

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &SetResource{}
	_ resource.ResourceWithImportState = &SetResource{}
)

type SetResource struct {
	data *NftablesProviderData
}

type SetModel struct {
	Family    types.String `tfsdk:"family"`
	Table     types.String `tfsdk:"table"`
	Name      types.String `tfsdk:"name"`
	Type      types.String `tfsdk:"type"`
	Flags     types.List   `tfsdk:"flags"`
	Timeout   types.String `tfsdk:"timeout"`
	Size      types.Int64  `tfsdk:"size"`
	Policy    types.String `tfsdk:"policy"`
	AutoMerge types.Bool   `tfsdk:"auto_merge"`
	Counter   types.Bool   `tfsdk:"counter"`
	Comment   types.String `tfsdk:"comment"`
	Elements  types.List   `tfsdk:"elements"`
}

func NewSetResource() resource.Resource {
	return &SetResource{}
}

func (r *SetResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_set"
}

func (r *SetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an nftables named set.",
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
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Set name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Required:    true,
				Description: "Set data type: ipv4_addr, ipv6_addr, ether_addr, inet_proto, inet_service, mark, ifname. Use '.' for concatenation.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"flags": schema.ListAttribute{
				Optional:    true,
				Description: "Set flags: constant, interval, timeout.",
				ElementType: types.StringType,
			},
			"timeout": schema.StringAttribute{
				Optional:    true,
				Description: "Default element timeout (e.g., '1h', '30m', '60s').",
			},
			"size": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of elements.",
			},
			"policy": schema.StringAttribute{
				Optional:    true,
				Description: "Set policy: performance or memory.",
			},
			"auto_merge": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Automatically merge overlapping intervals.",
			},
			"counter": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Enable per-element counters.",
			},
			"comment": schema.StringAttribute{
				Optional:    true,
				Description: "Set comment.",
			},
			"elements": schema.ListAttribute{
				Optional:    true,
				Description: "Set elements. For interval sets, use 'start-end' format.",
				ElementType: types.StringType,
			},
		},
	}
}

func (r *SetResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *SetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan SetModel
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

	keyType, err := parseSetDataType(plan.Type.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid set type", err.Error())
		return
	}

	set := &nftables.Set{
		Table:   table,
		Name:    plan.Name.ValueString(),
		KeyType: keyType,
	}

	// Parse flags
	if !plan.Flags.IsNull() && !plan.Flags.IsUnknown() {
		var flags []string
		resp.Diagnostics.Append(plan.Flags.ElementsAs(ctx, &flags, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, f := range flags {
			switch f {
			case "constant":
				set.Constant = true
			case "interval":
				set.Interval = true
			case "timeout":
				set.HasTimeout = true
			}
		}
	}

	if !plan.Timeout.IsNull() && !plan.Timeout.IsUnknown() {
		d, err := time.ParseDuration(plan.Timeout.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid timeout", err.Error())
			return
		}
		set.Timeout = d
		set.HasTimeout = true
	}

	if !plan.Size.IsNull() && !plan.Size.IsUnknown() {
		set.Size = uint32(plan.Size.ValueInt64())
	}

	if plan.AutoMerge.ValueBool() {
		set.AutoMerge = true
	}

	if plan.Counter.ValueBool() {
		set.Counter = true
	}

	if !plan.Comment.IsNull() && !plan.Comment.IsUnknown() {
		set.Comment = plan.Comment.ValueString()
	}

	if strings.Contains(plan.Type.ValueString(), ".") {
		set.Concatenation = true
	}

	// Parse elements
	var elements []nftables.SetElement
	if !plan.Elements.IsNull() && !plan.Elements.IsUnknown() {
		var elems []string
		resp.Diagnostics.Append(plan.Elements.ElementsAs(ctx, &elems, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, e := range elems {
			elem, err := parseSetElement(e, keyType, set.Interval)
			if err != nil {
				resp.Diagnostics.AddError("Invalid element", err.Error())
				return
			}
			elements = append(elements, elem...)
		}
	}

	if err := r.data.Conn.AddSet(set, elements); err != nil {
		resp.Diagnostics.AddError("Failed to create set", err.Error())
		return
	}

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to flush set", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state SetModel
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

	sets, err := r.data.Conn.GetSets(table)
	if err != nil {
		resp.Diagnostics.AddError("Failed to list sets", err.Error())
		return
	}

	var found *nftables.Set
	for _, s := range sets {
		if s.Name == state.Name.ValueString() {
			found = s
			break
		}
	}

	if found == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *SetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan SetModel
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
	keyType, _ := parseSetDataType(plan.Type.ValueString())

	// Flush existing elements
	r.data.Conn.FlushSet(&nftables.Set{
		Table:   table,
		Name:    plan.Name.ValueString(),
		KeyType: keyType,
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to flush set elements", err.Error())
		return
	}

	// Add new elements
	if !plan.Elements.IsNull() && !plan.Elements.IsUnknown() {
		var elems []string
		resp.Diagnostics.Append(plan.Elements.ElementsAs(ctx, &elems, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		set := &nftables.Set{
			Table:   table,
			Name:    plan.Name.ValueString(),
			KeyType: keyType,
		}

		var elements []nftables.SetElement
		isInterval := false
		if !plan.Flags.IsNull() {
			var flags []string
			resp.Diagnostics.Append(plan.Flags.ElementsAs(ctx, &flags, false)...)
			for _, f := range flags {
				if f == "interval" {
					isInterval = true
				}
			}
		}

		for _, e := range elems {
			elem, err := parseSetElement(e, keyType, isInterval)
			if err != nil {
				resp.Diagnostics.AddError("Invalid element", err.Error())
				return
			}
			elements = append(elements, elem...)
		}

		if err := r.data.Conn.SetAddElements(set, elements); err != nil {
			resp.Diagnostics.AddError("Failed to add elements", err.Error())
			return
		}
	}

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to flush", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state SetModel
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

	r.data.Conn.DelSet(&nftables.Set{
		Table: table,
		Name:  state.Name.ValueString(),
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to delete set", err.Error())
		return
	}
}

func (r *SetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, "|", 3)
	if len(parts) != 3 {
		resp.Diagnostics.AddError("Invalid import ID", "Expected format: family|table|set_name")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("family"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("table"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[2])...)
}

func parseSetDataType(s string) (nftables.SetDatatype, error) {
	// Handle concatenated types
	if strings.Contains(s, ".") {
		parts := strings.Split(s, ".")
		var types []nftables.SetDatatype
		for _, p := range parts {
			t, err := parseSingleSetDataType(strings.TrimSpace(p))
			if err != nil {
				return nftables.SetDatatype{}, err
			}
			types = append(types, t)
		}
		result, err := nftables.ConcatSetType(types...)
		return result, err
	}
	return parseSingleSetDataType(s)
}

func parseSingleSetDataType(s string) (nftables.SetDatatype, error) {
	switch strings.ToLower(s) {
	case "ipv4_addr":
		return nftables.TypeIPAddr, nil
	case "ipv6_addr":
		return nftables.TypeIP6Addr, nil
	case "ether_addr":
		return nftables.TypeLLAddr, nil
	case "inet_proto":
		return nftables.TypeInetProto, nil
	case "inet_service":
		return nftables.TypeInetService, nil
	case "mark":
		return nftables.TypeMark, nil
	case "ifname":
		return nftables.TypeIFName, nil
	case "ct_state":
		return nftables.TypeCTState, nil
	case "verdict":
		return nftables.TypeVerdict, nil
	default:
		return nftables.SetDatatype{}, fmt.Errorf("unknown set data type: %q", s)
	}
}

func parseSetElement(s string, keyType nftables.SetDatatype, isInterval bool) ([]nftables.SetElement, error) {
	// Handle interval ranges for CIDR notation
	if strings.Contains(s, "/") && isInterval {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %s", s)
		}
		// For interval sets with CIDR, add start and end
		start := ipNet.IP
		end := make(net.IP, len(start))
		for i := range start {
			end[i] = start[i] | ^ipNet.Mask[i]
		}
		// Increment end by one for exclusive upper bound
		endExcl := incrementIP(end)
		return []nftables.SetElement{
			{Key: start},
			{Key: endExcl, IntervalEnd: true},
		}, nil
	}

	// Handle range notation: "start-end"
	if strings.Contains(s, "-") && isInterval {
		parts := strings.SplitN(s, "-", 2)
		startKey, err := encodeSetKey(strings.TrimSpace(parts[0]), keyType)
		if err != nil {
			return nil, err
		}
		endKey, err := encodeSetKey(strings.TrimSpace(parts[1]), keyType)
		if err != nil {
			return nil, err
		}
		// Increment for exclusive end
		endExclKey := incrementBytes(endKey)
		return []nftables.SetElement{
			{Key: startKey},
			{Key: endExclKey, IntervalEnd: true},
		}, nil
	}

	key, err := encodeSetKey(s, keyType)
	if err != nil {
		return nil, err
	}

	if isInterval {
		endKey := incrementBytes(key)
		return []nftables.SetElement{
			{Key: key},
			{Key: endKey, IntervalEnd: true},
		}, nil
	}

	return []nftables.SetElement{{Key: key}}, nil
}

func encodeSetKey(s string, keyType nftables.SetDatatype) ([]byte, error) {
	switch keyType {
	case nftables.TypeIPAddr:
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv4 address: %s", s)
		}
		return ip.To4(), nil
	case nftables.TypeIP6Addr:
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %s", s)
		}
		return ip.To16(), nil
	case nftables.TypeLLAddr:
		mac, err := net.ParseMAC(s)
		if err != nil {
			return nil, fmt.Errorf("invalid MAC: %s", s)
		}
		// nftables requires 8-byte aligned LL addresses
		b := make([]byte, 8)
		copy(b, mac)
		return b, nil
	case nftables.TypeInetService:
		port, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", s)
		}
		return binaryutil.BigEndian.PutUint16(uint16(port)), nil
	case nftables.TypeInetProto:
		proto, err := parseProtocol(s)
		if err != nil {
			return nil, err
		}
		return []byte{proto}, nil
	case nftables.TypeMark:
		val, err := strconv.ParseUint(s, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid mark: %s", s)
		}
		return binaryutil.NativeEndian.PutUint32(uint32(val)), nil
	case nftables.TypeIFName:
		return ifnameBytes(s), nil
	default:
		// Try as raw bytes
		val, err := strconv.ParseUint(s, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("cannot encode %q for type %v", s, keyType)
		}
		return binaryutil.BigEndian.PutUint32(uint32(val)), nil
	}
}

func incrementIP(ip net.IP) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)
	for i := len(result) - 1; i >= 0; i-- {
		result[i]++
		if result[i] != 0 {
			break
		}
	}
	return result
}

func incrementBytes(b []byte) []byte {
	result := make([]byte, len(b))
	copy(result, b)
	for i := len(result) - 1; i >= 0; i-- {
		result[i]++
		if result[i] != 0 {
			break
		}
	}
	return result
}
