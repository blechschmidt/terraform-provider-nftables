package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/sys/unix"
)

// --- Counter Resource ---

var (
	_ resource.Resource                = &CounterResource{}
	_ resource.ResourceWithImportState = &CounterResource{}
)

type CounterResource struct {
	data *NftablesProviderData
}

type CounterModel struct {
	Family  types.String `tfsdk:"family"`
	Table   types.String `tfsdk:"table"`
	Name    types.String `tfsdk:"name"`
	Packets types.Int64  `tfsdk:"packets"`
	Bytes   types.Int64  `tfsdk:"bytes"`
}

func NewCounterResource() resource.Resource {
	return &CounterResource{}
}

func (r *CounterResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_counter"
}

func (r *CounterResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a named nftables counter.",
		Attributes: map[string]schema.Attribute{
			"family": schema.StringAttribute{
				Required: true, Description: "Address family.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"table": schema.StringAttribute{
				Required: true, Description: "Table name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required: true, Description: "Counter name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"packets": schema.Int64Attribute{
				Computed: true, Description: "Packet count.",
			},
			"bytes": schema.Int64Attribute{
				Computed: true, Description: "Byte count.",
			},
		},
	}
}

func (r *CounterResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.data = req.ProviderData.(*NftablesProviderData)
}

func (r *CounterResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CounterModel
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

	r.data.Conn.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  plan.Name.ValueString(),
		Type:  nftables.ObjTypeCounter,
		Obj:   &expr.Counter{Bytes: 0, Packets: 0},
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to create counter", err.Error())
		return
	}

	plan.Packets = types.Int64Value(0)
	plan.Bytes = types.Int64Value(0)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CounterResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CounterModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	obj, err := r.data.Conn.GetObjReset(&nftables.NamedObj{
		Table: table,
		Name:  state.Name.ValueString(),
		Type:  nftables.ObjTypeCounter,
	})
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	if obj == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CounterResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CounterModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CounterResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CounterModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	r.data.Conn.DeleteObject(&nftables.NamedObj{
		Table: table,
		Name:  state.Name.ValueString(),
		Type:  nftables.ObjTypeCounter,
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to delete counter", err.Error())
	}
}

func (r *CounterResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importStatefulObject(ctx, req, resp)
}

// --- Quota Resource ---

var (
	_ resource.Resource                = &QuotaResource{}
	_ resource.ResourceWithImportState = &QuotaResource{}
)

type QuotaResource struct {
	data *NftablesProviderData
}

type QuotaModel struct {
	Family   types.String `tfsdk:"family"`
	Table    types.String `tfsdk:"table"`
	Name     types.String `tfsdk:"name"`
	Bytes    types.Int64  `tfsdk:"bytes"`
	Over     types.Bool   `tfsdk:"over"`
	Consumed types.Int64  `tfsdk:"consumed"`
}

func NewQuotaResource() resource.Resource {
	return &QuotaResource{}
}

func (r *QuotaResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_quota"
}

func (r *QuotaResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a named nftables quota.",
		Attributes: map[string]schema.Attribute{
			"family": schema.StringAttribute{
				Required: true, Description: "Address family.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"table": schema.StringAttribute{
				Required: true, Description: "Table name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required: true, Description: "Quota name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"bytes": schema.Int64Attribute{
				Required:    true,
				Description: "Quota threshold in bytes.",
			},
			"over": schema.BoolAttribute{
				Optional:    true,
				Description: "If true, match when quota is exceeded (over). Default: false (until).",
			},
			"consumed": schema.Int64Attribute{
				Computed:    true,
				Description: "Bytes consumed.",
			},
		},
	}
}

func (r *QuotaResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.data = req.ProviderData.(*NftablesProviderData)
}

func (r *QuotaResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan QuotaModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(plan.Family.ValueString())
	table := &nftables.Table{Family: family, Name: plan.Table.ValueString()}

	r.data.Conn.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  plan.Name.ValueString(),
		Type:  nftables.ObjTypeQuota,
		Obj: &expr.Quota{
			Bytes:    uint64(plan.Bytes.ValueInt64()),
			Over:     plan.Over.ValueBool(),
			Consumed: 0,
		},
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to create quota", err.Error())
		return
	}

	plan.Consumed = types.Int64Value(0)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *QuotaResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state QuotaModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	obj, err := r.data.Conn.GetObjReset(&nftables.NamedObj{
		Table: table,
		Name:  state.Name.ValueString(),
		Type:  nftables.ObjTypeQuota,
	})
	if err != nil || obj == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *QuotaResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan QuotaModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	family, _ := parseFamily(plan.Family.ValueString())
	table := &nftables.Table{Family: family, Name: plan.Table.ValueString()}

	r.data.Conn.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  plan.Name.ValueString(),
		Type:  nftables.ObjTypeQuota,
		Obj: &expr.Quota{
			Bytes:    uint64(plan.Bytes.ValueInt64()),
			Over:     plan.Over.ValueBool(),
			Consumed: 0,
		},
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to update quota", err.Error())
		return
	}

	plan.Consumed = types.Int64Value(0)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *QuotaResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state QuotaModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	r.data.Conn.DeleteObject(&nftables.NamedObj{
		Table: table,
		Name:  state.Name.ValueString(),
		Type:  nftables.ObjTypeQuota,
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to delete quota", err.Error())
	}
}

func (r *QuotaResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importStatefulObject(ctx, req, resp)
}

// --- Limit Resource ---

var (
	_ resource.Resource                = &LimitResource{}
	_ resource.ResourceWithImportState = &LimitResource{}
)

type LimitResource struct {
	data *NftablesProviderData
}

type LimitModel struct {
	Family types.String `tfsdk:"family"`
	Table  types.String `tfsdk:"table"`
	Name   types.String `tfsdk:"name"`
	Rate   types.Int64  `tfsdk:"rate"`
	Unit   types.String `tfsdk:"unit"`
	Burst  types.Int64  `tfsdk:"burst"`
	Type   types.String `tfsdk:"type"`
	Over   types.Bool   `tfsdk:"over"`
}

func NewLimitResource() resource.Resource {
	return &LimitResource{}
}

func (r *LimitResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_limit"
}

func (r *LimitResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a named nftables rate limit.",
		Attributes: map[string]schema.Attribute{
			"family": schema.StringAttribute{
				Required: true, Description: "Address family.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"table": schema.StringAttribute{
				Required: true, Description: "Table name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required: true, Description: "Limit name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"rate": schema.Int64Attribute{
				Required:    true,
				Description: "Rate value.",
			},
			"unit": schema.StringAttribute{
				Required:    true,
				Description: "Rate unit: second, minute, hour, day, week.",
			},
			"burst": schema.Int64Attribute{
				Optional:    true,
				Description: "Burst value.",
			},
			"type": schema.StringAttribute{
				Optional:    true,
				Description: "Limit type: packets or bytes. Default: packets.",
			},
			"over": schema.BoolAttribute{
				Optional:    true,
				Description: "If true, match when rate is exceeded.",
			},
		},
	}
}

func (r *LimitResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.data = req.ProviderData.(*NftablesProviderData)
}

func (r *LimitResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan LimitModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(plan.Family.ValueString())
	table := &nftables.Table{Family: family, Name: plan.Table.ValueString()}

	unit, err := parseLimitUnit(plan.Unit.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid unit", err.Error())
		return
	}

	limitType := expr.LimitTypePkts
	if !plan.Type.IsNull() && plan.Type.ValueString() == "bytes" {
		limitType = expr.LimitTypePktBytes
	}

	r.data.Conn.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  plan.Name.ValueString(),
		Type:  nftables.ObjTypeLimit,
		Obj: &expr.Limit{
			Type:  limitType,
			Rate:  uint64(plan.Rate.ValueInt64()),
			Unit:  unit,
			Burst: uint32(plan.Burst.ValueInt64()),
			Over:  plan.Over.ValueBool(),
		},
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to create limit", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *LimitResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state LimitModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	obj, err := r.data.Conn.GetObjReset(&nftables.NamedObj{
		Table: table,
		Name:  state.Name.ValueString(),
		Type:  nftables.ObjTypeLimit,
	})
	if err != nil || obj == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *LimitResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan LimitModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	family, _ := parseFamily(plan.Family.ValueString())
	table := &nftables.Table{Family: family, Name: plan.Table.ValueString()}
	unit, _ := parseLimitUnit(plan.Unit.ValueString())
	limitType := expr.LimitTypePkts
	if !plan.Type.IsNull() && plan.Type.ValueString() == "bytes" {
		limitType = expr.LimitTypePktBytes
	}

	r.data.Conn.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  plan.Name.ValueString(),
		Type:  nftables.ObjTypeLimit,
		Obj: &expr.Limit{
			Type:  limitType,
			Rate:  uint64(plan.Rate.ValueInt64()),
			Unit:  unit,
			Burst: uint32(plan.Burst.ValueInt64()),
			Over:  plan.Over.ValueBool(),
		},
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to update limit", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *LimitResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state LimitModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	r.data.Conn.DeleteObject(&nftables.NamedObj{
		Table: table,
		Name:  state.Name.ValueString(),
		Type:  nftables.ObjTypeLimit,
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to delete limit", err.Error())
	}
}

func (r *LimitResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importStatefulObject(ctx, req, resp)
}

// --- CT Helper Resource ---

var (
	_ resource.Resource                = &CtHelperResource{}
	_ resource.ResourceWithImportState = &CtHelperResource{}
)

type CtHelperResource struct {
	data *NftablesProviderData
}

type CtHelperModel struct {
	Family   types.String `tfsdk:"family"`
	Table    types.String `tfsdk:"table"`
	Name     types.String `tfsdk:"name"`
	Helper   types.String `tfsdk:"helper"`
	Protocol types.String `tfsdk:"protocol"`
	L3Proto  types.String `tfsdk:"l3proto"`
}

func NewCtHelperResource() resource.Resource {
	return &CtHelperResource{}
}

func (r *CtHelperResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ct_helper"
}

func (r *CtHelperResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an nftables connection tracking helper.",
		Attributes: map[string]schema.Attribute{
			"family": schema.StringAttribute{
				Required: true, Description: "Address family.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"table": schema.StringAttribute{
				Required: true, Description: "Table name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required: true, Description: "Helper object name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"helper": schema.StringAttribute{
				Required:    true,
				Description: "CT helper name (e.g., 'ftp', 'sip').",
			},
			"protocol": schema.StringAttribute{
				Required:    true,
				Description: "L4 protocol: tcp or udp.",
			},
			"l3proto": schema.StringAttribute{
				Optional:    true,
				Description: "L3 protocol: ip or ip6.",
			},
		},
	}
}

func (r *CtHelperResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.data = req.ProviderData.(*NftablesProviderData)
}

func (r *CtHelperResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CtHelperModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(plan.Family.ValueString())
	table := &nftables.Table{Family: family, Name: plan.Table.ValueString()}

	l4proto, err := parseProtocol(plan.Protocol.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid protocol", err.Error())
		return
	}

	l3proto := uint16(unix.NFPROTO_IPV4)
	if !plan.L3Proto.IsNull() && !plan.L3Proto.IsUnknown() {
		switch plan.L3Proto.ValueString() {
		case "ip6", "ipv6":
			l3proto = unix.NFPROTO_IPV6
		}
	}

	r.data.Conn.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  plan.Name.ValueString(),
		Type:  nftables.ObjTypeCtHelper,
		Obj: &expr.CtHelper{
			Name:    plan.Helper.ValueString(),
			L4Proto: l4proto,
			L3Proto: l3proto,
		},
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to create ct helper", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CtHelperResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CtHelperModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	obj, err := r.data.Conn.GetObjReset(&nftables.NamedObj{
		Table: table,
		Name:  state.Name.ValueString(),
		Type:  nftables.ObjTypeCtHelper,
	})
	if err != nil || obj == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CtHelperResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CtHelperModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	family, _ := parseFamily(plan.Family.ValueString())
	table := &nftables.Table{Family: family, Name: plan.Table.ValueString()}
	l4proto, _ := parseProtocol(plan.Protocol.ValueString())
	l3proto := uint16(unix.NFPROTO_IPV4)
	if !plan.L3Proto.IsNull() && plan.L3Proto.ValueString() == "ip6" {
		l3proto = unix.NFPROTO_IPV6
	}

	r.data.Conn.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  plan.Name.ValueString(),
		Type:  nftables.ObjTypeCtHelper,
		Obj: &expr.CtHelper{
			Name:    plan.Helper.ValueString(),
			L4Proto: l4proto,
			L3Proto: l3proto,
		},
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to update ct helper", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CtHelperResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CtHelperModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	r.data.Conn.DeleteObject(&nftables.NamedObj{
		Table: table,
		Name:  state.Name.ValueString(),
		Type:  nftables.ObjTypeCtHelper,
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to delete ct helper", err.Error())
	}
}

func (r *CtHelperResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importStatefulObject(ctx, req, resp)
}

// --- CT Timeout Resource ---

var (
	_ resource.Resource                = &CtTimeoutResource{}
	_ resource.ResourceWithImportState = &CtTimeoutResource{}
)

type CtTimeoutResource struct {
	data *NftablesProviderData
}

type CtTimeoutModel struct {
	Family   types.String `tfsdk:"family"`
	Table    types.String `tfsdk:"table"`
	Name     types.String `tfsdk:"name"`
	Protocol types.String `tfsdk:"protocol"`
	L3Proto  types.String `tfsdk:"l3proto"`
	Policy   types.Map    `tfsdk:"policy"`
}

func NewCtTimeoutResource() resource.Resource {
	return &CtTimeoutResource{}
}

func (r *CtTimeoutResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ct_timeout"
}

func (r *CtTimeoutResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an nftables connection tracking timeout policy.",
		Attributes: map[string]schema.Attribute{
			"family": schema.StringAttribute{
				Required: true, Description: "Address family.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"table": schema.StringAttribute{
				Required: true, Description: "Table name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required: true, Description: "Timeout policy name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"protocol": schema.StringAttribute{
				Required:    true,
				Description: "L4 protocol: tcp or udp.",
			},
			"l3proto": schema.StringAttribute{
				Optional:    true,
				Description: "L3 protocol: ip or ip6.",
			},
			"policy": schema.MapAttribute{
				Required:    true,
				Description: "Timeout policy map: state -> timeout in seconds (e.g., 'established' = '3600').",
				ElementType: types.Int64Type,
			},
		},
	}
}

func (r *CtTimeoutResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.data = req.ProviderData.(*NftablesProviderData)
}

func (r *CtTimeoutResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CtTimeoutModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(plan.Family.ValueString())
	table := &nftables.Table{Family: family, Name: plan.Table.ValueString()}

	l4proto, err := parseProtocol(plan.Protocol.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid protocol", err.Error())
		return
	}

	l3proto := uint16(unix.NFPROTO_IPV4)
	if !plan.L3Proto.IsNull() && !plan.L3Proto.IsUnknown() {
		switch plan.L3Proto.ValueString() {
		case "ip6", "ipv6":
			l3proto = unix.NFPROTO_IPV6
		}
	}

	var policyMap map[string]int64
	resp.Diagnostics.Append(plan.Policy.ElementsAs(ctx, &policyMap, false)...)

	policy := make(expr.CtStatePolicyTimeout)
	for state, timeout := range policyMap {
		stateID, err := parseCTStateID(state)
		if err != nil {
			resp.Diagnostics.AddError("Invalid CT state", err.Error())
			return
		}
		policy[stateID] = uint32(timeout)
	}

	r.data.Conn.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  plan.Name.ValueString(),
		Type:  nftables.ObjTypeCtTimeout,
		Obj: &expr.CtTimeout{
			L4Proto: l4proto,
			L3Proto: l3proto,
			Policy:  policy,
		},
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to create ct timeout", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CtTimeoutResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CtTimeoutModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	obj, err := r.data.Conn.GetObjReset(&nftables.NamedObj{
		Table: table,
		Name:  state.Name.ValueString(),
		Type:  nftables.ObjTypeCtTimeout,
	})
	if err != nil || obj == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CtTimeoutResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CtTimeoutModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CtTimeoutResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CtTimeoutModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	r.data.Conn.DeleteObject(&nftables.NamedObj{
		Table: table,
		Name:  state.Name.ValueString(),
		Type:  nftables.ObjTypeCtTimeout,
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to delete ct timeout", err.Error())
	}
}

func (r *CtTimeoutResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importStatefulObject(ctx, req, resp)
}

// --- CT Expectation Resource ---

var (
	_ resource.Resource                = &CtExpectationResource{}
	_ resource.ResourceWithImportState = &CtExpectationResource{}
)

type CtExpectationResource struct {
	data *NftablesProviderData
}

type CtExpectationModel struct {
	Family   types.String `tfsdk:"family"`
	Table    types.String `tfsdk:"table"`
	Name     types.String `tfsdk:"name"`
	Protocol types.String `tfsdk:"protocol"`
	L3Proto  types.String `tfsdk:"l3proto"`
	DPort    types.Int64  `tfsdk:"dport"`
	Timeout  types.Int64  `tfsdk:"timeout"`
	Size     types.Int64  `tfsdk:"size"`
}

func NewCtExpectationResource() resource.Resource {
	return &CtExpectationResource{}
}

func (r *CtExpectationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ct_expectation"
}

func (r *CtExpectationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an nftables connection tracking expectation.",
		Attributes: map[string]schema.Attribute{
			"family": schema.StringAttribute{
				Required: true, Description: "Address family.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"table": schema.StringAttribute{
				Required: true, Description: "Table name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required: true, Description: "Expectation name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"protocol": schema.StringAttribute{
				Required:    true,
				Description: "L4 protocol: tcp or udp.",
			},
			"l3proto": schema.StringAttribute{
				Optional:    true,
				Description: "L3 protocol: ip or ip6.",
			},
			"dport": schema.Int64Attribute{
				Required:    true,
				Description: "Expected destination port.",
			},
			"timeout": schema.Int64Attribute{
				Required:    true,
				Description: "Expectation timeout in milliseconds.",
			},
			"size": schema.Int64Attribute{
				Required:    true,
				Description: "Maximum number of expected connections.",
			},
		},
	}
}

func (r *CtExpectationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.data = req.ProviderData.(*NftablesProviderData)
}

func (r *CtExpectationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CtExpectationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(plan.Family.ValueString())
	table := &nftables.Table{Family: family, Name: plan.Table.ValueString()}

	l4proto, _ := parseProtocol(plan.Protocol.ValueString())
	l3proto := uint16(unix.NFPROTO_IPV4)
	if !plan.L3Proto.IsNull() && plan.L3Proto.ValueString() == "ip6" {
		l3proto = unix.NFPROTO_IPV6
	}

	r.data.Conn.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  plan.Name.ValueString(),
		Type:  nftables.ObjTypeCtExpect,
		Obj: &expr.CtExpect{
			L4Proto: l4proto,
			L3Proto: l3proto,
			DPort:   uint16(plan.DPort.ValueInt64()),
			Timeout: uint32(plan.Timeout.ValueInt64()),
			Size:    uint8(plan.Size.ValueInt64()),
		},
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to create ct expectation", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CtExpectationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CtExpectationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	obj, err := r.data.Conn.GetObjReset(&nftables.NamedObj{
		Table: table,
		Name:  state.Name.ValueString(),
		Type:  nftables.ObjTypeCtExpect,
	})
	if err != nil || obj == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CtExpectationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CtExpectationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CtExpectationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CtExpectationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	r.data.Conn.DeleteObject(&nftables.NamedObj{
		Table: table,
		Name:  state.Name.ValueString(),
		Type:  nftables.ObjTypeCtExpect,
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to delete ct expectation", err.Error())
	}
}

func (r *CtExpectationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importStatefulObject(ctx, req, resp)
}

// --- Synproxy Resource ---

var (
	_ resource.Resource                = &SynproxyResource{}
	_ resource.ResourceWithImportState = &SynproxyResource{}
)

type SynproxyResource struct {
	data *NftablesProviderData
}

type SynproxyModel struct {
	Family    types.String `tfsdk:"family"`
	Table     types.String `tfsdk:"table"`
	Name      types.String `tfsdk:"name"`
	MSS       types.Int64  `tfsdk:"mss"`
	WScale    types.Int64  `tfsdk:"wscale"`
	Timestamp types.Bool   `tfsdk:"timestamp"`
	SackPerm  types.Bool   `tfsdk:"sack_perm"`
}

func NewSynproxyResource() resource.Resource {
	return &SynproxyResource{}
}

func (r *SynproxyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_synproxy"
}

func (r *SynproxyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an nftables SYN proxy object.",
		Attributes: map[string]schema.Attribute{
			"family": schema.StringAttribute{
				Required: true, Description: "Address family.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"table": schema.StringAttribute{
				Required: true, Description: "Table name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required: true, Description: "Synproxy name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"mss": schema.Int64Attribute{
				Required:    true,
				Description: "Maximum Segment Size.",
			},
			"wscale": schema.Int64Attribute{
				Required:    true,
				Description: "Window scale factor.",
			},
			"timestamp": schema.BoolAttribute{
				Optional:    true,
				Description: "Enable TCP timestamp option.",
			},
			"sack_perm": schema.BoolAttribute{
				Optional:    true,
				Description: "Enable TCP SACK permitted option.",
			},
		},
	}
}

func (r *SynproxyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.data = req.ProviderData.(*NftablesProviderData)
}

func (r *SynproxyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan SynproxyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(plan.Family.ValueString())
	table := &nftables.Table{Family: family, Name: plan.Table.ValueString()}

	r.data.Conn.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  plan.Name.ValueString(),
		Type:  nftables.ObjTypeSynProxy,
		Obj: &expr.SynProxy{
			Mss:       uint16(plan.MSS.ValueInt64()),
			Wscale:    uint8(plan.WScale.ValueInt64()),
			Timestamp: plan.Timestamp.ValueBool(),
			SackPerm:  plan.SackPerm.ValueBool(),
		},
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to create synproxy", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SynproxyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state SynproxyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	obj, err := r.data.Conn.GetObjReset(&nftables.NamedObj{
		Table: table,
		Name:  state.Name.ValueString(),
		Type:  nftables.ObjTypeSynProxy,
	})
	if err != nil || obj == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *SynproxyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan SynproxyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	family, _ := parseFamily(plan.Family.ValueString())
	table := &nftables.Table{Family: family, Name: plan.Table.ValueString()}

	r.data.Conn.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  plan.Name.ValueString(),
		Type:  nftables.ObjTypeSynProxy,
		Obj: &expr.SynProxy{
			Mss:       uint16(plan.MSS.ValueInt64()),
			Wscale:    uint8(plan.WScale.ValueInt64()),
			Timestamp: plan.Timestamp.ValueBool(),
			SackPerm:  plan.SackPerm.ValueBool(),
		},
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to update synproxy", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SynproxyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state SynproxyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	r.data.Conn.DeleteObject(&nftables.NamedObj{
		Table: table,
		Name:  state.Name.ValueString(),
		Type:  nftables.ObjTypeSynProxy,
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to delete synproxy", err.Error())
	}
}

func (r *SynproxyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importStatefulObject(ctx, req, resp)
}

// --- Shared helpers ---

func parseCTStateID(s string) (uint16, error) {
	// TCP states
	tcpStates := map[string]uint16{
		"close":        1,
		"listen":       2,
		"syn_sent":     3,
		"syn_recv":     4,
		"established":  5,
		"fin_wait":     6,
		"close_wait":   7,
		"last_ack":     8,
		"time_wait":    9,
		"syn_sent2":    10,
	}
	// UDP states
	udpStates := map[string]uint16{
		"unreplied": 1,
		"replied":   2,
	}

	if v, ok := tcpStates[strings.ToLower(s)]; ok {
		return v, nil
	}
	if v, ok := udpStates[strings.ToLower(s)]; ok {
		return v, nil
	}

	// Try numeric
	val, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("unknown CT state: %q", s)
	}
	return uint16(val), nil
}

func importStatefulObject(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, "|", 3)
	if len(parts) != 3 {
		resp.Diagnostics.AddError("Invalid import ID", fmt.Sprintf("Expected format: family|table|name, got: %s", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("family"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("table"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[2])...)
}
