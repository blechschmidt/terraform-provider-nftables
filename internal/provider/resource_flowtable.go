package provider

import (
	"context"
	"strings"

	"github.com/google/nftables"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &FlowtableResource{}
	_ resource.ResourceWithImportState = &FlowtableResource{}
)

type FlowtableResource struct {
	data *NftablesProviderData
}

type FlowtableModel struct {
	Family   types.String `tfsdk:"family"`
	Table    types.String `tfsdk:"table"`
	Name     types.String `tfsdk:"name"`
	Hook     types.String `tfsdk:"hook"`
	Priority types.Int32  `tfsdk:"priority"`
	Devices  types.List   `tfsdk:"devices"`
}

func NewFlowtableResource() resource.Resource {
	return &FlowtableResource{}
}

func (r *FlowtableResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_flowtable"
}

func (r *FlowtableResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an nftables flowtable for conntrack-based fastpath forwarding.",
		Attributes: map[string]schema.Attribute{
			"family": schema.StringAttribute{
				Required:    true,
				Description: "Address family: ip, ip6, or inet.",
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
				Description: "Flowtable name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"hook": schema.StringAttribute{
				Required:    true,
				Description: "Hook: ingress.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"priority": schema.Int32Attribute{
				Required:    true,
				Description: "Flowtable priority.",
				PlanModifiers: []planmodifier.Int32{
					int32planmodifier.RequiresReplace(),
				},
			},
			"devices": schema.ListAttribute{
				Required:    true,
				Description: "List of devices for the flowtable.",
				ElementType: types.StringType,
			},
		},
	}
}

func (r *FlowtableResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *FlowtableResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan FlowtableModel
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

	var devices []string
	resp.Diagnostics.Append(plan.Devices.ElementsAs(ctx, &devices, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	prio := nftables.FlowtablePriority(plan.Priority.ValueInt32())

	r.data.Conn.AddFlowtable(&nftables.Flowtable{
		Table:    table,
		Name:     plan.Name.ValueString(),
		Hooknum:  nftables.FlowtableHookIngress,
		Priority: nftables.FlowtablePriorityRef(prio),
		Devices:  devices,
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to create flowtable", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *FlowtableResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state FlowtableModel
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

	fts, err := r.data.Conn.ListFlowtables(table)
	if err != nil {
		resp.Diagnostics.AddError("Failed to list flowtables", err.Error())
		return
	}

	found := false
	for _, ft := range fts {
		if ft.Name == state.Name.ValueString() {
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

func (r *FlowtableResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan FlowtableModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Flowtable devices can be updated by re-adding
	family, _ := parseFamily(plan.Family.ValueString())
	table := &nftables.Table{Family: family, Name: plan.Table.ValueString()}

	var devices []string
	resp.Diagnostics.Append(plan.Devices.ElementsAs(ctx, &devices, false)...)

	prio := nftables.FlowtablePriority(plan.Priority.ValueInt32())

	r.data.Conn.AddFlowtable(&nftables.Flowtable{
		Table:    table,
		Name:     plan.Name.ValueString(),
		Hooknum:  nftables.FlowtableHookIngress,
		Priority: nftables.FlowtablePriorityRef(prio),
		Devices:  devices,
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to update flowtable", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *FlowtableResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state FlowtableModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, _ := parseFamily(state.Family.ValueString())
	table := &nftables.Table{Family: family, Name: state.Table.ValueString()}

	r.data.Conn.DelFlowtable(&nftables.Flowtable{
		Table: table,
		Name:  state.Name.ValueString(),
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to delete flowtable", err.Error())
		return
	}
}

func (r *FlowtableResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, "|", 3)
	if len(parts) != 3 {
		resp.Diagnostics.AddError("Invalid import ID", "Expected format: family|table|flowtable_name")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("family"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("table"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[2])...)
}
