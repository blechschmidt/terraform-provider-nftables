package provider

import (
	"context"
	"fmt"
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
	_ resource.Resource                = &TableResource{}
	_ resource.ResourceWithImportState = &TableResource{}
)

type TableResource struct {
	data *NftablesProviderData
}

type TableModel struct {
	Family  types.String `tfsdk:"family"`
	Name    types.String `tfsdk:"name"`
	Dormant types.Bool   `tfsdk:"dormant"`
}

func NewTableResource() resource.Resource {
	return &TableResource{}
}

func (r *TableResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_table"
}

func (r *TableResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an nftables table.",
		Attributes: map[string]schema.Attribute{
			"family": schema.StringAttribute{
				Required:    true,
				Description: "Address family: ip, ip6, inet, arp, bridge, netdev.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Table name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"dormant": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "If true, the table is dormant (inactive).",
			},
		},
	}
}

func (r *TableResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *TableResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan TableModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, err := parseFamily(plan.Family.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid family", err.Error())
		return
	}

	var flags uint32
	if plan.Dormant.ValueBool() {
		flags = 0x1 // NFT_TABLE_F_DORMANT
	}

	r.data.Conn.AddTable(&nftables.Table{
		Family: family,
		Name:   plan.Name.ValueString(),
		Flags:  flags,
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to create table", err.Error())
		return
	}

	if plan.Dormant.IsNull() || plan.Dormant.IsUnknown() {
		plan.Dormant = types.BoolValue(false)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TableResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state TableModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, err := parseFamily(state.Family.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid family", err.Error())
		return
	}

	tables, err := r.data.Conn.ListTablesOfFamily(family)
	if err != nil {
		resp.Diagnostics.AddError("Failed to list tables", err.Error())
		return
	}

	var found *nftables.Table
	for _, t := range tables {
		if t.Name == state.Name.ValueString() {
			found = t
			break
		}
	}

	if found == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	// Note: ListTablesOfFamily doesn't return flags reliably in all kernel/library
	// versions, so we preserve the dormant state from Terraform state.
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *TableResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan TableModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, err := parseFamily(plan.Family.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid family", err.Error())
		return
	}

	var flags uint32
	if plan.Dormant.ValueBool() {
		flags = 0x1 // NFT_TABLE_F_DORMANT
	}

	r.data.Conn.AddTable(&nftables.Table{
		Family: family,
		Name:   plan.Name.ValueString(),
		Flags:  flags,
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to update table", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TableResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state TableModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	family, err := parseFamily(state.Family.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid family", err.Error())
		return
	}

	r.data.Conn.DelTable(&nftables.Table{
		Family: family,
		Name:   state.Name.ValueString(),
	})

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to delete table", err.Error())
		return
	}
}

func (r *TableResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, "|", 2)
	if len(parts) != 2 {
		resp.Diagnostics.AddError("Invalid import ID", "Expected format: family|name")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("family"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[1])...)
}

func parseFamily(s string) (nftables.TableFamily, error) {
	switch strings.ToLower(s) {
	case "ip", "ipv4":
		return nftables.TableFamilyIPv4, nil
	case "ip6", "ipv6":
		return nftables.TableFamilyIPv6, nil
	case "inet":
		return nftables.TableFamilyINet, nil
	case "arp":
		return nftables.TableFamilyARP, nil
	case "bridge":
		return nftables.TableFamilyBridge, nil
	case "netdev":
		return nftables.TableFamilyNetdev, nil
	default:
		return 0, fmt.Errorf("unknown address family: %q (valid: ip, ip6, inet, arp, bridge, netdev)", s)
	}
}

func familyString(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyBridge:
		return "bridge"
	case nftables.TableFamilyNetdev:
		return "netdev"
	default:
		return "unknown"
	}
}
