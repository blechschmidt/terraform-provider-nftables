package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &MapResource{}
	_ resource.ResourceWithImportState = &MapResource{}
)

type MapResource struct {
	data *NftablesProviderData
}

type MapModel struct {
	Family   types.String `tfsdk:"family"`
	Table    types.String `tfsdk:"table"`
	Name     types.String `tfsdk:"name"`
	KeyType  types.String `tfsdk:"key_type"`
	DataType types.String `tfsdk:"data_type"`
	Flags    types.List   `tfsdk:"flags"`
	Comment  types.String `tfsdk:"comment"`
	Elements types.Map    `tfsdk:"elements"`
}

func NewMapResource() resource.Resource {
	return &MapResource{}
}

func (r *MapResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_map"
}

func (r *MapResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an nftables named map (including verdict maps).",
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
				Description: "Map name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_type": schema.StringAttribute{
				Required:    true,
				Description: "Key data type: ipv4_addr, ipv6_addr, inet_service, etc. Use '.' for concatenation.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"data_type": schema.StringAttribute{
				Required:    true,
				Description: "Value data type. Use 'verdict' for verdict maps.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"flags": schema.ListAttribute{
				Optional:    true,
				Description: "Map flags: constant, interval, timeout.",
				ElementType: types.StringType,
			},
			"comment": schema.StringAttribute{
				Optional:    true,
				Description: "Map comment.",
			},
			"elements": schema.MapAttribute{
				Optional:    true,
				Description: "Map elements as key->value pairs. For verdict maps, values are 'accept', 'drop', 'jump <chain>', 'goto <chain>'.",
				ElementType: types.StringType,
			},
		},
	}
}

func (r *MapResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *MapResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan MapModel
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

	keyType, err := parseSetDataType(plan.KeyType.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid key type", err.Error())
		return
	}

	dataType, err := parseSetDataType(plan.DataType.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid data type", err.Error())
		return
	}

	set := &nftables.Set{
		Table:    table,
		Name:     plan.Name.ValueString(),
		IsMap:    true,
		KeyType:  keyType,
		DataType: dataType,
	}

	if strings.Contains(plan.KeyType.ValueString(), ".") {
		set.Concatenation = true
	}

	if !plan.Flags.IsNull() && !plan.Flags.IsUnknown() {
		var flags []string
		resp.Diagnostics.Append(plan.Flags.ElementsAs(ctx, &flags, false)...)
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

	if !plan.Comment.IsNull() && !plan.Comment.IsUnknown() {
		set.Comment = plan.Comment.ValueString()
	}

	var elements []nftables.SetElement
	if !plan.Elements.IsNull() && !plan.Elements.IsUnknown() {
		var elems map[string]string
		resp.Diagnostics.Append(plan.Elements.ElementsAs(ctx, &elems, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for k, v := range elems {
			elem, err := parseMapElement(k, v, keyType, dataType)
			if err != nil {
				resp.Diagnostics.AddError("Invalid map element", err.Error())
				return
			}
			elements = append(elements, elem)
		}
	}

	if err := r.data.Conn.AddSet(set, elements); err != nil {
		resp.Diagnostics.AddError("Failed to create map", err.Error())
		return
	}

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to flush map", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *MapResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state MapModel
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

	found := false
	for _, s := range sets {
		if s.Name == state.Name.ValueString() && s.IsMap {
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

func (r *MapResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan MapModel
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
	keyType, _ := parseSetDataType(plan.KeyType.ValueString())
	dataType, _ := parseSetDataType(plan.DataType.ValueString())

	set := &nftables.Set{
		Table:    table,
		Name:     plan.Name.ValueString(),
		IsMap:    true,
		KeyType:  keyType,
		DataType: dataType,
	}

	r.data.Conn.FlushSet(set)
	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to flush map elements", err.Error())
		return
	}

	if !plan.Elements.IsNull() && !plan.Elements.IsUnknown() {
		var elems map[string]string
		resp.Diagnostics.Append(plan.Elements.ElementsAs(ctx, &elems, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		var elements []nftables.SetElement
		for k, v := range elems {
			elem, err := parseMapElement(k, v, keyType, dataType)
			if err != nil {
				resp.Diagnostics.AddError("Invalid map element", err.Error())
				return
			}
			elements = append(elements, elem)
		}

		if err := r.data.Conn.SetAddElements(set, elements); err != nil {
			resp.Diagnostics.AddError("Failed to add map elements", err.Error())
			return
		}
	}

	if err := r.data.Conn.Flush(); err != nil {
		resp.Diagnostics.AddError("Failed to flush", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *MapResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state MapModel
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
		resp.Diagnostics.AddError("Failed to delete map", err.Error())
		return
	}
}

func (r *MapResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, "|", 3)
	if len(parts) != 3 {
		resp.Diagnostics.AddError("Invalid import ID", "Expected format: family|table|map_name")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("family"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("table"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[2])...)
}

func parseMapElement(key, value string, keyType, dataType nftables.SetDatatype) (nftables.SetElement, error) {
	keyBytes, err := encodeSetKey(key, keyType)
	if err != nil {
		return nftables.SetElement{}, fmt.Errorf("invalid key %q: %w", key, err)
	}

	// Verdict map
	if dataType == nftables.TypeVerdict {
		verdict, err := parseVerdictValue(value)
		if err != nil {
			return nftables.SetElement{}, err
		}
		return nftables.SetElement{
			Key:         keyBytes,
			VerdictData: verdict,
		}, nil
	}

	valBytes, err := encodeSetKey(value, dataType)
	if err != nil {
		return nftables.SetElement{}, fmt.Errorf("invalid value %q: %w", value, err)
	}

	return nftables.SetElement{
		Key: keyBytes,
		Val: valBytes,
	}, nil
}

func parseVerdictValue(s string) (*expr.Verdict, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "accept":
		return &expr.Verdict{Kind: expr.VerdictAccept}, nil
	case s == "drop":
		return &expr.Verdict{Kind: expr.VerdictDrop}, nil
	case s == "return":
		return &expr.Verdict{Kind: expr.VerdictReturn}, nil
	case s == "continue":
		return &expr.Verdict{Kind: expr.VerdictContinue}, nil
	case strings.HasPrefix(s, "jump "):
		return &expr.Verdict{Kind: expr.VerdictJump, Chain: strings.TrimPrefix(s, "jump ")}, nil
	case strings.HasPrefix(s, "goto "):
		return &expr.Verdict{Kind: expr.VerdictGoto, Chain: strings.TrimPrefix(s, "goto ")}, nil
	default:
		return nil, fmt.Errorf("unknown verdict: %q", s)
	}
}
