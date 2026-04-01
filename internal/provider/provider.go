package provider

import (
	"context"
	"fmt"
	"os"
	"github.com/blechschmidt/terraform-provider-nftables/internal/provfunc"
	"github.com/google/nftables"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ provider.Provider              = &NftablesProvider{}
	_ provider.ProviderWithFunctions = &NftablesProvider{}
)

type NftablesProvider struct {
	version string
}

type NftablesProviderModel struct {
	Namespace types.String `tfsdk:"namespace"`
}

type NftablesProviderData struct {
	Conn      *nftables.Conn
	Namespace string
	nsFile    *os.File // kept open for namespace fd lifetime
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &NftablesProvider{
			version: version,
		}
	}
}

func (p *NftablesProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "nftables"
	resp.Version = p.version
}

func (p *NftablesProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Terraform provider for managing nftables firewall rules via netlink.",
		Attributes: map[string]schema.Attribute{
			"namespace": schema.StringAttribute{
				Optional:    true,
				Description: "Network namespace to operate in. If not set, uses the default namespace.",
			},
		},
	}
}

func (p *NftablesProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config NftablesProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var opts []nftables.ConnOption
	ns := ""

	if !config.Namespace.IsNull() && !config.Namespace.IsUnknown() {
		ns = config.Namespace.ValueString()
		nsPath := fmt.Sprintf("/var/run/netns/%s", ns)
		fd, err := os.Open(nsPath)
		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to open network namespace",
				fmt.Sprintf("Could not open namespace %q: %s", ns, err),
			)
			return
		}
		opts = append(opts, nftables.WithNetNSFd(int(fd.Fd())))

		data := &NftablesProviderData{
			Namespace: ns,
			nsFile:    fd, // prevent GC from closing the fd
		}

		conn, err := nftables.New(opts...)
		if err != nil {
			fd.Close()
			resp.Diagnostics.AddError(
				"Failed to create nftables connection",
				fmt.Sprintf("Could not create netlink connection: %s", err),
			)
			return
		}

		data.Conn = conn
		resp.DataSourceData = data
		resp.ResourceData = data
		return
	}

	conn, err := nftables.New(opts...)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to create nftables connection",
			fmt.Sprintf("Could not create netlink connection: %s", err),
		)
		return
	}

	data := &NftablesProviderData{
		Conn:      conn,
		Namespace: ns,
	}

	resp.DataSourceData = data
	resp.ResourceData = data
}

func (p *NftablesProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewTableResource,
		NewChainResource,
		NewRuleResource,
		NewSetResource,
		NewMapResource,
		NewFlowtableResource,
		NewCounterResource,
		NewQuotaResource,
		NewLimitResource,
		NewCtHelperResource,
		NewCtTimeoutResource,
		NewCtExpectationResource,
		NewSynproxyResource,
		// SecmarkResource requires SELinux, omitted from default build
	}
}

func (p *NftablesProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func (p *NftablesProvider) Functions(_ context.Context) []func() function.Function {
	return provfunc.All()
}
