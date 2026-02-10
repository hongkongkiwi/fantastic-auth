package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-fantasticauth/internal/data_sources"
	"terraform-provider-fantasticauth/internal/resources"
	"terraform-provider-fantasticauth/internal/tenantclient"
)

func New(version string) func() *schema.Provider {
	return func() *schema.Provider {
		p := &schema.Provider{
			Schema: map[string]*schema.Schema{
				"api_key": {
					Type:        schema.TypeString,
					Required:    true,
					DefaultFunc: schema.EnvDefaultFunc("FANTASTICAUTH_API_KEY", nil),
					Description: "The API key for Fantasticauth authentication",
					Sensitive:   true,
				},
				"base_url": {
					Type:        schema.TypeString,
					Required:    true,
					DefaultFunc: schema.EnvDefaultFunc("FANTASTICAUTH_BASE_URL", nil),
					Description: "The base URL of the Fantasticauth server",
				},
				"tenant_id": {
					Type:        schema.TypeString,
					Required:    true,
					DefaultFunc: schema.EnvDefaultFunc("FANTASTICAUTH_TENANT_ID", nil),
					Description: "The tenant ID for Fantasticauth",
				},
			},
			ResourcesMap: map[string]*schema.Resource{
				"fantasticauth_user":                resources.ResourceUser(),
				"fantasticauth_organization":        resources.ResourceOrganization(),
				"fantasticauth_oauth_client":        resources.ResourceOAuthClient(),
				"fantasticauth_saml_connection":     resources.ResourceSAMLConnection(),
				"fantasticauth_webhook":             resources.ResourceWebhook(),
				"fantasticauth_role":                resources.ResourceRole(),
				"fantasticauth_organization_member": resources.ResourceOrganizationMember(),
			},
			DataSourcesMap: map[string]*schema.Resource{
				"fantasticauth_user":         data_sources.DataSourceUser(),
				"fantasticauth_organization": data_sources.DataSourceOrganization(),
				"fantasticauth_tenant":       data_sources.DataSourceTenant(),
			},
		}

		p.ConfigureContextFunc = configure(version, p)

		return p
	}
}

func configure(version string, p *schema.Provider) func(context.Context, *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		config := &tenantclient.Config{
			APIKey:   d.Get("api_key").(string),
			BaseURL:  d.Get("base_url").(string),
			TenantID: d.Get("tenant_id").(string),
		}

		client, err := tenantclient.NewClient(config)
		if err != nil {
			return nil, diag.FromErr(err)
		}

		return client, nil
	}
}
