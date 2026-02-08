package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-vault/internal/data_sources"
	"terraform-provider-vault/internal/resources"
)

func New(version string) func() *schema.Provider {
	return func() *schema.Provider {
		p := &schema.Provider{
			Schema: map[string]*schema.Schema{
				"api_key": {
					Type:        schema.TypeString,
					Required:    true,
					DefaultFunc: schema.EnvDefaultFunc("VAULT_API_KEY", nil),
					Description: "The API key for Vault authentication",
					Sensitive:   true,
				},
				"base_url": {
					Type:        schema.TypeString,
					Required:    true,
					DefaultFunc: schema.EnvDefaultFunc("VAULT_BASE_URL", nil),
					Description: "The base URL of the Vault server",
				},
				"tenant_id": {
					Type:        schema.TypeString,
					Required:    true,
					DefaultFunc: schema.EnvDefaultFunc("VAULT_TENANT_ID", nil),
					Description: "The tenant ID for Vault",
				},
			},
			ResourcesMap: map[string]*schema.Resource{
				"vault_user":              resources.ResourceUser(),
				"vault_organization":      resources.ResourceOrganization(),
				"vault_oauth_client":      resources.ResourceOAuthClient(),
				"vault_saml_connection":   resources.ResourceSAMLConnection(),
				"vault_webhook":           resources.ResourceWebhook(),
				"vault_role":              resources.ResourceRole(),
				"vault_organization_member": resources.ResourceOrganizationMember(),
			},
			DataSourcesMap: map[string]*schema.Resource{
				"vault_user":          data_sources.DataSourceUser(),
				"vault_organization":  data_sources.DataSourceOrganization(),
				"vault_tenant":        data_sources.DataSourceTenant(),
			},
		}

		p.ConfigureContextFunc = configure(version, p)

		return p
	}
}

func configure(version string, p *schema.Provider) func(context.Context, *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		config := &Config{
			APIKey:   d.Get("api_key").(string),
			BaseURL:  d.Get("base_url").(string),
			TenantID: d.Get("tenant_id").(string),
		}

		client, err := NewClient(config)
		if err != nil {
			return nil, diag.FromErr(err)
		}

		return client, nil
	}
}
