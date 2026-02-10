package data_sources

import (
	"context"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-fantasticauth/internal/tenantclient"
)

// Tenant represents the current tenant
type Tenant struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Slug        string                 `json:"slug"`
	Description string                 `json:"description"`
	Settings    map[string]interface{} `json:"settings"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

func DataSourceTenant() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceTenantRead,
		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The tenant ID",
			},
			"name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The tenant name",
			},
			"slug": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The tenant slug",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The tenant description",
			},
			"settings": {
				Type:        schema.TypeMap,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Tenant settings",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the tenant was created",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the tenant was last updated",
			},
		},
	}
}

func dataSourceTenantRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)
	var diags diag.Diagnostics

	resp, err := client.Get(ctx, "/tenant")
	if err != nil {
		return diag.FromErr(err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return diag.Errorf("tenant not found")
	}

	var tenant Tenant
	if err := tenantclient.UnmarshalResponse(resp, &tenant); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(tenant.ID)
	d.Set("name", tenant.Name)
	d.Set("slug", tenant.Slug)
	d.Set("description", tenant.Description)
	d.Set("settings", tenant.Settings)
	d.Set("created_at", tenant.CreatedAt.Format(time.RFC3339))
	d.Set("updated_at", tenant.UpdatedAt.Format(time.RFC3339))

	return diags
}
