package data_sources

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-vault/internal/provider"
)

// Organization represents a Vault organization for data source
type Organization struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Slug        string                 `json:"slug"`
	Description string                 `json:"description"`
	Settings    map[string]interface{} `json:"settings"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

func DataSourceOrganization() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceOrganizationRead,
		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The organization ID (either id or slug must be specified)",
			},
			"slug": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The organization slug (either id or slug must be specified)",
			},
			"name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The organization name",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The organization description",
			},
			"settings": {
				Type:        schema.TypeMap,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Organization settings",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the organization was created",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the organization was last updated",
			},
		},
	}
}

func dataSourceOrganizationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)
	var diags diag.Diagnostics

	orgID := d.Get("id").(string)
	slug := d.Get("slug").(string)

	if orgID == "" && slug == "" {
		return diag.Errorf("either id or slug must be specified")
	}

	var resp *http.Response
	var err error

	if orgID != "" {
		resp, err = client.Get(ctx, fmt.Sprintf("/organizations/%s", orgID))
	} else {
		// Search by slug
		resp, err = client.Get(ctx, fmt.Sprintf("/organizations?slug=%s", slug))
	}

	if err != nil {
		return diag.FromErr(err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return diag.Errorf("organization not found")
	}

	var org Organization
	if err := provider.UnmarshalResponse(resp, &org); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(org.ID)
	d.Set("name", org.Name)
	d.Set("slug", org.Slug)
	d.Set("description", org.Description)
	d.Set("settings", org.Settings)
	d.Set("created_at", org.CreatedAt.Format(time.RFC3339))
	d.Set("updated_at", org.UpdatedAt.Format(time.RFC3339))

	return diags
}
