package resources

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-fantasticauth/internal/tenantclient"
)

// Organization represents a Vault organization
type Organization struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Slug        string                 `json:"slug"`
	Description string                 `json:"description"`
	Settings    map[string]interface{} `json:"settings"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

func ResourceOrganization() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceOrganizationCreate,
		ReadContext:   resourceOrganizationRead,
		UpdateContext: resourceOrganizationUpdate,
		DeleteContext: resourceOrganizationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The organization name",
			},
			"slug": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The organization slug (unique identifier)",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The organization description",
			},
			"settings": {
				Type:        schema.TypeMap,
				Optional:    true,
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

func resourceOrganizationCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)

	settings := make(map[string]interface{})
	if v, ok := d.GetOk("settings"); ok {
		for key, val := range v.(map[string]interface{}) {
			settings[key] = val
		}
	}

	org := &Organization{
		Name:        d.Get("name").(string),
		Slug:        d.Get("slug").(string),
		Description: d.Get("description").(string),
		Settings:    settings,
	}

	resp, err := client.Post(ctx, "/organizations", org)
	if err != nil {
		return diag.FromErr(err)
	}

	var createdOrg Organization
	if err := tenantclient.UnmarshalResponse(resp, &createdOrg); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdOrg.ID)

	return resourceOrganizationRead(ctx, d, m)
}

func resourceOrganizationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)
	var diags diag.Diagnostics

	resp, err := client.Get(ctx, fmt.Sprintf("/organizations/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return diags
	}

	var org Organization
	if err := tenantclient.UnmarshalResponse(resp, &org); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", org.Name)
	d.Set("slug", org.Slug)
	d.Set("description", org.Description)
	d.Set("settings", org.Settings)
	d.Set("created_at", org.CreatedAt.Format(time.RFC3339))
	d.Set("updated_at", org.UpdatedAt.Format(time.RFC3339))

	return diags
}

func resourceOrganizationUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)

	settings := make(map[string]interface{})
	if v, ok := d.GetOk("settings"); ok {
		for key, val := range v.(map[string]interface{}) {
			settings[key] = val
		}
	}

	updateData := map[string]interface{}{
		"name":        d.Get("name").(string),
		"description": d.Get("description").(string),
		"settings":    settings,
	}

	resp, err := client.Put(ctx, fmt.Sprintf("/organizations/%s", d.Id()), updateData)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := tenantclient.UnmarshalResponse(resp, nil); err != nil {
		return diag.FromErr(err)
	}

	return resourceOrganizationRead(ctx, d, m)
}

func resourceOrganizationDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)
	var diags diag.Diagnostics

	resp, err := client.Delete(ctx, fmt.Sprintf("/organizations/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	if err := tenantclient.UnmarshalResponse(resp, nil); err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")
	return diags
}
