package resources

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-vault/internal/provider"
)

// Role represents a role
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func ResourceRole() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceRoleCreate,
		ReadContext:   resourceRoleRead,
		UpdateContext: resourceRoleUpdate,
		DeleteContext: resourceRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The role name",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The role description",
			},
			"permissions": {
				Type:        schema.TypeList,
				Required:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "List of permissions assigned to the role",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the role was created",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the role was last updated",
			},
		},
	}
}

func resourceRoleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)

	role := &Role{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		Permissions: expandStringList(d.Get("permissions").([]interface{})),
	}

	resp, err := client.Post(ctx, "/roles", role)
	if err != nil {
		return diag.FromErr(err)
	}

	var createdRole Role
	if err := provider.UnmarshalResponse(resp, &createdRole); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdRole.ID)

	return resourceRoleRead(ctx, d, m)
}

func resourceRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)
	var diags diag.Diagnostics

	resp, err := client.Get(ctx, fmt.Sprintf("/roles/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return diags
	}

	var role Role
	if err := provider.UnmarshalResponse(resp, &role); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", role.Name)
	d.Set("description", role.Description)
	d.Set("permissions", role.Permissions)
	d.Set("created_at", role.CreatedAt.Format(time.RFC3339))
	d.Set("updated_at", role.UpdatedAt.Format(time.RFC3339))

	return diags
}

func resourceRoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)

	updateData := map[string]interface{}{
		"name":        d.Get("name").(string),
		"description": d.Get("description").(string),
		"permissions": expandStringList(d.Get("permissions").([]interface{})),
	}

	resp, err := client.Put(ctx, fmt.Sprintf("/roles/%s", d.Id()), updateData)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := provider.UnmarshalResponse(resp, nil); err != nil {
		return diag.FromErr(err)
	}

	return resourceRoleRead(ctx, d, m)
}

func resourceRoleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)
	var diags diag.Diagnostics

	resp, err := client.Delete(ctx, fmt.Sprintf("/roles/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	if err := provider.UnmarshalResponse(resp, nil); err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")
	return diags
}
