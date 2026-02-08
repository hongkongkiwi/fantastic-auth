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

// OrganizationMember represents an organization membership
type OrganizationMember struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	UserID         string    `json:"user_id"`
	Role           string    `json:"role"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func ResourceOrganizationMember() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceOrganizationMemberCreate,
		ReadContext:   resourceOrganizationMemberRead,
		UpdateContext: resourceOrganizationMemberUpdate,
		DeleteContext: resourceOrganizationMemberDelete,
		Schema: map[string]*schema.Schema{
			"organization_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The organization ID",
			},
			"user_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The user ID",
			},
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The member's role in the organization (admin, member, etc.)",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the membership was created",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the membership was last updated",
			},
		},
	}
}

func resourceOrganizationMemberCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)

	member := &OrganizationMember{
		OrganizationID: d.Get("organization_id").(string),
		UserID:         d.Get("user_id").(string),
		Role:           d.Get("role").(string),
	}

	resp, err := client.Post(ctx, fmt.Sprintf("/organizations/%s/members", member.OrganizationID), member)
	if err != nil {
		return diag.FromErr(err)
	}

	var createdMember OrganizationMember
	if err := provider.UnmarshalResponse(resp, &createdMember); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdMember.ID)

	return resourceOrganizationMemberRead(ctx, d, m)
}

func resourceOrganizationMemberRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)
	var diags diag.Diagnostics

	orgID := d.Get("organization_id").(string)

	resp, err := client.Get(ctx, fmt.Sprintf("/organizations/%s/members/%s", orgID, d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return diags
	}

	var member OrganizationMember
	if err := provider.UnmarshalResponse(resp, &member); err != nil {
		return diag.FromErr(err)
	}

	d.Set("organization_id", member.OrganizationID)
	d.Set("user_id", member.UserID)
	d.Set("role", member.Role)
	d.Set("created_at", member.CreatedAt.Format(time.RFC3339))
	d.Set("updated_at", member.UpdatedAt.Format(time.RFC3339))

	return diags
}

func resourceOrganizationMemberUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)

	orgID := d.Get("organization_id").(string)

	updateData := map[string]interface{}{
		"role": d.Get("role").(string),
	}

	resp, err := client.Put(ctx, fmt.Sprintf("/organizations/%s/members/%s", orgID, d.Id()), updateData)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := provider.UnmarshalResponse(resp, nil); err != nil {
		return diag.FromErr(err)
	}

	return resourceOrganizationMemberRead(ctx, d, m)
}

func resourceOrganizationMemberDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)
	var diags diag.Diagnostics

	orgID := d.Get("organization_id").(string)

	resp, err := client.Delete(ctx, fmt.Sprintf("/organizations/%s/members/%s", orgID, d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	if err := provider.UnmarshalResponse(resp, nil); err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")
	return diags
}
