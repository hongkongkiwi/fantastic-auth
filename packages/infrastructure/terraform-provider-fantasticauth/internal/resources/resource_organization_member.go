package resources

import (
	"context"
	"errors"
	"fmt"
	"time"

	tenantauth "github.com/fantasticauth/tenant-sdk-go/vaultauth"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-fantasticauth/internal/tenantclient"
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
	client := m.(*tenantclient.Client)

	orgID := d.Get("organization_id").(string)
	userID := d.Get("user_id").(string)
	member, err := client.TenantSDK.Organizations.AddMember(orgID, tenantauth.AddMemberRequest{
		UserID: userID,
		Role:   d.Get("role").(string),
	})
	if err != nil || member == nil {
		return diag.FromErr(err)
	}

	// Stable Terraform ID based on identity tuple.
	d.SetId(fmt.Sprintf("%s:%s", orgID, userID))

	return resourceOrganizationMemberRead(ctx, d, m)
}

func resourceOrganizationMemberRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)
	var diags diag.Diagnostics

	orgID := d.Get("organization_id").(string)
	userID := d.Get("user_id").(string)

	members, err := client.TenantSDK.Organizations.GetMembers(orgID)
	if err != nil {
		var notFoundErr *tenantauth.NotFoundError
		if errors.As(err, &notFoundErr) {
			d.SetId("")
			return diags
		}
		return diag.FromErr(err)
	}

	var matched *tenantauth.OrganizationMembership
	for i := range members {
		if members[i].UserID == userID {
			matched = &members[i]
			break
		}
	}

	if matched == nil {
		d.SetId("")
		return diags
	}

	d.Set("organization_id", matched.OrganizationID)
	d.Set("user_id", matched.UserID)
	d.Set("role", string(matched.Role))
	if matched.JoinedAt != nil {
		d.Set("created_at", matched.JoinedAt.Format(time.RFC3339))
		d.Set("updated_at", matched.JoinedAt.Format(time.RFC3339))
	}

	return diags
}

func resourceOrganizationMemberUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)

	orgID := d.Get("organization_id").(string)
	userID := d.Get("user_id").(string)

	_, err := client.TenantSDK.Organizations.UpdateMemberRole(orgID, userID, tenantauth.UpdateMemberRoleRequest{
		Role: d.Get("role").(string),
	})
	if err != nil {
		return diag.FromErr(err)
	}

	return resourceOrganizationMemberRead(ctx, d, m)
}

func resourceOrganizationMemberDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)
	var diags diag.Diagnostics

	orgID := d.Get("organization_id").(string)
	userID := d.Get("user_id").(string)

	if err := client.TenantSDK.Organizations.RemoveMember(orgID, userID); err != nil {
		var notFoundErr *tenantauth.NotFoundError
		if errors.As(err, &notFoundErr) {
			d.SetId("")
			return diags
		}
		return diag.FromErr(err)
	}

	d.SetId("")
	return diags
}
