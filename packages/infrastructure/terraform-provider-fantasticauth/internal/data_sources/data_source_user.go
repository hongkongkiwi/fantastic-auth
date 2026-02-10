package data_sources

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-fantasticauth/internal/tenantclient"
)

// User represents a Vault user for data source
type User struct {
	ID            string            `json:"id"`
	Email         string            `json:"email"`
	FirstName     string            `json:"first_name"`
	LastName      string            `json:"last_name"`
	EmailVerified bool              `json:"email_verified"`
	Metadata      map[string]string `json:"metadata"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

func DataSourceUser() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceUserRead,
		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The user ID (either id or email must be specified)",
			},
			"email": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The user's email address (either id or email must be specified)",
			},
			"first_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The user's first name",
			},
			"last_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The user's last name",
			},
			"email_verified": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the email is verified",
			},
			"metadata": {
				Type:        schema.TypeMap,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Additional metadata for the user",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the user was created",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the user was last updated",
			},
		},
	}
}

func dataSourceUserRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)
	var diags diag.Diagnostics

	userID := d.Get("id").(string)
	email := d.Get("email").(string)

	if userID == "" && email == "" {
		return diag.Errorf("either id or email must be specified")
	}

	var resp *http.Response
	var err error

	if userID != "" {
		resp, err = client.Get(ctx, fmt.Sprintf("/users/%s", userID))
	} else {
		// Search by email
		resp, err = client.Get(ctx, fmt.Sprintf("/users?email=%s", email))
	}

	if err != nil {
		return diag.FromErr(err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return diag.Errorf("user not found")
	}

	var user User
	if err := tenantclient.UnmarshalResponse(resp, &user); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(user.ID)
	d.Set("email", user.Email)
	d.Set("first_name", user.FirstName)
	d.Set("last_name", user.LastName)
	d.Set("email_verified", user.EmailVerified)
	d.Set("metadata", user.Metadata)
	d.Set("created_at", user.CreatedAt.Format(time.RFC3339))
	d.Set("updated_at", user.UpdatedAt.Format(time.RFC3339))

	return diags
}
