package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-vault/internal/provider"
)

// User represents a Vault user
type User struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	Password      string                 `json:"password,omitempty"`
	FirstName     string                 `json:"first_name"`
	LastName      string                 `json:"last_name"`
	EmailVerified bool                   `json:"email_verified"`
	Metadata      map[string]string      `json:"metadata"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

func ResourceUser() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceUserCreate,
		ReadContext:   resourceUserRead,
		UpdateContext: resourceUserUpdate,
		DeleteContext: resourceUserDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"email": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The user's email address",
			},
			"password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "The user's password",
			},
			"first_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The user's first name",
			},
			"last_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The user's last name",
			},
			"email_verified": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether the email is verified",
			},
			"metadata": {
				Type:        schema.TypeMap,
				Optional:    true,
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

func resourceUserCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)

	metadata := make(map[string]string)
	if v, ok := d.GetOk("metadata"); ok {
		for key, val := range v.(map[string]interface{}) {
			metadata[key] = val.(string)
		}
	}

	user := &User{
		Email:         d.Get("email").(string),
		Password:      d.Get("password").(string),
		FirstName:     d.Get("first_name").(string),
		LastName:      d.Get("last_name").(string),
		EmailVerified: d.Get("email_verified").(bool),
		Metadata:      metadata,
	}

	resp, err := client.Post(ctx, "/users", user)
	if err != nil {
		return diag.FromErr(err)
	}

	var createdUser User
	if err := provider.UnmarshalResponse(resp, &createdUser); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdUser.ID)

	return resourceUserRead(ctx, d, m)
}

func resourceUserRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)
	var diags diag.Diagnostics

	resp, err := client.Get(ctx, fmt.Sprintf("/users/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return diags
	}

	var user User
	if err := provider.UnmarshalResponse(resp, &user); err != nil {
		return diag.FromErr(err)
	}

	d.Set("email", user.Email)
	d.Set("first_name", user.FirstName)
	d.Set("last_name", user.LastName)
	d.Set("email_verified", user.EmailVerified)
	d.Set("metadata", user.Metadata)
	d.Set("created_at", user.CreatedAt.Format(time.RFC3339))
	d.Set("updated_at", user.UpdatedAt.Format(time.RFC3339))

	return diags
}

func resourceUserUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)

	metadata := make(map[string]string)
	if v, ok := d.GetOk("metadata"); ok {
		for key, val := range v.(map[string]interface{}) {
			metadata[key] = val.(string)
		}
	}

	updateData := map[string]interface{}{
		"first_name":     d.Get("first_name").(string),
		"last_name":      d.Get("last_name").(string),
		"email_verified": d.Get("email_verified").(bool),
		"metadata":       metadata,
	}

	if d.HasChange("password") {
		updateData["password"] = d.Get("password").(string)
	}

	if d.HasChange("email") {
		updateData["email"] = d.Get("email").(string)
	}

	resp, err := client.Put(ctx, fmt.Sprintf("/users/%s", d.Id()), updateData)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := provider.UnmarshalResponse(resp, nil); err != nil {
		return diag.FromErr(err)
	}

	return resourceUserRead(ctx, d, m)
}

func resourceUserDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)
	var diags diag.Diagnostics

	resp, err := client.Delete(ctx, fmt.Sprintf("/users/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	if err := provider.UnmarshalResponse(resp, nil); err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")
	return diags
}
