package resources

import (
	"context"
	"errors"
	"time"

	tenantauth "github.com/fantasticauth/tenant-sdk-go/vaultauth"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-fantasticauth/internal/tenantclient"
)

// User represents a Vault user
type User struct {
	ID            string            `json:"id"`
	Email         string            `json:"email"`
	Password      string            `json:"password,omitempty"`
	FirstName     string            `json:"first_name"`
	LastName      string            `json:"last_name"`
	EmailVerified bool              `json:"email_verified"`
	Metadata      map[string]string `json:"metadata"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
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
	client := m.(*tenantclient.Client)

	metadata := make(map[string]interface{})
	if v, ok := d.GetOk("metadata"); ok {
		for key, val := range v.(map[string]interface{}) {
			metadata[key] = val.(string)
		}
	}

	var firstName *string
	if v, ok := d.GetOk("first_name"); ok {
		s := v.(string)
		if s != "" {
			firstName = &s
		}
	}

	var lastName *string
	if v, ok := d.GetOk("last_name"); ok {
		s := v.(string)
		if s != "" {
			lastName = &s
		}
	}

	createdUser, err := client.TenantSDK.Users.Create(tenantauth.CreateUserRequest{
		Email:         d.Get("email").(string),
		Password:      d.Get("password").(string),
		FirstName:     firstName,
		LastName:      lastName,
		EmailVerified: d.Get("email_verified").(bool),
		Metadata:      metadata,
	})
	if err != nil || createdUser == nil {
		return diag.FromErr(err)
	}

	d.SetId(createdUser.ID)

	return resourceUserRead(ctx, d, m)
}

func resourceUserRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)
	var diags diag.Diagnostics

	user, err := client.TenantSDK.Users.Get(d.Id())
	if err != nil {
		var notFoundErr *tenantauth.NotFoundError
		if errors.As(err, &notFoundErr) {
			d.SetId("")
			return diags
		}
		return diag.FromErr(err)
	}

	d.Set("email", user.Email)
	if user.FirstName != nil {
		d.Set("first_name", *user.FirstName)
	} else {
		d.Set("first_name", "")
	}
	if user.LastName != nil {
		d.Set("last_name", *user.LastName)
	} else {
		d.Set("last_name", "")
	}
	d.Set("email_verified", user.EmailVerified)
	if user.Metadata != nil {
		metadata := make(map[string]string, len(user.Metadata))
		for key, val := range user.Metadata {
			if s, ok := val.(string); ok {
				metadata[key] = s
			}
		}
		d.Set("metadata", metadata)
	}
	if user.CreatedAt != nil {
		d.Set("created_at", user.CreatedAt.Format(time.RFC3339))
	}
	if user.UpdatedAt != nil {
		d.Set("updated_at", user.UpdatedAt.Format(time.RFC3339))
	}

	return diags
}

func resourceUserUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)

	metadata := make(map[string]interface{})
	if v, ok := d.GetOk("metadata"); ok {
		for key, val := range v.(map[string]interface{}) {
			metadata[key] = val.(string)
		}
	}

	var firstName *string
	if v, ok := d.GetOk("first_name"); ok {
		s := v.(string)
		if s != "" {
			firstName = &s
		}
	}

	var lastName *string
	if v, ok := d.GetOk("last_name"); ok {
		s := v.(string)
		if s != "" {
			lastName = &s
		}
	}

	req := tenantauth.UpdateUserRequest{
		FirstName: firstName,
		LastName:  lastName,
		Metadata:  metadata,
	}

	if d.HasChange("email") {
		email := d.Get("email").(string)
		req.Email = &email
	}

	if _, err := client.TenantSDK.Users.Update(d.Id(), req); err != nil {
		return diag.FromErr(err)
	}

	if d.HasChange("password") {
		if err := client.TenantSDK.Users.UpdatePassword(d.Id(), d.Get("password").(string)); err != nil {
			return diag.FromErr(err)
		}
	}

	return resourceUserRead(ctx, d, m)
}

func resourceUserDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)
	var diags diag.Diagnostics

	if err := client.TenantSDK.Users.Delete(d.Id()); err != nil {
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
