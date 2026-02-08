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

// OAuthClient represents an OAuth client
type OAuthClient struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	ClientID        string    `json:"client_id"`
	ClientSecret    string    `json:"client_secret,omitempty"`
	RedirectURIs    []string  `json:"redirect_uris"`
	AllowedScopes   []string  `json:"allowed_scopes"`
	AllowedGrants   []string  `json:"allowed_grants"`
	IsConfidential  bool      `json:"is_confidential"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func ResourceOAuthClient() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceOAuthClientCreate,
		ReadContext:   resourceOAuthClientRead,
		UpdateContext: resourceOAuthClientUpdate,
		DeleteContext: resourceOAuthClientDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The OAuth client name",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The OAuth client description",
			},
			"client_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The OAuth client ID",
			},
			"client_secret": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "The OAuth client secret (only available on create)",
			},
			"redirect_uris": {
				Type:        schema.TypeList,
				Required:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Allowed redirect URIs",
			},
			"allowed_scopes": {
				Type:        schema.TypeList,
				Required:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Allowed OAuth scopes",
			},
			"allowed_grants": {
				Type:        schema.TypeList,
				Required:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Allowed grant types",
			},
			"is_confidential": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Whether the client is confidential or public",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the client was created",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the client was last updated",
			},
		},
	}
}

func expandStringList(list []interface{}) []string {
	result := make([]string, len(list))
	for i, v := range list {
		result[i] = v.(string)
	}
	return result
}

func resourceOAuthClientCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)

	oauthClient := &OAuthClient{
		Name:           d.Get("name").(string),
		Description:    d.Get("description").(string),
		RedirectURIs:   expandStringList(d.Get("redirect_uris").([]interface{})),
		AllowedScopes:  expandStringList(d.Get("allowed_scopes").([]interface{})),
		AllowedGrants:  expandStringList(d.Get("allowed_grants").([]interface{})),
		IsConfidential: d.Get("is_confidential").(bool),
	}

	resp, err := client.Post(ctx, "/oauth/clients", oauthClient)
	if err != nil {
		return diag.FromErr(err)
	}

	var createdClient OAuthClient
	if err := provider.UnmarshalResponse(resp, &createdClient); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdClient.ID)
	d.Set("client_secret", createdClient.ClientSecret)

	return resourceOAuthClientRead(ctx, d, m)
}

func resourceOAuthClientRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)
	var diags diag.Diagnostics

	resp, err := client.Get(ctx, fmt.Sprintf("/oauth/clients/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return diags
	}

	var oauthClient OAuthClient
	if err := provider.UnmarshalResponse(resp, &oauthClient); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", oauthClient.Name)
	d.Set("description", oauthClient.Description)
	d.Set("client_id", oauthClient.ClientID)
	d.Set("redirect_uris", oauthClient.RedirectURIs)
	d.Set("allowed_scopes", oauthClient.AllowedScopes)
	d.Set("allowed_grants", oauthClient.AllowedGrants)
	d.Set("is_confidential", oauthClient.IsConfidential)
	d.Set("created_at", oauthClient.CreatedAt.Format(time.RFC3339))
	d.Set("updated_at", oauthClient.UpdatedAt.Format(time.RFC3339))

	return diags
}

func resourceOAuthClientUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)

	updateData := map[string]interface{}{
		"name":            d.Get("name").(string),
		"description":     d.Get("description").(string),
		"redirect_uris":   expandStringList(d.Get("redirect_uris").([]interface{})),
		"allowed_scopes":  expandStringList(d.Get("allowed_scopes").([]interface{})),
		"allowed_grants":  expandStringList(d.Get("allowed_grants").([]interface{})),
		"is_confidential": d.Get("is_confidential").(bool),
	}

	resp, err := client.Put(ctx, fmt.Sprintf("/oauth/clients/%s", d.Id()), updateData)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := provider.UnmarshalResponse(resp, nil); err != nil {
		return diag.FromErr(err)
	}

	return resourceOAuthClientRead(ctx, d, m)
}

func resourceOAuthClientDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)
	var diags diag.Diagnostics

	resp, err := client.Delete(ctx, fmt.Sprintf("/oauth/clients/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	if err := provider.UnmarshalResponse(resp, nil); err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")
	return diags
}
