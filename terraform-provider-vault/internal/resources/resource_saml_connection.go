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

// SAMLConnection represents a SAML connection
type SAMLConnection struct {
	ID                     string            `json:"id"`
	Name                   string            `json:"name"`
	IDPMetadataXML         string            `json:"idp_metadata_xml"`
	NameIDFormat           string            `json:"name_id_format"`
	AttributeMappings      map[string]string `json:"attribute_mappings"`
	JITProvisioningEnabled bool              `json:"jit_provisioning_enabled"`
	CreatedAt              time.Time         `json:"created_at"`
	UpdatedAt              time.Time         `json:"updated_at"`
}

func ResourceSAMLConnection() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceSAMLConnectionCreate,
		ReadContext:   resourceSAMLConnectionRead,
		UpdateContext: resourceSAMLConnectionUpdate,
		DeleteContext: resourceSAMLConnectionDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The SAML connection name",
			},
			"idp_metadata_xml": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "The IdP metadata XML",
			},
			"name_id_format": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				Description: "The NameID format",
			},
			"attribute_mappings": {
				Type:        schema.TypeMap,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Attribute mappings from IdP to user attributes",
			},
			"jit_provisioning_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to enable JIT provisioning",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the connection was created",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the connection was last updated",
			},
		},
	}
}

func resourceSAMLConnectionCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)

	attributeMappings := make(map[string]string)
	if v, ok := d.GetOk("attribute_mappings"); ok {
		for key, val := range v.(map[string]interface{}) {
			attributeMappings[key] = val.(string)
		}
	}

	conn := &SAMLConnection{
		Name:                   d.Get("name").(string),
		IDPMetadataXML:         d.Get("idp_metadata_xml").(string),
		NameIDFormat:           d.Get("name_id_format").(string),
		AttributeMappings:      attributeMappings,
		JITProvisioningEnabled: d.Get("jit_provisioning_enabled").(bool),
	}

	resp, err := client.Post(ctx, "/saml/connections", conn)
	if err != nil {
		return diag.FromErr(err)
	}

	var createdConn SAMLConnection
	if err := provider.UnmarshalResponse(resp, &createdConn); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdConn.ID)

	return resourceSAMLConnectionRead(ctx, d, m)
}

func resourceSAMLConnectionRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)
	var diags diag.Diagnostics

	resp, err := client.Get(ctx, fmt.Sprintf("/saml/connections/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return diags
	}

	var conn SAMLConnection
	if err := provider.UnmarshalResponse(resp, &conn); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", conn.Name)
	// Don't set idp_metadata_xml on read for security
	d.Set("name_id_format", conn.NameIDFormat)
	d.Set("attribute_mappings", conn.AttributeMappings)
	d.Set("jit_provisioning_enabled", conn.JITProvisioningEnabled)
	d.Set("created_at", conn.CreatedAt.Format(time.RFC3339))
	d.Set("updated_at", conn.UpdatedAt.Format(time.RFC3339))

	return diags
}

func resourceSAMLConnectionUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)

	attributeMappings := make(map[string]string)
	if v, ok := d.GetOk("attribute_mappings"); ok {
		for key, val := range v.(map[string]interface{}) {
			attributeMappings[key] = val.(string)
		}
	}

	updateData := map[string]interface{}{
		"name":                     d.Get("name").(string),
		"name_id_format":           d.Get("name_id_format").(string),
		"attribute_mappings":       attributeMappings,
		"jit_provisioning_enabled": d.Get("jit_provisioning_enabled").(bool),
	}

	if d.HasChange("idp_metadata_xml") {
		updateData["idp_metadata_xml"] = d.Get("idp_metadata_xml").(string)
	}

	resp, err := client.Put(ctx, fmt.Sprintf("/saml/connections/%s", d.Id()), updateData)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := provider.UnmarshalResponse(resp, nil); err != nil {
		return diag.FromErr(err)
	}

	return resourceSAMLConnectionRead(ctx, d, m)
}

func resourceSAMLConnectionDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*provider.Client)
	var diags diag.Diagnostics

	resp, err := client.Delete(ctx, fmt.Sprintf("/saml/connections/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	if err := provider.UnmarshalResponse(resp, nil); err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")
	return diags
}
