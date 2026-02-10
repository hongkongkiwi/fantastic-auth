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

// Webhook represents a webhook configuration
type Webhook struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	URL       string            `json:"url"`
	Events    []string          `json:"events"`
	Secret    string            `json:"secret,omitempty"`
	Headers   map[string]string `json:"headers"`
	IsActive  bool              `json:"is_active"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

func ResourceWebhook() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceWebhookCreate,
		ReadContext:   resourceWebhookRead,
		UpdateContext: resourceWebhookUpdate,
		DeleteContext: resourceWebhookDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The webhook name",
			},
			"url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The webhook URL",
			},
			"events": {
				Type:        schema.TypeList,
				Required:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Events to subscribe to",
			},
			"secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Secret for webhook signature verification",
			},
			"headers": {
				Type:        schema.TypeMap,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Custom headers to include in webhook requests",
			},
			"is_active": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Whether the webhook is active",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the webhook was created",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "When the webhook was last updated",
			},
		},
	}
}

func resourceWebhookCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)

	headers := make(map[string]string)
	if v, ok := d.GetOk("headers"); ok {
		for key, val := range v.(map[string]interface{}) {
			headers[key] = val.(string)
		}
	}

	webhook := &Webhook{
		Name:     d.Get("name").(string),
		URL:      d.Get("url").(string),
		Events:   expandStringList(d.Get("events").([]interface{})),
		Secret:   d.Get("secret").(string),
		Headers:  headers,
		IsActive: d.Get("is_active").(bool),
	}

	resp, err := client.Post(ctx, "/webhooks", webhook)
	if err != nil {
		return diag.FromErr(err)
	}

	var createdWebhook Webhook
	if err := tenantclient.UnmarshalResponse(resp, &createdWebhook); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdWebhook.ID)

	return resourceWebhookRead(ctx, d, m)
}

func resourceWebhookRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)
	var diags diag.Diagnostics

	resp, err := client.Get(ctx, fmt.Sprintf("/webhooks/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return diags
	}

	var webhook Webhook
	if err := tenantclient.UnmarshalResponse(resp, &webhook); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", webhook.Name)
	d.Set("url", webhook.URL)
	d.Set("events", webhook.Events)
	// Don't set secret on read for security
	d.Set("headers", webhook.Headers)
	d.Set("is_active", webhook.IsActive)
	d.Set("created_at", webhook.CreatedAt.Format(time.RFC3339))
	d.Set("updated_at", webhook.UpdatedAt.Format(time.RFC3339))

	return diags
}

func resourceWebhookUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)

	headers := make(map[string]string)
	if v, ok := d.GetOk("headers"); ok {
		for key, val := range v.(map[string]interface{}) {
			headers[key] = val.(string)
		}
	}

	updateData := map[string]interface{}{
		"name":      d.Get("name").(string),
		"url":       d.Get("url").(string),
		"events":    expandStringList(d.Get("events").([]interface{})),
		"headers":   headers,
		"is_active": d.Get("is_active").(bool),
	}

	if d.HasChange("secret") {
		updateData["secret"] = d.Get("secret").(string)
	}

	resp, err := client.Put(ctx, fmt.Sprintf("/webhooks/%s", d.Id()), updateData)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := tenantclient.UnmarshalResponse(resp, nil); err != nil {
		return diag.FromErr(err)
	}

	return resourceWebhookRead(ctx, d, m)
}

func resourceWebhookDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*tenantclient.Client)
	var diags diag.Diagnostics

	resp, err := client.Delete(ctx, fmt.Sprintf("/webhooks/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	if err := tenantclient.UnmarshalResponse(resp, nil); err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")
	return diags
}
