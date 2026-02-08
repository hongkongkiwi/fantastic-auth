# WhatsApp OTP Setup Guide

This guide explains how to configure WhatsApp Business API for sending OTP codes in Vault.

## Overview

WhatsApp OTP provides an alternative to SMS for multi-factor authentication with several advantages:

- **Higher delivery rates** in many countries (especially LATAM, India, Southeast Asia)
- **No SMS gateway costs** in some regions
- **Rich media support** (buttons, formatting)
- **End-to-end encryption** for enhanced security
- **No character limits** like traditional SMS

## Prerequisites

Before you begin, you'll need:

1. A Meta Business Account
2. A Facebook Developer account
3. A verified WhatsApp Business account
4. A phone number to register with WhatsApp Business

## Setup Steps

### 1. Create a Meta Business Account

If you don't have one already:

1. Go to [Meta Business Suite](https://business.facebook.com/)
2. Click "Create Account"
3. Follow the verification steps

### 2. Create a WhatsApp Business App

1. Go to [Facebook Developers](https://developers.facebook.com/)
2. Create a new app
3. Select "Business" as the app type
4. Add "WhatsApp" product to your app

### 3. Add and Verify Phone Number

1. In the WhatsApp section of your app:
   - Go to "Getting Started"
   - Click "Add phone number"
2. Enter your business phone number
3. Verify via SMS or voice call
4. Note the **Phone Number ID** (you'll need this for configuration)

### 4. Create Message Template

WhatsApp requires pre-approved message templates for business messaging:

1. Go to WhatsApp > Message Templates
2. Click "Create Template"
3. Select category: **Authentication**
4. Name your template (e.g., `vault_otp_en`)
5. Language: English (or your preferred language)
6. Header (optional): None or text
7. Body text example:
   ```
   Your Vault verification code is {{1}}. This code is valid for 10 minutes.
   ```
   
   Or for multiple languages:
   - Spanish: `Tu código de verificación de Vault es {{1}}. Válido por 10 minutos.`
   - Portuguese: `Seu código de verificação Vault é {{1}}. Válido por 10 minutos.`

8. Footer (optional): "Do not share this code"
9. Buttons (optional): None
10. Submit for review (usually approved within minutes for OTP templates)

### 5. Generate Access Token

1. Go to your app dashboard
2. In the left sidebar, go to **WhatsApp > Getting Started**
3. Look for "Access Tokens" section
4. Click "Add" to create a new token
5. Select the appropriate permissions (at minimum: `whatsapp_business_messaging`)
6. Copy the token and store it securely

**Note:** Temporary tokens expire in 24 hours. For production, generate a **Permanent Access Token**:

1. Go to **System Users** in Business Manager
2. Create a system user with Admin role
3. Assign the WhatsApp app to this user
4. Generate a permanent token

### 6. Configure Vault

Add these environment variables to your `.env` file:

```bash
# WhatsApp Business API
WHATSAPP_ENABLED=true
WHATSAPP_PHONE_NUMBER_ID=123456789012345
WHATSAPP_ACCESS_TOKEN=EAABsbCS1iBpBA...
WHATSAPP_API_VERSION=v18.0
WHATSAPP_TEMPLATE_NAME=vault_otp_en
WHATSAPP_LANGUAGE_CODE=en
WHATSAPP_FALLBACK_TO_SMS=true
```

#### Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `WHATSAPP_ENABLED` | Enable WhatsApp OTP | `false` |
| `WHATSAPP_PHONE_NUMBER_ID` | Your WhatsApp Business phone number ID | - |
| `WHATSAPP_ACCESS_TOKEN` | Meta Graph API access token | - |
| `WHATSAPP_API_VERSION` | Graph API version | `v18.0` |
| `WHATSAPP_TEMPLATE_NAME` | Name of your approved template | `vault_otp_en` |
| `WHATSAPP_LANGUAGE_CODE` | Template language code | `en` |
| `WHATSAPP_FALLBACK_TO_SMS` | Fallback to SMS if WhatsApp fails | `true` |

### 7. Test the Integration

1. Start your Vault server
2. Enable MFA for a test user
3. Select WhatsApp as the MFA method
4. Enter a phone number with WhatsApp installed
5. You should receive the OTP via WhatsApp

## Template Language Support

Pre-configured template names for common languages:

| Language | Template Name | Code |
|----------|---------------|------|
| English | `vault_otp_en` | en |
| Spanish | `vault_otp_es` | es |
| Portuguese | `vault_otp_pt` | pt |
| French | `vault_otp_fr` | fr |
| German | `vault_otp_de` | de |
| Hindi | `vault_otp_hi` | hi |
| Arabic | `vault_otp_ar` | ar |
| Indonesian | `vault_otp_id` | id |

Create templates with these exact names, or customize the `WHATSAPP_TEMPLATE_NAME` configuration.

## Phone Number Format

WhatsApp requires phone numbers in **E.164 format** without the `+` prefix:

- ✅ Correct: `14155552671`
- ❌ Incorrect: `+1 415 555 2671`
- ❌ Incorrect: `(415) 555-2671`

The Vault system automatically normalizes phone numbers to the correct format.

## Rate Limits

WhatsApp Business API has the following rate limits:

- **1,000 messages/second** for most phone numbers
- Higher limits available for verified business accounts
- Template message limits apply per 24-hour window

Vault's internal rate limiting is configured via:

```bash
SMS_MAX_SENDS_PER_PHONE=3
SMS_RATE_LIMIT_WINDOW_SECS=600
```

## Fallback to SMS

Enable SMS fallback to ensure OTP delivery when:

- The user doesn't have WhatsApp installed
- WhatsApp service is unavailable
- The phone number is not registered with WhatsApp

```bash
WHATSAPP_FALLBACK_TO_SMS=true
```

When fallback is enabled and WhatsApp fails, the system automatically sends via SMS instead.

## Security Considerations

1. **Access Token Security**: Store the access token securely (use environment variables, never commit to git)
2. **Token Rotation**: Regularly rotate access tokens
3. **Template Approval**: Only use approved templates to avoid account suspension
4. **Rate Limiting**: Implement proper rate limiting to prevent abuse
5. **Phone Verification**: Always verify phone number ownership before enabling MFA

## Troubleshooting

### Error: "Template does not exist"

- Verify the template name matches exactly (case-sensitive)
- Ensure the template is approved by Meta
- Check the language code matches the template language

### Error: "Invalid access token"

- Token may have expired (temporary tokens last 24 hours)
- Generate a permanent token for production
- Ensure the token has `whatsapp_business_messaging` permission

### Error: "Phone number not registered"

- The recipient must have WhatsApp installed
- Phone number must include country code
- Number format should be E.164 without `+`

### Messages not being received

1. Check WhatsApp Business account status
2. Verify phone number is not blocked
3. Ensure template has the `{{1}}` placeholder for OTP code
4. Check rate limits haven't been exceeded

### Webhook verification issues

If setting up webhooks for delivery receipts:

1. Ensure your webhook URL is publicly accessible
2. Verify the webhook token matches in both Meta dashboard and Vault config
3. Subscribe to `messages` webhook events

## API Reference

The WhatsApp provider uses Meta's Graph API:

```
POST https://graph.facebook.com/{version}/{phone_number_id}/messages
```

Request body:
```json
{
  "messaging_product": "whatsapp",
  "recipient_type": "individual",
  "to": "14155552671",
  "type": "template",
  "template": {
    "name": "vault_otp_en",
    "language": { "code": "en" },
    "components": [
      {
        "type": "body",
        "parameters": [
          { "type": "text", "text": "123456" }
        ]
      }
    ]
  }
}
```

For more details, see:
- [WhatsApp Business API Documentation](https://developers.facebook.com/docs/whatsapp/cloud-api)
- [Message Templates](https://developers.facebook.com/docs/whatsapp/business-management-api/message-templates)
- [Graph API Reference](https://developers.facebook.com/docs/graph-api)

## Cost Considerations

WhatsApp Business API pricing varies by country:

- **Free tier**: 1,000 conversations per month
- **User-initiated**: Usually cheaper (user sends first message)
- **Business-initiated**: Higher cost (template messages like OTP)

See [Meta's pricing page](https://business.whatsapp.com/products/business-platform/pricing) for current rates.

## Migration from SMS

To migrate users from SMS to WhatsApp MFA:

1. Keep SMS configured as a fallback
2. Allow users to add WhatsApp MFA alongside existing SMS
3. After verification, users can disable SMS MFA if desired
4. Update frontend to show WhatsApp as an option

## SDK Support

### React SDK

```typescript
const { sendOtp } = useMfa();
await sendOtp({ channel: 'whatsapp', phoneNumber: '+1234567890' });
```

### iOS SDK

```swift
try await mfa.sendCode(to: "+1234567890", channel: .whatsapp)
```

### Android SDK

```kotlin
mfa.sendCode(phone = "+1234567890", channel = OtpChannel.WHATSAPP)
```

## Support

For issues related to WhatsApp Business API:
- Meta Developer Support: https://developers.facebook.com/support
- Vault Issues: Create an issue in the Vault GitHub repository
