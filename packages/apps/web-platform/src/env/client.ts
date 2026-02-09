import { createEnv } from '@t3-oss/env-core'
import { z } from 'zod'

export const env = createEnv({
  clientPrefix: 'VITE_',
  client: {
    VITE_INTERNAL_API_BASE_URL: z.string().url().optional(),
    VITE_SENTRY_DSN: z.string().url().optional(),
    VITE_SENTRY_ENVIRONMENT: z.string().min(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE: z.coerce.number().min(0).max(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE_HIGH: z.coerce.number().min(0).max(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE_HIGH_ROUTES: z.string().min(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE_LOW: z.coerce.number().min(0).max(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE_LOW_ROUTES: z.string().min(1).optional(),
    VITE_LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).optional(),
    VITE_ENABLE_SUPPORT_IMPERSONATION: z.enum(['true', 'false']).optional().default('false'),
    // CAPTCHA Providers - Set to 'true' to enable each provider
    VITE_CAPTCHA_RECAPTCHA_V2_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_CAPTCHA_RECAPTCHA_V3_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_CAPTCHA_HCAPTCHA_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_CAPTCHA_TURNSTILE_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    // OAuth Providers - Set to 'true' to enable each provider
    VITE_OAUTH_GOOGLE_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_OAUTH_GITHUB_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_OAUTH_MICROSOFT_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_OAUTH_APPLE_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    // Email Providers - Set to 'true' to enable each provider
    VITE_EMAIL_SMTP_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_EMAIL_SENDGRID_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_EMAIL_MAILGUN_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_EMAIL_AWS_SES_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_EMAIL_POSTMARK_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_EMAIL_RESEND_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    // SMS Providers - Set to 'true' to enable each provider
    VITE_SMS_TWILIO_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_SMS_MESSAGE_BIRD_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_SMS_VONAGE_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    // Storage Providers - Set to 'true' to enable each provider
    VITE_STORAGE_S3_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_STORAGE_R2_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_STORAGE_AZURE_BLOB_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    // Payment Providers - Set to 'true' to enable each provider
    VITE_PAYMENT_STRIPE_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_PAYMENT_PADDLE_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    // Analytics - Set to 'true' to enable
    VITE_ANALYTICS_POSTHOG_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_ANALYTICS_PLAUSIBLE_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    // Security - Set to 'true' to enable
    VITE_SECURITY_HIBP_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_SECURITY_MAXMIND_ENABLED: z.enum(['true', 'false']).optional().default('false'),
  },
  runtimeEnv: import.meta.env,
  emptyStringAsUndefined: true,
})
