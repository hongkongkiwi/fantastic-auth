import { createEnv } from '@t3-oss/env-core'
import { z } from 'zod'

export const env = createEnv({
  clientPrefix: 'VITE_',
  client: {
    VITE_API_URL: z.string().min(1).optional(),
    VITE_LOG_LEVEL: z
      .enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal'])
      .optional(),
    VITE_SENTRY_DSN: z.string().url().optional(),
    VITE_SENTRY_ENVIRONMENT: z.string().min(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE: z.coerce.number().min(0).max(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE_HIGH: z.coerce.number().min(0).max(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE_HIGH_ROUTES: z.string().min(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE_LOW: z.coerce.number().min(0).max(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE_LOW_ROUTES: z.string().min(1).optional(),
    VITE_FEATURE_SECURITY_DASHBOARD: z.enum(['true', 'false']).optional().default('false'),
    VITE_FEATURE_SELF_SERVICE_DEVICES: z.enum(['true', 'false']).optional().default('false'),
    VITE_FEATURE_SELF_SERVICE_SESSIONS: z.enum(['true', 'false']).optional().default('false'),
    VITE_FEATURE_SELF_SERVICE_PRIVACY: z.enum(['true', 'false']).optional().default('false'),
    VITE_OAUTH_GOOGLE_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_OAUTH_GITHUB_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_OAUTH_MICROSOFT_ENABLED: z.enum(['true', 'false']).optional().default('false'),
    VITE_OAUTH_APPLE_ENABLED: z.enum(['true', 'false']).optional().default('false'),
  },
  runtimeEnv: import.meta.env,
  emptyStringAsUndefined: true,
})
