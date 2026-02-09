import { createEnv } from '@t3-oss/env-core'
import { z } from 'zod'

export const env = createEnv({
  server: {
    INTERNAL_API_BASE_URL: z.string().url().optional(),
    INTERNAL_API_KEY: z.string().min(1).optional(),
    INTERNAL_UI_TOKEN: z.string().min(1).optional(),
    INTERNAL_UI_PASSWORD: z.string().min(1).optional(),
    INTERNAL_UI_AUDIT_STORAGE: z.enum(['file']).optional(),
    LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).optional(),
  },
  runtimeEnv: process.env,
  emptyStringAsUndefined: true,
})
