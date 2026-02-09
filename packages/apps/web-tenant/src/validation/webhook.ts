import { z } from 'zod'

const validWebhookEvents = [
  'user.created',
  'user.updated',
  'user.deleted',
  'organization.created',
  'organization.updated',
  'organization.deleted',
  'session.created',
  'session.revoked',
  'mfa.enabled',
  'mfa.disabled',
] as const

export const createWebhookSchema = z.object({
  url: z
    .string()
    .min(1, 'URL is required')
    .url('Please enter a valid URL')
    .refine(
      (url) => url.startsWith('https://'),
      'Webhook URL must use HTTPS'
    ),
  events: z
    .array(z.enum(validWebhookEvents))
    .min(1, 'At least one event is required'),
  secret: z
    .string()
    .min(32, 'Secret must be at least 32 characters')
    .optional(),
})

export type CreateWebhookInput = z.infer<typeof createWebhookSchema>

export const updateWebhookSchema = z.object({
  url: z
    .string()
    .url('Please enter a valid URL')
    .refine(
      (url) => url.startsWith('https://'),
      'Webhook URL must use HTTPS'
    )
    .optional(),
  events: z.array(z.enum(validWebhookEvents)).optional(),
  active: z.boolean().optional(),
})

export type UpdateWebhookInput = z.infer<typeof updateWebhookSchema>
