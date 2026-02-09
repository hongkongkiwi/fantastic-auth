import { z } from 'zod'

export const createUserSchema = z.object({
  email: z
    .string()
    .min(1, 'Email is required')
    .email('Please enter a valid email address'),
  firstName: z
    .string()
    .min(1, 'First name is required')
    .max(50, 'First name must be less than 50 characters'),
  lastName: z
    .string()
    .min(1, 'Last name is required')
    .max(50, 'Last name must be less than 50 characters'),
  role: z.enum(['admin', 'member'], {
    required_error: 'Role is required',
  }),
})

export type CreateUserInput = z.infer<typeof createUserSchema>

export const updateUserSchema = z.object({
  firstName: z
    .string()
    .min(1, 'First name is required')
    .max(50, 'First name must be less than 50 characters')
    .optional(),
  lastName: z
    .string()
    .min(1, 'Last name is required')
    .max(50, 'Last name must be less than 50 characters')
    .optional(),
  role: z.enum(['admin', 'member']).optional(),
  status: z.enum(['active', 'inactive', 'suspended']).optional(),
})

export type UpdateUserInput = z.infer<typeof updateUserSchema>

export const inviteUserSchema = z.object({
  email: z
    .string()
    .min(1, 'Email is required')
    .email('Please enter a valid email address'),
  role: z.enum(['admin', 'member'], {
    required_error: 'Role is required',
  }),
  organizationId: z.string().optional(),
})

export type InviteUserInput = z.infer<typeof inviteUserSchema>
