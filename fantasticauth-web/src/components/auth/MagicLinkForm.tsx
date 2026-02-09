import { useState } from 'react'
import { motion } from 'framer-motion'
import { Mail, ArrowRight, CheckCircle } from 'lucide-react'
import { Button } from '../ui/Button'
import { Input } from '../ui/Input'
import { useForm } from '@tanstack/react-form'

interface MagicLinkFormProps {
  onSuccess?: () => void
}

export function MagicLinkForm({ onSuccess }: MagicLinkFormProps) {
  const [isLoading, setIsLoading] = useState(false)
  const [isSent, setIsSent] = useState(false)
  const [error, setError] = useState('')
  const [sentEmail, setSentEmail] = useState('')

  const form = useForm({
    defaultValues: {
      email: '',
    },
    onSubmit: async ({ value }) => {
      setError('')
      setIsLoading(true)

      try {
        const response = await fetch('/api/v1/auth/magic-link', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: value.email }),
        })

        if (!response.ok) {
          const data = await response.json()
          throw new Error(data.error?.message || 'Failed to send magic link')
        }

        setSentEmail(value.email)
        setIsSent(true)
        onSuccess?.()
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An error occurred')
      } finally {
        setIsLoading(false)
      }
    },
  })

  if (isSent) {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="text-center space-y-4 py-8"
      >
        <div className="w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto">
          <CheckCircle className="w-8 h-8 text-green-600 dark:text-green-400" />
        </div>
        <div>
          <h3 className="text-lg font-semibold">Check your email</h3>
          <p className="text-sm text-muted-foreground mt-1">
            We've sent a magic link to <strong>{sentEmail}</strong>
          </p>
          <p className="text-xs text-muted-foreground mt-2">
            Link expires in 15 minutes
          </p>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            setIsSent(false)
            setSentEmail('')
            form.reset()
          }}
        >
          Use a different email
        </Button>
      </motion.div>
    )
  }

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault()
        event.stopPropagation()
        void form.handleSubmit()
      }}
      className="space-y-4"
    >
      <div className="space-y-2">
        <form.Field
          name="email"
          validators={{
            onChange: ({ value }) => {
              if (!value.trim()) return 'Email is required'
              if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
                return 'Please enter a valid email'
              }
              return undefined
            },
          }}
        >
          {(field) => (
            <Input
              label="Email"
              type="email"
              placeholder="you@example.com"
              value={field.state.value}
              onChange={(e) => field.handleChange(e.target.value)}
              onBlur={field.handleBlur}
              leftIcon={<Mail className="h-4 w-4 text-muted-foreground" />}
              name="email"
              autoComplete="email"
              autoCapitalize="none"
              spellCheck={false}
              required
              disabled={isLoading}
              error={
                error ||
                (field.state.meta.isTouched ? field.state.meta.errors[0] : undefined)
              }
            />
          )}
        </form.Field>
      </div>

      <Button
        type="submit"
        fullWidth
        isLoading={isLoading}
        rightIcon={<ArrowRight className="h-4 w-4" />}
      >
        {isLoading ? 'Sending…' : 'Send Magic Link'}
      </Button>

      <p className="text-xs text-center text-muted-foreground">
        You'll receive an email with a secure link to sign in instantly
      </p>
    </form>
  )
}
