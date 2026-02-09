import * as Sentry from '@sentry/react'
import { env } from '@/env/client'

let initialized = false

const parseRoutes = (value?: string) =>
  value
    ?.split(',')
    .map((entry) => entry.trim())
    .filter(Boolean) ?? []

export const initSentry = () => {
  if (initialized) return
  if (typeof window === 'undefined') return
  if (!env.VITE_SENTRY_DSN) return

  const highSampleRoutes = parseRoutes(env.VITE_SENTRY_TRACES_SAMPLE_RATE_HIGH_ROUTES)
  const lowSampleRoutes = parseRoutes(env.VITE_SENTRY_TRACES_SAMPLE_RATE_LOW_ROUTES)
  const defaultSampleRate = env.VITE_SENTRY_TRACES_SAMPLE_RATE ?? 0
  const highSampleRate = env.VITE_SENTRY_TRACES_SAMPLE_RATE_HIGH
  const lowSampleRate = env.VITE_SENTRY_TRACES_SAMPLE_RATE_LOW

  const pickSampleRate = (pathname?: string | null) => {
    if (!pathname) return defaultSampleRate
    if (highSampleRate !== undefined && highSampleRoutes.some((route) => pathname.startsWith(route))) {
      return highSampleRate
    }
    if (lowSampleRate !== undefined && lowSampleRoutes.some((route) => pathname.startsWith(route))) {
      return lowSampleRate
    }
    return defaultSampleRate
  }

  Sentry.init({
    dsn: env.VITE_SENTRY_DSN,
    environment: env.VITE_SENTRY_ENVIRONMENT,
    tracesSampleRate: defaultSampleRate,
    tracesSampler: (context) => {
      const pathname =
        context?.location?.pathname ??
        (typeof window !== 'undefined' ? window.location.pathname : undefined) ??
        (typeof context?.transactionContext?.name === 'string'
          ? context.transactionContext.name
          : undefined)
      return pickSampleRate(pathname)
    },
  })

  initialized = true
}

export const isSentryInitialized = () => initialized

export { Sentry }

