import { logger } from './logger'
import { env } from '../env/client'
import { Sentry, isSentryInitialized } from './sentry'

type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal'

const levelOrder: LogLevel[] = ['trace', 'debug', 'info', 'warn', 'error', 'fatal']
const minLevel = (env.VITE_LOG_LEVEL as LogLevel | undefined) ?? 'info'

const shouldLog = (level: LogLevel) =>
  levelOrder.indexOf(level) >= levelOrder.indexOf(minLevel)

const shouldSendToSentry = () =>
  Boolean(env.VITE_SENTRY_DSN) && isSentryInitialized()

const capture = (
  level: 'info' | 'warning' | 'error' | 'fatal',
  message: string,
  error?: unknown,
  meta?: Record<string, unknown>,
) => {
  if (!shouldSendToSentry()) return

  Sentry.withScope((scope) => {
    scope.setLevel(level)
    if (meta) {
      scope.setContext('meta', meta)
    }
    if (error instanceof Error) {
      Sentry.captureException(error)
    } else {
      Sentry.captureMessage(message)
    }
  })
}

export const clientLogger = {
  debug: (message: string, meta?: Record<string, unknown>) => {
    if (!shouldLog('debug')) return
    meta ? logger.withMetadata(meta).debug(message) : logger.debug(message)
  },
  info: (message: string, meta?: Record<string, unknown>) => {
    if (!shouldLog('info')) return
    meta ? logger.withMetadata(meta).info(message) : logger.info(message)
  },
  warn: (message: string, meta?: Record<string, unknown>) => {
    if (shouldLog('warn')) {
      meta ? logger.withMetadata(meta).warn(message) : logger.warn(message)
    }
    capture('warning', message, undefined, meta)
  },
  error: (message: string, error?: unknown, meta?: Record<string, unknown>) => {
    if (shouldLog('error')) {
      if (error instanceof Error) {
        logger.withError(error).error(message)
      } else if (meta) {
        logger.withMetadata(meta).error(message)
      } else {
        logger.error(message)
      }
    }

    capture('error', message, error, meta)
  },
}
