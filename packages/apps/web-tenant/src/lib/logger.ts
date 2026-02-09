import { ConsoleTransport, LogLayer } from 'loglayer'
import { env } from '@/env/client'
import { Sentry, isSentryInitialized } from './sentry'

type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal'

const levelOrder: LogLevel[] = ['trace', 'debug', 'info', 'warn', 'error', 'fatal']
const minLevel = (env.VITE_LOG_LEVEL as LogLevel | undefined) ?? 'info'

const shouldLog = (level: LogLevel) =>
  levelOrder.indexOf(level) >= levelOrder.indexOf(minLevel)

export const logger = new LogLayer({
  transport: new ConsoleTransport({
    logger: console,
  }),
})

const captureToSentry = (message: string, error?: unknown, meta?: Record<string, unknown>) => {
  if (!env.VITE_SENTRY_DSN || !isSentryInitialized()) return
  Sentry.withScope((scope) => {
    scope.setLevel('error')
    if (meta) scope.setContext('meta', meta)
    if (error instanceof Error) {
      Sentry.captureException(error)
    } else {
      Sentry.captureMessage(message)
    }
  })
}

export const appLogger = {
  debug: (message: string, meta?: Record<string, unknown>) => {
    if (!shouldLog('debug')) return
    meta ? logger.withMetadata(meta).debug(message) : logger.debug(message)
  },
  info: (message: string, meta?: Record<string, unknown>) => {
    if (!shouldLog('info')) return
    meta ? logger.withMetadata(meta).info(message) : logger.info(message)
  },
  warn: (message: string, meta?: Record<string, unknown>) => {
    if (!shouldLog('warn')) return
    meta ? logger.withMetadata(meta).warn(message) : logger.warn(message)
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
    captureToSentry(message, error, meta)
  },
}
