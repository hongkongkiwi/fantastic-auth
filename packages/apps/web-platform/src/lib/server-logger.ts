import { logger } from './logger'
import { env } from '../env/server'

type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal'

const levelOrder: LogLevel[] = ['trace', 'debug', 'info', 'warn', 'error', 'fatal']
const minLevel: LogLevel = (env.LOG_LEVEL as LogLevel | undefined) ?? 'info'

const shouldLog = (level: LogLevel) =>
  levelOrder.indexOf(level) >= levelOrder.indexOf(minLevel)

export const serverLogger = {
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
    if (!shouldLog('error')) return
    if (error instanceof Error) {
      logger.withError(error).error(message)
    } else if (meta) {
      logger.withMetadata(meta).error(message)
    } else {
      logger.error(message)
    }
  },
}
