type LoggerMeta = Record<string, unknown>

type LoggerLike = {
  debug: (message: string) => void
  info: (message: string) => void
  warn: (message: string) => void
  error: (message: string) => void
  withMetadata: (meta: LoggerMeta) => LoggerLike
  withError: (error: unknown) => LoggerLike
}

const createLogger = (meta?: LoggerMeta, error?: unknown): LoggerLike => {
  const format = (message: string) => {
    if (!meta && !error) return message
    return JSON.stringify({ message, meta, error })
  }

  return {
    debug: (message) => console.debug(format(message)),
    info: (message) => console.info(format(message)),
    warn: (message) => console.warn(format(message)),
    error: (message) => console.error(format(message)),
    withMetadata: (nextMeta) => createLogger({ ...(meta ?? {}), ...nextMeta }, error),
    withError: (nextError) => createLogger(meta, nextError),
  }
}

export const logger = createLogger()
