import { LogLayer, LoggerType } from 'loglayer'

export const logger = new LogLayer({
  logger: {
    instance: console,
    type: LoggerType.CONSOLE,
  },
})
