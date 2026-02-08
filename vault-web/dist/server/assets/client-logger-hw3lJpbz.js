import { l as logger } from "./auth-middleware-CUT-Ooy9.js";
import { e as env, x as isSentryInitialized } from "./router-BDwxh4pl.js";
import * as Sentry from "@sentry/react";
const levelOrder = ["trace", "debug", "info", "warn", "error", "fatal"];
const minLevel = env.VITE_LOG_LEVEL ?? "info";
const shouldLog = (level) => levelOrder.indexOf(level) >= levelOrder.indexOf(minLevel);
const shouldSendToSentry = () => Boolean(env.VITE_SENTRY_DSN) && isSentryInitialized();
const capture = (level, message, error, meta) => {
  if (!shouldSendToSentry()) return;
  Sentry.withScope((scope) => {
    scope.setLevel(level);
    if (meta) {
      scope.setContext("meta", meta);
    }
    if (error instanceof Error) {
      Sentry.captureException(error);
    } else {
      Sentry.captureMessage(message);
    }
  });
};
const clientLogger = {
  debug: (message, meta) => {
    if (!shouldLog("debug")) return;
    meta ? logger.withMetadata(meta).debug(message) : logger.debug(message);
  },
  info: (message, meta) => {
    if (!shouldLog("info")) return;
    meta ? logger.withMetadata(meta).info(message) : logger.info(message);
  },
  warn: (message, meta) => {
    if (shouldLog("warn")) {
      meta ? logger.withMetadata(meta).warn(message) : logger.warn(message);
    }
    capture("warning", message, void 0, meta);
  },
  error: (message, error, meta) => {
    if (shouldLog("error")) {
      if (error instanceof Error) {
        logger.withError(error).error(message);
      } else if (meta) {
        logger.withMetadata(meta).error(message);
      } else {
        logger.error(message);
      }
    }
    capture("error", message, error, meta);
  }
};
export {
  clientLogger as c
};
