import { e as env, p as parseCookie, v as validateSession, g as getSessionCookieName } from "./server-DL57AnWM.js";
const createMiddleware = (options, __opts) => {
  const resolvedOptions = {
    type: "request",
    ...__opts || options
  };
  return {
    options: resolvedOptions,
    middleware: (middleware) => {
      return createMiddleware(
        {},
        Object.assign(resolvedOptions, { middleware })
      );
    },
    inputValidator: (inputValidator) => {
      return createMiddleware(
        {},
        Object.assign(resolvedOptions, { inputValidator })
      );
    },
    client: (client) => {
      return createMiddleware(
        {},
        Object.assign(resolvedOptions, { client })
      );
    },
    server: (server) => {
      return createMiddleware(
        {},
        Object.assign(resolvedOptions, { server })
      );
    }
  };
};
const createLogger = (meta, error) => {
  const format = (message) => {
    if (!meta && !error) return message;
    return JSON.stringify({ message, meta, error });
  };
  return {
    debug: (message) => console.debug(format(message)),
    info: (message) => console.info(format(message)),
    warn: (message) => console.warn(format(message)),
    error: (message) => console.error(format(message)),
    withMetadata: (nextMeta) => createLogger({ ...meta ?? {}, ...nextMeta }, error),
    withError: (nextError) => createLogger(meta, nextError)
  };
};
const logger = createLogger();
const levelOrder = ["trace", "debug", "info", "warn", "error", "fatal"];
const minLevel = env.LOG_LEVEL ?? "info";
const shouldLog = (level) => levelOrder.indexOf(level) >= levelOrder.indexOf(minLevel);
const serverLogger = {
  debug: (message, meta) => {
    if (!shouldLog("debug")) return;
    meta ? logger.withMetadata(meta).debug(message) : logger.debug(message);
  },
  info: (message, meta) => {
    if (!shouldLog("info")) return;
    meta ? logger.withMetadata(meta).info(message) : logger.info(message);
  },
  warn: (message, meta) => {
    if (!shouldLog("warn")) return;
    meta ? logger.withMetadata(meta).warn(message) : logger.warn(message);
  },
  error: (message, error, meta) => {
    if (!shouldLog("error")) return;
    if (error instanceof Error) {
      logger.withError(error).error(message);
    } else if (meta) {
      logger.withMetadata(meta).error(message);
    } else {
      logger.error(message);
    }
  }
};
const serverLogger$1 = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  serverLogger
}, Symbol.toStringTag, { value: "Module" }));
const hasUiPassword = () => Boolean(env.INTERNAL_UI_PASSWORD);
const hasUiToken = () => Boolean(env.INTERNAL_UI_TOKEN);
const assertAuthConfigured = () => {
  if (!hasUiPassword() && !hasUiToken()) {
    serverLogger.warn("UI auth is not configured");
    throw new Error(
      "UI auth is not configured. Set INTERNAL_UI_PASSWORD and/or INTERNAL_UI_TOKEN."
    );
  }
};
const authMiddleware = createMiddleware({ type: "request" }).server(
  async ({ request, next }) => {
    assertAuthConfigured();
    const requiredPassword = env.INTERNAL_UI_PASSWORD;
    if (!requiredPassword) {
      return next();
    }
    const token = parseCookie(
      request.headers.get("cookie"),
      getSessionCookieName()
    );
    if (!token || !validateSession(token)) {
      serverLogger.warn("Unauthorized UI request");
      return new Response("Unauthorized", { status: 401 });
    }
    return next();
  }
);
export {
  authMiddleware as a,
  assertAuthConfigured as b,
  serverLogger$1 as c,
  logger as l,
  serverLogger as s
};
