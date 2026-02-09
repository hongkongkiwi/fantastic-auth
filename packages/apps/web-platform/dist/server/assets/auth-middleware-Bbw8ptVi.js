import { Redis } from "ioredis";
import { e as env } from "./server-Dz7KC5sb.js";
import { l as logger } from "./logger-D87hn870.js";
import { d as createMiddleware } from "../server.js";
const SESSION_COOKIE_NAME = "vault_ui_session";
const SESSION_TTL_MS = 1e3 * 60 * 60 * 8;
const CSRF_TOKEN_TTL_MS = 1e3 * 60 * 60 * 24;
let redis = null;
const memorySessions = /* @__PURE__ */ new Map();
const memoryCsrf = /* @__PURE__ */ new Map();
const getSessionKey = (token) => `session:${token}`;
const getCsrfKey = (token) => `csrf:${token}`;
const generateToken = () => crypto.randomUUID();
const generateCsrfToken = () => {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
};
const cleanupMemory = () => {
  const now = Date.now();
  for (const [token, entry] of memorySessions.entries()) {
    if (entry.expiresAt <= now) {
      memorySessions.delete(token);
    }
  }
  for (const [token, entry] of memoryCsrf.entries()) {
    if (entry.expiresAt <= now) {
      memoryCsrf.delete(token);
    }
  }
};
const getRedis = () => {
  const redisUrl = process.env.REDIS_URL;
  if (!redisUrl) {
    return null;
  }
  if (redis) {
    return redis;
  }
  redis = new Redis(redisUrl, {
    retryStrategy: (attempt) => {
      if (attempt > 3) return null;
      return Math.min(attempt * 100, 3e3);
    },
    maxRetriesPerRequest: 3
  });
  return redis;
};
const getSessionCookieName = () => SESSION_COOKIE_NAME;
const getSessionTtlSeconds = () => Math.floor(SESSION_TTL_MS / 1e3);
const getCsrfTtlSeconds = () => Math.floor(CSRF_TOKEN_TTL_MS / 1e3);
const createSession = async (user) => {
  cleanupMemory();
  const token = generateToken();
  const csrfToken = generateCsrfToken();
  const record = {
    token,
    createdAt: Date.now(),
    user,
    csrfToken
  };
  const client = getRedis();
  if (!client) {
    memorySessions.set(token, {
      value: record,
      expiresAt: Date.now() + SESSION_TTL_MS
    });
    memoryCsrf.set(token, {
      value: csrfToken,
      expiresAt: Date.now() + CSRF_TOKEN_TTL_MS
    });
    return record;
  }
  await Promise.all([
    client.setex(getSessionKey(token), getSessionTtlSeconds(), JSON.stringify(record)),
    client.setex(getCsrfKey(token), getCsrfTtlSeconds(), csrfToken)
  ]);
  return record;
};
const revokeSession = async (token) => {
  cleanupMemory();
  memorySessions.delete(token);
  memoryCsrf.delete(token);
  const client = getRedis();
  if (!client) return;
  await Promise.all([client.del(getSessionKey(token)), client.del(getCsrfKey(token))]);
};
const validateSession = async (token) => {
  cleanupMemory();
  const client = getRedis();
  if (!client) {
    return memorySessions.has(token);
  }
  const value = await client.get(getSessionKey(token));
  return Boolean(value);
};
const getSession = async (token) => {
  cleanupMemory();
  const client = getRedis();
  if (!client) {
    const entry = memorySessions.get(token);
    if (!entry) return null;
    memorySessions.set(token, {
      value: entry.value,
      expiresAt: Date.now() + SESSION_TTL_MS
    });
    return entry.value;
  }
  const raw = await client.get(getSessionKey(token));
  if (!raw) return null;
  await client.expire(getSessionKey(token), getSessionTtlSeconds());
  return JSON.parse(raw);
};
const getSessionUser = async (token) => {
  const session = await getSession(token);
  return session?.user ?? null;
};
const getCsrfToken = async (sessionToken) => {
  cleanupMemory();
  const client = getRedis();
  if (!client) {
    return memoryCsrf.get(sessionToken)?.value ?? null;
  }
  return await client.get(getCsrfKey(sessionToken));
};
const validateCsrfToken = async (sessionToken, csrfToken) => {
  const stored = await getCsrfToken(sessionToken);
  return Boolean(stored && stored === csrfToken);
};
const parseCookie = (cookieHeader, name) => {
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(";");
  for (const part of parts) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) {
      return decodeURIComponent(rest.join("="));
    }
  }
  return null;
};
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
const assertAuthConfigured = () => {
  if (!hasUiPassword()) {
    serverLogger.warn("UI session auth is not configured");
    throw new Error("UI session auth is not configured. Set INTERNAL_UI_PASSWORD.");
  }
};
const authMiddleware = createMiddleware({ type: "request" }).server(
  async ({ request, next }) => {
    assertAuthConfigured();
    const token = parseCookie(
      request.headers.get("cookie"),
      getSessionCookieName()
    );
    if (!token) {
      serverLogger.warn("Unauthorized UI request - no session token");
      return new Response("Unauthorized", { status: 401 });
    }
    const isValid = await validateSession(token);
    if (!isValid) {
      serverLogger.warn("Unauthorized UI request - invalid session");
      return new Response("Unauthorized", { status: 401 });
    }
    return next({
      context: {
        sessionToken: token
      }
    });
  }
);
createMiddleware({ type: "request" }).server(
  async ({ request, next }) => {
    const sessionToken = parseCookie(
      request.headers.get("cookie"),
      getSessionCookieName()
    );
    if (!sessionToken) {
      return new Response("Unauthorized", { status: 401 });
    }
    const csrfToken = request.headers.get("X-CSRF-Token");
    if (!csrfToken) {
      serverLogger.warn("CSRF validation failed - missing token");
      return new Response("CSRF token required", { status: 403 });
    }
    const isValid = await validateCsrfToken(sessionToken, csrfToken);
    if (!isValid) {
      serverLogger.warn("CSRF validation failed - invalid token");
      return new Response("Invalid CSRF token", { status: 403 });
    }
    return next({
      context: {
        sessionToken
      }
    });
  }
);
createMiddleware({ type: "request" }).server(
  async ({ request, next }) => {
    assertAuthConfigured();
    const sessionToken = parseCookie(
      request.headers.get("cookie"),
      getSessionCookieName()
    );
    if (!sessionToken) {
      serverLogger.warn("Unauthorized request - no session token");
      return new Response("Unauthorized", { status: 401 });
    }
    const isSessionValid = await validateSession(sessionToken);
    if (!isSessionValid) {
      serverLogger.warn("Unauthorized request - invalid session");
      return new Response("Unauthorized", { status: 401 });
    }
    const method = request.method;
    if (method === "POST" || method === "PUT" || method === "DELETE" || method === "PATCH") {
      const csrfToken = request.headers.get("X-CSRF-Token");
      if (!csrfToken) {
        serverLogger.warn("CSRF validation failed - missing token");
        return new Response("CSRF token required", { status: 403 });
      }
      const isCsrfValid = await validateCsrfToken(sessionToken, csrfToken);
      if (!isCsrfValid) {
        serverLogger.warn("CSRF validation failed - invalid token");
        return new Response("Invalid CSRF token", { status: 403 });
      }
    }
    const freshCsrfToken = await getCsrfToken(sessionToken);
    return next({
      context: {
        sessionToken,
        csrfToken: freshCsrfToken
      }
    });
  }
);
createMiddleware({ type: "request" }).server(
  async ({ request, next }) => {
    const token = parseCookie(
      request.headers.get("cookie"),
      getSessionCookieName()
    );
    if (token) {
      const isValid = await validateSession(token);
      if (isValid) {
        return next({
          context: {
            sessionToken: token
          }
        });
      }
    }
    return next();
  }
);
export {
  authMiddleware as a,
  assertAuthConfigured as b,
  createSession as c,
  getSessionTtlSeconds as d,
  getSessionUser as e,
  serverLogger$1 as f,
  getSessionCookieName as g,
  parseCookie as p,
  revokeSession as r,
  serverLogger as s
};
