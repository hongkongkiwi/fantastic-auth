import { createEnv } from "@t3-oss/env-core";
import { z } from "zod";
const SESSION_COOKIE_NAME = "vault_ui_session";
const SESSION_TTL_MS = 1e3 * 60 * 60 * 8;
const sessions = /* @__PURE__ */ new Map();
const getSessionCookieName = () => SESSION_COOKIE_NAME;
const getSessionTtlSeconds = () => Math.floor(SESSION_TTL_MS / 1e3);
const createSession = () => {
  const token = crypto.randomUUID();
  const record = { token, createdAt: Date.now() };
  sessions.set(token, record);
  return record;
};
const revokeSession = (token) => {
  sessions.delete(token);
};
const validateSession = (token) => {
  const record = sessions.get(token);
  if (!record) return false;
  if (Date.now() - record.createdAt > SESSION_TTL_MS) {
    sessions.delete(token);
    return false;
  }
  return true;
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
const env = createEnv({
  server: {
    INTERNAL_API_BASE_URL: z.string().url().optional(),
    INTERNAL_API_KEY: z.string().min(1).optional(),
    INTERNAL_UI_TOKEN: z.string().min(1).optional(),
    INTERNAL_UI_PASSWORD: z.string().min(1).optional(),
    INTERNAL_UI_AUDIT_STORAGE: z.enum(["file"]).optional(),
    LOG_LEVEL: z.enum(["trace", "debug", "info", "warn", "error", "fatal"]).optional()
  },
  runtimeEnv: process.env,
  emptyStringAsUndefined: true
});
export {
  getSessionTtlSeconds as a,
  createSession as c,
  env as e,
  getSessionCookieName as g,
  parseCookie as p,
  revokeSession as r,
  validateSession as v
};
