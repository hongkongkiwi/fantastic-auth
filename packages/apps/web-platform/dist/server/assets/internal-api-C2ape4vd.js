import { c as createServerRpc, a as createServerFn, g as getRequest } from "../server.js";
import { a as authMiddleware, b as assertAuthConfigured, c as createSession, g as getSessionCookieName, d as getSessionTtlSeconds, p as parseCookie, r as revokeSession, e as getSessionUser, s as serverLogger } from "./auth-middleware-Bbw8ptVi.js";
import { promises, createReadStream } from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { Readable, Transform } from "node:stream";
import crypto from "node:crypto";
import { e as env } from "./server-Dz7KC5sb.js";
import { gzipSync } from "node:zlib";
import createClient from "openapi-fetch";
import "react/jsx-runtime";
import "@tanstack/history";
import "@tanstack/router-core/ssr/client";
import "@tanstack/router-core";
import "node:async_hooks";
import "@tanstack/router-core/ssr/server";
import "h3-v2";
import "tiny-invariant";
import "seroval";
import "@tanstack/react-router/ssr/server";
import "@tanstack/react-router";
import "react";
import "ioredis";
import "./logger-D87hn870.js";
import "loglayer";
import "@t3-oss/env-core";
import "zod";
const AUDIT_DIR = path.join(process.cwd(), ".data");
const AUDIT_FILE = path.join(AUDIT_DIR, "audit.log");
const AUDIT_HASH_VERSION = 1;
const GENESIS_HASH = "genesis";
const AUDIT_STORAGE = env.INTERNAL_UI_AUDIT_STORAGE || "file";
const ensureAuditFile = async () => {
  if (AUDIT_STORAGE !== "file") {
    const { serverLogger: serverLogger2 } = await import("./auth-middleware-Bbw8ptVi.js").then((n) => n.f);
    serverLogger2.warn("Unsupported audit storage configured", {
      storage: AUDIT_STORAGE
    });
    throw new Error(
      `Unsupported audit storage: ${AUDIT_STORAGE}. Only 'file' is available right now.`
    );
  }
  await promises.mkdir(AUDIT_DIR, { recursive: true });
  try {
    await promises.access(AUDIT_FILE);
  } catch {
    await promises.writeFile(AUDIT_FILE, "");
  }
};
let cachedTail = null;
const computeAuditHash = (prevHash, payload) => {
  const hash = crypto.createHash("sha256");
  hash.update(prevHash);
  hash.update(JSON.stringify(payload));
  return hash.digest("hex");
};
const readLastLine = async () => {
  await ensureAuditFile();
  const file = await promises.open(AUDIT_FILE, "r");
  try {
    const stats = await file.stat();
    if (stats.size === 0) return null;
    let position = stats.size;
    let buffer = Buffer.alloc(Math.min(4096, position));
    let data = "";
    while (position > 0 && !data.includes("\n")) {
      const readSize = Math.min(buffer.length, position);
      position -= readSize;
      const { bytesRead } = await file.read(buffer, 0, readSize, position);
      data = buffer.toString("utf8", 0, bytesRead) + data;
      if (position === 0) break;
      if (readSize === buffer.length && buffer.length < 64 * 1024) {
        buffer = Buffer.alloc(Math.min(buffer.length * 2, 64 * 1024));
      }
    }
    const lines = data.trim().split("\n");
    return lines.length ? lines[lines.length - 1] : null;
  } finally {
    await file.close();
  }
};
const getTailState = async () => {
  if (cachedTail) return cachedTail;
  const lastLine = await readLastLine();
  if (!lastLine) {
    cachedTail = { hash: GENESIS_HASH, seq: 0 };
    return cachedTail;
  }
  try {
    const record = JSON.parse(lastLine);
    if (record.hash && typeof record.seq === "number") {
      cachedTail = { hash: record.hash, seq: record.seq };
      return cachedTail;
    }
  } catch {
  }
  cachedTail = { hash: GENESIS_HASH, seq: 0 };
  return cachedTail;
};
const appendAuditEvent = async (event) => {
  await ensureAuditFile();
  const tail = await getTailState();
  const seq = tail.seq + 1;
  const base = {
    timestamp: event.timestamp,
    action: event.action,
    detail: event.detail,
    source: event.source,
    seq,
    version: AUDIT_HASH_VERSION
  };
  const hash = computeAuditHash(tail.hash, base);
  const record = {
    ...base,
    prevHash: tail.hash,
    hash
  };
  const line = `${JSON.stringify(record)}
`;
  await promises.appendFile(AUDIT_FILE, line, "utf8");
  cachedTail = { hash, seq };
};
const loadAuditRecords = async () => {
  await ensureAuditFile();
  const content = await promises.readFile(AUDIT_FILE, "utf8");
  const lines = content.split("\n").filter(Boolean);
  const records = [];
  let prevHash = GENESIS_HASH;
  let expectedSeq = 1;
  let hasLegacy = false;
  for (const line of lines) {
    let record = null;
    try {
      record = JSON.parse(line);
    } catch {
      record = null;
    }
    if (!record) continue;
    const seq = typeof record.seq === "number" ? record.seq : null;
    const version = typeof record.version === "number" ? record.version : null;
    const base = seq && version ? {
      timestamp: record.timestamp,
      action: record.action,
      detail: record.detail,
      source: record.source,
      seq,
      version
    } : null;
    let valid = false;
    if (base && record.hash && record.prevHash) {
      const expected = computeAuditHash(record.prevHash, base);
      valid = record.hash === expected && record.prevHash === prevHash && seq === expectedSeq;
    } else {
      hasLegacy = true;
    }
    record.valid = valid;
    records.push(record);
    if (record.hash) {
      prevHash = record.hash;
    }
    if (seq !== null) {
      expectedSeq = seq + 1;
    }
  }
  const validCount = records.filter((record) => record.valid).length;
  const integrity = {
    total: records.length,
    valid: validCount,
    invalid: records.length - validCount,
    lastHash: records.length ? records[records.length - 1].hash : void 0,
    lastSeq: records.length ? records[records.length - 1].seq : void 0,
    hasLegacy
  };
  return { records, integrity };
};
const readAuditEvents = async (options) => {
  const { records, integrity } = await loadAuditRecords();
  const sinceTime = options?.since ? Date.parse(options.since) : null;
  const untilTime = options?.until ? Date.parse(options.until) : null;
  const filtered = records.filter((event) => {
    if (options?.action && !event.action.includes(options.action)) {
      return false;
    }
    if (sinceTime && !Number.isNaN(sinceTime)) {
      const eventTime = Date.parse(event.timestamp);
      if (Number.isNaN(eventTime) || eventTime < sinceTime) {
        return false;
      }
    }
    if (untilTime && !Number.isNaN(untilTime)) {
      const eventTime = Date.parse(event.timestamp);
      if (Number.isNaN(eventTime) || eventTime > untilTime) {
        return false;
      }
    }
    return true;
  });
  const ordered = options?.sort === "asc" ? filtered : filtered.reverse();
  const offset = options?.offset ?? 0;
  const limited = options?.limit ? ordered.slice(offset, offset + options.limit) : ordered;
  return { events: limited, integrity };
};
const countAuditEvents = async (options) => {
  const { records } = await loadAuditRecords();
  const sinceTime = options?.since ? Date.parse(options.since) : null;
  const untilTime = options?.until ? Date.parse(options.until) : null;
  return records.filter((event) => {
    if (options?.action && !event.action.includes(options.action)) {
      return false;
    }
    if (sinceTime && !Number.isNaN(sinceTime)) {
      const eventTime = Date.parse(event.timestamp);
      if (Number.isNaN(eventTime) || eventTime < sinceTime) {
        return false;
      }
    }
    if (untilTime && !Number.isNaN(untilTime)) {
      const eventTime = Date.parse(event.timestamp);
      if (Number.isNaN(eventTime) || eventTime > untilTime) {
        return false;
      }
    }
    return true;
  }).length;
};
const auditFileSize = async () => {
  try {
    const stats = await promises.stat(AUDIT_FILE);
    return stats.size;
  } catch {
    return 0;
  }
};
const streamAuditCsv = async (options) => {
  await ensureAuditFile();
  const sinceTime = options?.since ? Date.parse(options.since) : null;
  const untilTime = options?.until ? Date.parse(options.until) : null;
  const stream = createReadStream(AUDIT_FILE, { encoding: "utf8" });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  async function* generate() {
    yield "timestamp,action,detail,source,seq,valid\n";
    let prevHash = GENESIS_HASH;
    let expectedSeq = 1;
    for await (const line of rl) {
      if (!line) continue;
      let event = null;
      try {
        event = JSON.parse(line);
      } catch {
        continue;
      }
      if (options?.action && !event.action.includes(options.action)) {
        continue;
      }
      if (sinceTime && !Number.isNaN(sinceTime)) {
        const eventTime = Date.parse(event.timestamp);
        if (Number.isNaN(eventTime) || eventTime < sinceTime) {
          continue;
        }
      }
      if (untilTime && !Number.isNaN(untilTime)) {
        const eventTime = Date.parse(event.timestamp);
        if (Number.isNaN(eventTime) || eventTime > untilTime) {
          continue;
        }
      }
      let valid = false;
      if (event.hash && event.prevHash && typeof event.seq === "number" && typeof event.version === "number") {
        const base = {
          timestamp: event.timestamp,
          action: event.action,
          detail: event.detail,
          source: event.source,
          seq: event.seq,
          version: event.version
        };
        const expected = computeAuditHash(event.prevHash, base);
        valid = event.hash === expected && event.prevHash === prevHash && event.seq === expectedSeq;
      }
      if (event.hash) {
        prevHash = event.hash;
      }
      if (typeof event.seq === "number") {
        expectedSeq = event.seq + 1;
      }
      const row = [
        event.timestamp,
        event.action,
        event.detail,
        event.source ?? "",
        event.seq ?? "",
        valid ? "true" : "false"
      ].map((value) => `"${String(value ?? "").replace(/\"/g, '""')}"`).join(",");
      yield `${row}
`;
    }
  }
  const readable = Readable.from(generate());
  if (!options?.onBytes) return readable;
  const counter = new Transform({
    transform(chunk, _encoding, callback) {
      options.onBytes?.(Buffer.byteLength(chunk));
      callback(null, chunk);
    }
  });
  return readable.pipe(counter);
};
const DEFAULT_TIMEOUT_MS = 1e4;
const DEFAULT_RETRIES = 2;
const DEFAULT_RETRY_DELAY_MS = 250;
const shouldRetry = (response) => {
  if (!response) return true;
  return [429, 502, 503, 504].includes(response.status);
};
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const fetchWithRetry = async (input, init = {}, options = {}) => {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const retries = options.retries ?? DEFAULT_RETRIES;
  const retryDelayMs = options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS;
  let attempt = 0;
  let lastError = null;
  const method = (init.method ?? "GET").toUpperCase();
  const canRetry = method === "GET" || method === "HEAD";
  while (attempt <= retries) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(input, {
        ...init,
        signal: controller.signal
      });
      clearTimeout(id);
      if (!canRetry || !shouldRetry(response) || attempt === retries) {
        return response;
      }
      await sleep(retryDelayMs * Math.pow(2, attempt));
      attempt += 1;
      continue;
    } catch (err) {
      clearTimeout(id);
      lastError = err;
      if (!canRetry || attempt === retries) {
        throw err;
      }
      await sleep(retryDelayMs * Math.pow(2, attempt));
      attempt += 1;
    }
  }
  throw lastError instanceof Error ? lastError : new Error("Request failed");
};
const withInternalAuthHeaders = (headers) => {
  const merged = new Headers(headers);
  if (env.INTERNAL_API_KEY) {
    merged.set("X-API-Key", env.INTERNAL_API_KEY);
  }
  if (env.INTERNAL_UI_TOKEN) {
    merged.set("Authorization", `Bearer ${env.INTERNAL_UI_TOKEN}`);
  }
  return merged;
};
const createInternalClient = (baseUrl) => createClient({
  baseUrl,
  fetch: (input, init) => fetchWithRetry(input, {
    ...init,
    headers: withInternalAuthHeaders(init?.headers)
  })
});
const recordAuditExportRequest = () => {
  (/* @__PURE__ */ new Date()).toISOString();
};
const recordAuditExportBytes = (bytes) => {
};
const recordAuditExportError = () => {
  (/* @__PURE__ */ new Date()).toISOString();
};
const DEFAULT_BASE_URL = "http://localhost:3000/api/v1/internal";
const CACHE_TTL_MS = 3e4;
const getUiConfig_createServerFn_handler = createServerRpc({
  id: "911819bcdb0ac36df37529995fbcc19319f1c13d411900322765b0b4689b6866",
  name: "getUiConfig",
  filename: "src/server/internal-api.ts"
}, (opts) => getUiConfig.__executeServer(opts));
const getUiConfig = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).handler(getUiConfig_createServerFn_handler, async () => ({
  internalApiBaseUrl: env.INTERNAL_API_BASE_URL || DEFAULT_BASE_URL,
  hasApiKey: Boolean(env.INTERNAL_API_KEY)
}));
const normalizeBaseUrl = (baseUrl) => (baseUrl || env.INTERNAL_API_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, "");
const getClient = (baseUrl) => createInternalClient(normalizeBaseUrl(baseUrl));
const normalizeApiError = (error, response) => {
  const message = typeof error === "string" ? error : error instanceof Error ? error.message : JSON.stringify(error ?? "Unknown error");
  if (response) {
    serverLogger.error(`Internal API error: ${message}`, void 0, {
      status: response.status
    });
    return `Internal API error (${response.status}): ${message}`;
  }
  serverLogger.error(`Internal API error: ${message}`);
  return message;
};
const cache = /* @__PURE__ */ new Map();
const loginAttempts = /* @__PURE__ */ new Map();
const LOGIN_ATTEMPT_WINDOW_MS = 5 * 60 * 1e3;
const LOGIN_ATTEMPT_MAX_FAILURES = 5;
const LOGIN_ATTEMPT_BLOCK_MS = 15 * 60 * 1e3;
const getCached = (key) => {
  const entry = cache.get(key);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) {
    cache.delete(key);
    return null;
  }
  return entry.value;
};
const setCached = (key, value) => {
  cache.set(key, {
    expiresAt: Date.now() + CACHE_TTL_MS,
    value
  });
};
const buildCacheKey = (prefix, data) => `${prefix}:${JSON.stringify(data ?? {})}`;
const optionalBaseUrlInput = (input) => input;
const getLoginAttemptKey = (request) => {
  const forwardedFor = request.headers.get("x-forwarded-for");
  const ip = forwardedFor?.split(",")[0]?.trim() || "unknown";
  return ip;
};
const assertLoginAllowed = (key) => {
  const record = loginAttempts.get(key);
  if (!record) return;
  if (record.blockedUntil > Date.now()) {
    throw new Error("Too many failed attempts. Try again later.");
  }
  if (record.firstFailureAt + LOGIN_ATTEMPT_WINDOW_MS < Date.now()) {
    loginAttempts.delete(key);
  }
};
const registerFailedLoginAttempt = (key) => {
  const now = Date.now();
  const record = loginAttempts.get(key);
  if (!record || record.firstFailureAt + LOGIN_ATTEMPT_WINDOW_MS < now) {
    loginAttempts.set(key, {
      firstFailureAt: now,
      failureCount: 1,
      blockedUntil: 0
    });
    return;
  }
  record.failureCount += 1;
  if (record.failureCount >= LOGIN_ATTEMPT_MAX_FAILURES) {
    record.blockedUntil = now + LOGIN_ATTEMPT_BLOCK_MS;
  }
  loginAttempts.set(key, record);
};
const clearFailedLoginAttempts = (key) => {
  loginAttempts.delete(key);
};
const getInternalApiHeaders = () => {
  const headers = {
    "Content-Type": "application/json"
  };
  if (env.INTERNAL_API_KEY) {
    headers["X-API-Key"] = env.INTERNAL_API_KEY;
  }
  return headers;
};
const getTenantOwnerLabels = async (baseUrl) => {
  const client = getClient(baseUrl);
  const {
    data: payload,
    error,
    response
  } = await client.GET("/tenants", {
    params: {
      query: {
        page: 1,
        per_page: 250
      }
    },
    headers: env.INTERNAL_API_KEY ? {
      "X-API-Key": env.INTERNAL_API_KEY
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  const tenants = payload?.data ?? [];
  return tenants.map((tenant) => ({
    id: tenant.id ?? "",
    name: tenant.name ?? tenant.slug ?? tenant.id ?? "unknown",
    ownerId: tenant.owner?.id ?? ""
  }));
};
const listTenants_createServerFn_handler = createServerRpc({
  id: "7d1a3f2af301fa41e490368f34e8f8ae0e023376272e5b7ac61e60058bac7fc8",
  name: "listTenants",
  filename: "src/server/internal-api.ts"
}, (opts) => listTenants.__executeServer(opts));
const listTenants = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(listTenants_createServerFn_handler, async ({
  data
}) => {
  const cacheKey = buildCacheKey("listTenants", data);
  const cached = getCached(cacheKey);
  if (cached) return cached;
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/tenants", {
    params: {
      query: {
        page: data?.page,
        per_page: data?.perPage
      }
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  const result = payload ?? {
    data: []
  };
  setCached(cacheKey, result);
  return result;
});
const listSubscriptions_createServerFn_handler = createServerRpc({
  id: "c17ddf115d90cefc85f473daf8f20cdfdd867d5d820175d0b75dec148a580824",
  name: "listSubscriptions",
  filename: "src/server/internal-api.ts"
}, (opts) => listSubscriptions.__executeServer(opts));
const listSubscriptions = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(listSubscriptions_createServerFn_handler, async ({
  data
}) => {
  const cacheKey = buildCacheKey("listSubscriptions", data);
  const cached = getCached(cacheKey);
  if (cached) return cached;
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/billing/subscriptions", {
    params: {
      query: {
        status: data?.status
      }
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  const result = payload ?? {
    data: []
  };
  setCached(cacheKey, result);
  return result;
});
const createTenant_createServerFn_handler = createServerRpc({
  id: "dc593bf19a58f90a9ef7d91fc3ff660548f04d725398ce4e2b726ba87ed08215",
  name: "createTenant",
  filename: "src/server/internal-api.ts"
}, (opts) => createTenant.__executeServer(opts));
const createTenant = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createTenant_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.POST("/tenants", {
    body: {
      name: data.name,
      slug: data.slug,
      plan: data.plan,
      ownerEmail: data.ownerEmail,
      ownerName: data.ownerName,
      customDomain: data.customDomain
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  cache.clear();
  return payload ?? {};
});
const getTenantDetail_createServerFn_handler = createServerRpc({
  id: "c033dd462548d27447f8832a9453c6309e8118540920eeedf3890d19468800e1",
  name: "getTenantDetail",
  filename: "src/server/internal-api.ts"
}, (opts) => getTenantDetail.__executeServer(opts));
const getTenantDetail = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(getTenantDetail_createServerFn_handler, async ({
  data
}) => {
  const cacheKey = buildCacheKey("getTenant", data);
  const cached = getCached(cacheKey);
  if (cached) return cached;
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/tenants/{tenantId}", {
    params: {
      path: {
        tenantId: data.tenantId
      }
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  const result = payload ?? {};
  setCached(cacheKey, result);
  return result;
});
const updateSubscription_createServerFn_handler = createServerRpc({
  id: "a622107254c770bdbd2e7ecb7020f047b0e88c3cb653041ff9dce5d41d892c9a",
  name: "updateSubscription",
  filename: "src/server/internal-api.ts"
}, (opts) => updateSubscription.__executeServer(opts));
const updateSubscription = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(updateSubscription_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.PATCH("/billing/tenants/{tenantId}/subscription", {
    params: {
      path: {
        tenantId: data.tenantId
      }
    },
    body: {
      plan: data.plan,
      seats: data.seats,
      billingInterval: data.billingInterval
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  cache.clear();
  return payload ?? {};
});
const getPlatformOverview_createServerFn_handler = createServerRpc({
  id: "b33359e75789a3827c72557916ba7a42a77edc25f32840131f88b83d62bbba40",
  name: "getPlatformOverview",
  filename: "src/server/internal-api.ts"
}, (opts) => getPlatformOverview.__executeServer(opts));
const getPlatformOverview = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(getPlatformOverview_createServerFn_handler, async ({
  data
}) => {
  const cacheKey = buildCacheKey("platformOverview", data);
  const cached = getCached(cacheKey);
  if (cached) return cached;
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/analytics/overview", {
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  const result = payload ?? {};
  setCached(cacheKey, result);
  return result;
});
const getUsageAnalytics_createServerFn_handler = createServerRpc({
  id: "6e790c4843fa64087b09ea889d35fd2e8cdc0528e5b11a3c7e5f4662d874e863",
  name: "getUsageAnalytics",
  filename: "src/server/internal-api.ts"
}, (opts) => getUsageAnalytics.__executeServer(opts));
const getUsageAnalytics = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(getUsageAnalytics_createServerFn_handler, async ({
  data
}) => {
  const cacheKey = buildCacheKey("usageAnalytics", data);
  const cached = getCached(cacheKey);
  if (cached) return cached;
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/analytics/usage", {
    params: {
      query: {
        metric: data.metric
      }
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  const result = payload ?? {};
  setCached(cacheKey, result);
  return result;
});
const getTenantAnalytics_createServerFn_handler = createServerRpc({
  id: "5aba7518da0ee86bc4b21f1387f4ef7ef67de6189c9bf000d68952120cbb0b67",
  name: "getTenantAnalytics",
  filename: "src/server/internal-api.ts"
}, (opts) => getTenantAnalytics.__executeServer(opts));
const getTenantAnalytics = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(getTenantAnalytics_createServerFn_handler, async ({
  data
}) => {
  const cacheKey = buildCacheKey("tenantAnalytics", data);
  const cached = getCached(cacheKey);
  if (cached) return cached;
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/analytics/tenants", {
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  const result = payload ?? {};
  setCached(cacheKey, result);
  return result;
});
const listFeatureFlags_createServerFn_handler = createServerRpc({
  id: "2d1974e77be9521065178bba432c7ee8a925d552f6a5f0276a6d638df8be4e3a",
  name: "listFeatureFlags",
  filename: "src/server/internal-api.ts"
}, (opts) => listFeatureFlags.__executeServer(opts));
const listFeatureFlags = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(listFeatureFlags_createServerFn_handler, async ({
  data
}) => {
  const cacheKey = buildCacheKey("featureFlags", data);
  const cached = getCached(cacheKey);
  if (cached) return cached;
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/config/features", {
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  const result = payload ?? [];
  setCached(cacheKey, result);
  return result;
});
const updateFeatureFlag_createServerFn_handler = createServerRpc({
  id: "e815b707c6424f3284f4beb7f77f61b1b488727e9d69ed5ad25eb3991d841dab",
  name: "updateFeatureFlag",
  filename: "src/server/internal-api.ts"
}, (opts) => updateFeatureFlag.__executeServer(opts));
const updateFeatureFlag = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(updateFeatureFlag_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.PATCH("/config/features/{flagId}", {
    params: {
      path: {
        flagId: data.flagId
      }
    },
    body: {
      enabled: data.enabled,
      rolloutPercentage: data.rolloutPercentage,
      allowedTenants: data.allowedTenants
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  cache.clear();
  return payload ?? {};
});
const listOrganizations_createServerFn_handler = createServerRpc({
  id: "f64805bca92b126ddfe2186a93600233eb5dac7711eeeedf9005a6d6d152f545",
  name: "listOrganizations",
  filename: "src/server/internal-api.ts"
}, (opts) => listOrganizations.__executeServer(opts));
const listOrganizations = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator(optionalBaseUrlInput).handler(listOrganizations_createServerFn_handler, async ({
  data
}) => {
  const cacheKey = buildCacheKey("organizations", data);
  const cached = getCached(cacheKey);
  if (cached) return cached;
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/organizations", {
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  const result = payload ?? [];
  setCached(cacheKey, result);
  return result;
});
const getOrganization_createServerFn_handler = createServerRpc({
  id: "57ae7773025d2d02b9b4d337bf0f49633e23f9d9f49d2556ec828780ee4784ae",
  name: "getOrganization",
  filename: "src/server/internal-api.ts"
}, (opts) => getOrganization.__executeServer(opts));
const getOrganization = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(getOrganization_createServerFn_handler, async ({
  data
}) => {
  const cacheKey = buildCacheKey("organization", data);
  const cached = getCached(cacheKey);
  if (cached) return cached;
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/organizations/{orgId}", {
    params: {
      path: {
        orgId: data.orgId
      }
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  const result = payload ?? {};
  setCached(cacheKey, result);
  return result;
});
const listOrganizationMembers_createServerFn_handler = createServerRpc({
  id: "cce320e10e1a8e65e57e2a6b3f3beadb719dd70297c52668726fc81ef5ff743d",
  name: "listOrganizationMembers",
  filename: "src/server/internal-api.ts"
}, (opts) => listOrganizationMembers.__executeServer(opts));
const listOrganizationMembers = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(listOrganizationMembers_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/organizations/{orgId}/members", {
    params: {
      path: {
        orgId: data.orgId
      }
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  return payload ?? [];
});
const listRoles_createServerFn_handler = createServerRpc({
  id: "94db58d8167408f3279f7071fedc83f32279d5a2f1b067913bbebfddd43f95ea",
  name: "listRoles",
  filename: "src/server/internal-api.ts"
}, (opts) => listRoles.__executeServer(opts));
const listRoles = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator(optionalBaseUrlInput).handler(listRoles_createServerFn_handler, async ({
  data
}) => {
  const cacheKey = buildCacheKey("roles", data);
  const cached = getCached(cacheKey);
  if (cached) return cached;
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/roles", {
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  const result = payload ?? [];
  setCached(cacheKey, result);
  return result;
});
const createRole_createServerFn_handler = createServerRpc({
  id: "caf715d889b2bc776f8384bd2e654c78eed939be8bffaeb36475f57e3b604c74",
  name: "createRole",
  filename: "src/server/internal-api.ts"
}, (opts) => createRole.__executeServer(opts));
const createRole = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createRole_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.POST("/roles", {
    body: {
      name: data.name,
      description: data.description,
      scope: data.scope,
      permissions: data.permissions
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  cache.clear();
  return payload ?? {};
});
const updateRole_createServerFn_handler = createServerRpc({
  id: "4c8adbf2bdd9a5eed2f49d44acb7e4c32832d8a6a5a5c570d514360807da981d",
  name: "updateRole",
  filename: "src/server/internal-api.ts"
}, (opts) => updateRole.__executeServer(opts));
const updateRole = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(updateRole_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.PATCH("/roles/{roleId}", {
    params: {
      path: {
        roleId: data.roleId
      }
    },
    body: {
      name: data.name,
      description: data.description,
      permissions: data.permissions,
      status: data.status
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  cache.clear();
  return payload ?? {};
});
const listApiKeys_createServerFn_handler = createServerRpc({
  id: "4f6ae767327a0a1bea64094162ea2025b3ffbad335386eaf6786cd234d8abfbc",
  name: "listApiKeys",
  filename: "src/server/internal-api.ts"
}, (opts) => listApiKeys.__executeServer(opts));
const listApiKeys = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator(optionalBaseUrlInput).handler(listApiKeys_createServerFn_handler, async ({
  data
}) => {
  const cacheKey = buildCacheKey("apiKeys", data);
  const cached = getCached(cacheKey);
  if (cached) return cached;
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/api-keys", {
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  const result = payload ?? [];
  setCached(cacheKey, result);
  return result;
});
const createApiKey_createServerFn_handler = createServerRpc({
  id: "396af684ee9b727d29a146d6c5a4aeddc6acb2e5a8cb1554b324756d218cf816",
  name: "createApiKey",
  filename: "src/server/internal-api.ts"
}, (opts) => createApiKey.__executeServer(opts));
const createApiKey = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createApiKey_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.POST("/api-keys", {
    body: {
      name: data.name,
      scopes: data.scopes,
      expiresInDays: data.expiresInDays
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  cache.clear();
  return payload ?? {};
});
const deleteApiKey_createServerFn_handler = createServerRpc({
  id: "11393555b2981f30bac815a3639e326fc9d92a779e6f704fa01896197e6a2385",
  name: "deleteApiKey",
  filename: "src/server/internal-api.ts"
}, (opts) => deleteApiKey.__executeServer(opts));
const deleteApiKey = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(deleteApiKey_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.DELETE("/api-keys/{keyId}", {
    params: {
      path: {
        keyId: data.keyId
      }
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  cache.clear();
  return payload ?? {};
});
const listNotifications_createServerFn_handler = createServerRpc({
  id: "bd0dd0a37253ba5c75a0fe75533ebfe5dc5882902a083a90829941a4285551f7",
  name: "listNotifications",
  filename: "src/server/internal-api.ts"
}, (opts) => listNotifications.__executeServer(opts));
const listNotifications = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator(optionalBaseUrlInput).handler(listNotifications_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/notifications", {
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  return payload ?? [];
});
const markNotificationsRead_createServerFn_handler = createServerRpc({
  id: "d2a3ef54ab9d79e273211fd40725d3f56959510c1d1f8b5dee6a1dbfb61a3cdd",
  name: "markNotificationsRead",
  filename: "src/server/internal-api.ts"
}, (opts) => markNotificationsRead.__executeServer(opts));
const markNotificationsRead = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(markNotificationsRead_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.POST("/notifications/mark-read", {
    body: {
      ids: data.ids
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  return payload ?? [];
});
const listSupportTickets_createServerFn_handler = createServerRpc({
  id: "13e11b3b84a0ce0a939c985ef8c9ddab2d51685946b03864fbe985841da9bf4e",
  name: "listSupportTickets",
  filename: "src/server/internal-api.ts"
}, (opts) => listSupportTickets.__executeServer(opts));
const listSupportTickets = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator(optionalBaseUrlInput).handler(listSupportTickets_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/support/tickets", {
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  return payload ?? [];
});
const listSupportIncidents_createServerFn_handler = createServerRpc({
  id: "34bc7b65748fbdc2a5b7a3f9d8c53f227faf65c469130d4ea732c4c2fc7d3d70",
  name: "listSupportIncidents",
  filename: "src/server/internal-api.ts"
}, (opts) => listSupportIncidents.__executeServer(opts));
const listSupportIncidents = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator(optionalBaseUrlInput).handler(listSupportIncidents_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/support/incidents", {
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  return payload ?? [];
});
const listServiceStatus_createServerFn_handler = createServerRpc({
  id: "e371a416bea511d55a8582ecc0694c224f1a9ad7d9045f37943f920ebb431039",
  name: "listServiceStatus",
  filename: "src/server/internal-api.ts"
}, (opts) => listServiceStatus.__executeServer(opts));
const listServiceStatus = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator(optionalBaseUrlInput).handler(listServiceStatus_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/support/status", {
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  return payload ?? [];
});
const listPlatformInvoices_createServerFn_handler = createServerRpc({
  id: "5712a129ee0706a23bdfae0ed0e8a7ae984787e2e35da1aa75c73801a2f204bd",
  name: "listPlatformInvoices",
  filename: "src/server/internal-api.ts"
}, (opts) => listPlatformInvoices.__executeServer(opts));
const listPlatformInvoices = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(listPlatformInvoices_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/billing/invoices", {
    params: {
      query: {
        page: data.page,
        perPage: data.perPage,
        tenantId: data.tenantId,
        status: data.status,
        createdFrom: data.createdFrom,
        createdTo: data.createdTo
      }
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  return payload ?? {
    invoices: [],
    pagination: void 0
  };
});
const updateTenant_createServerFn_handler = createServerRpc({
  id: "77e5f5691ce2dd50a3ce2eeebaa0957eacbc8916d5276f38090ff1db9835ef4f",
  name: "updateTenant",
  filename: "src/server/internal-api.ts"
}, (opts) => updateTenant.__executeServer(opts));
const updateTenant = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(updateTenant_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.PATCH("/tenants/{tenantId}", {
    params: {
      path: {
        tenantId: data.tenantId
      }
    },
    body: {
      name: data.name,
      plan: data.plan,
      limits: data.limits,
      settings: data.settings
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  cache.clear();
  return payload ?? {};
});
const suspendTenant_createServerFn_handler = createServerRpc({
  id: "1f0cb82e8b0fdf3f27529d6d0650e6a5afd677f7094ac88451fa184d0fc32a5c",
  name: "suspendTenant",
  filename: "src/server/internal-api.ts"
}, (opts) => suspendTenant.__executeServer(opts));
const suspendTenant = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(suspendTenant_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.POST("/tenants/{tenantId}/suspend", {
    params: {
      path: {
        tenantId: data.tenantId
      }
    },
    body: {
      reason: data.reason,
      suspendUntil: data.suspendUntil
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  cache.clear();
  return payload ?? {};
});
const activateTenant_createServerFn_handler = createServerRpc({
  id: "06e1013355e060cedec5dc139f3bc60dace737992ee136c376dcc772e9288476",
  name: "activateTenant",
  filename: "src/server/internal-api.ts"
}, (opts) => activateTenant.__executeServer(opts));
const activateTenant = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(activateTenant_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.POST("/tenants/{tenantId}/activate", {
    params: {
      path: {
        tenantId: data.tenantId
      }
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  cache.clear();
  return payload ?? {};
});
const generateInvoice_createServerFn_handler = createServerRpc({
  id: "8253edfece41c96365eedab52199fc01ee193962b935f88fc3178f10d3f47220",
  name: "generateInvoice",
  filename: "src/server/internal-api.ts"
}, (opts) => generateInvoice.__executeServer(opts));
const generateInvoice = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(generateInvoice_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.POST("/billing/tenants/{tenantId}/invoice", {
    params: {
      path: {
        tenantId: data.tenantId
      }
    },
    body: {
      amount: data.amount,
      description: data.description
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  cache.clear();
  return payload ?? {};
});
const deleteTenant_createServerFn_handler = createServerRpc({
  id: "3f953bf1783c56e47338ca1a36de00c411a55923561ecb1c21c8509ab79914e0",
  name: "deleteTenant",
  filename: "src/server/internal-api.ts"
}, (opts) => deleteTenant.__executeServer(opts));
const deleteTenant = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(deleteTenant_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.DELETE("/tenants/{tenantId}", {
    params: {
      path: {
        tenantId: data.tenantId
      },
      query: {
        force: data.force
      }
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  cache.clear();
  return payload ?? {};
});
const migrateTenant_createServerFn_handler = createServerRpc({
  id: "900a121f7b0003a30714380df8a7cb4ea9927fda9130796bec5b0981533898f7",
  name: "migrateTenant",
  filename: "src/server/internal-api.ts"
}, (opts) => migrateTenant.__executeServer(opts));
const migrateTenant = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(migrateTenant_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.POST("/tenants/{tenantId}/migrate", {
    params: {
      path: {
        tenantId: data.tenantId
      }
    },
    body: {
      targetVersion: data.targetVersion
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  cache.clear();
  return payload ?? {};
});
const getSubscription_createServerFn_handler = createServerRpc({
  id: "bd68d543ffba4fce418155a90da2d6283713bf27a3bb77bfc11e2b373fdd8150",
  name: "getSubscription",
  filename: "src/server/internal-api.ts"
}, (opts) => getSubscription.__executeServer(opts));
const getSubscription = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(getSubscription_createServerFn_handler, async ({
  data
}) => {
  const cacheKey = buildCacheKey("getSubscription", data);
  const cached = getCached(cacheKey);
  if (cached) return cached;
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/billing/tenants/{tenantId}/subscription", {
    params: {
      path: {
        tenantId: data.tenantId
      }
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  const result = payload ?? {};
  setCached(cacheKey, result);
  return result;
});
const getServerStatus_createServerFn_handler = createServerRpc({
  id: "a22e95df85e1fd83c6049d7e397debc0eaa965fc4a65df8650d7f990655e2f0e",
  name: "getServerStatus",
  filename: "src/server/internal-api.ts"
}, (opts) => getServerStatus.__executeServer(opts));
const getServerStatus = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(getServerStatus_createServerFn_handler, async () => {
  return {
    ok: true
  };
});
const loginUi_createServerFn_handler = createServerRpc({
  id: "bd6fedde815c5158f58327da98a5cc46dd2a9ce1c6d90216a3ec2801c61ee5df",
  name: "loginUi",
  filename: "src/server/internal-api.ts"
}, (opts) => loginUi.__executeServer(opts));
const loginUi = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(loginUi_createServerFn_handler, async ({
  data
}) => {
  assertAuthConfigured();
  const request = getRequest();
  const loginAttemptKey = getLoginAttemptKey(request);
  assertLoginAllowed(loginAttemptKey);
  const normalizedEmail = data?.email?.trim().toLowerCase();
  const requiredPassword = env.INTERNAL_UI_PASSWORD;
  const requiredEmail = env.INTERNAL_UI_EMAIL?.trim().toLowerCase();
  if (!requiredPassword) {
    throw new Error("UI password not configured");
  }
  const emailValid = Boolean(normalizedEmail) && (!requiredEmail || normalizedEmail === requiredEmail);
  const passwordValid = Boolean(data?.password) && data?.password === requiredPassword;
  if (!emailValid || !passwordValid) {
    registerFailedLoginAttempt(loginAttemptKey);
    throw new Error("Invalid credentials");
  }
  clearFailedLoginAttempts(loginAttemptKey);
  const session = await createSession({
    email: normalizedEmail,
    name: normalizedEmail.split("@")[0] || "Admin",
    role: "admin"
  });
  const cookieParts = [`${getSessionCookieName()}=${encodeURIComponent(session.token)}`, `Max-Age=${getSessionTtlSeconds()}`, "Path=/", "SameSite=Lax", "HttpOnly"];
  {
    cookieParts.push("Secure");
  }
  return new Response(JSON.stringify({
    ok: true
  }), {
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": cookieParts.join("; ")
    }
  });
});
const logoutUi_createServerFn_handler = createServerRpc({
  id: "c83c165d725911da0a2d10bf9b4081d342982df3a4a1cb0005f655a148062e88",
  name: "logoutUi",
  filename: "src/server/internal-api.ts"
}, (opts) => logoutUi.__executeServer(opts));
const logoutUi = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(logoutUi_createServerFn_handler, async ({
  data
}) => {
  const request = getRequest();
  const token = data?.token ?? parseCookie(request.headers.get("cookie"), getSessionCookieName());
  if (token) {
    await revokeSession(token);
  }
  const cookieParts = [`${getSessionCookieName()}=`, "Max-Age=0", "Path=/", "SameSite=Lax", "HttpOnly"];
  {
    cookieParts.push("Secure");
  }
  return new Response(JSON.stringify({
    ok: true
  }), {
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": cookieParts.join("; ")
    }
  });
});
const getUiSessionStatus_createServerFn_handler = createServerRpc({
  id: "1db4956858288ffaf948aceb54510258587a817b9ce0750abd62db2175097a61",
  name: "getUiSessionStatus",
  filename: "src/server/internal-api.ts"
}, (opts) => getUiSessionStatus.__executeServer(opts));
const getUiSessionStatus = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).handler(getUiSessionStatus_createServerFn_handler, async () => {
  const request = getRequest();
  const token = parseCookie(request.headers.get("cookie"), getSessionCookieName());
  const sessionUser = token ? await getSessionUser(token) : null;
  if (!sessionUser) {
    return {
      ok: false,
      user: null
    };
  }
  return {
    ok: true,
    user: sessionUser
  };
});
const searchUsers_createServerFn_handler = createServerRpc({
  id: "52b693a0d0986e1b88869bd1b2f3ad89e5d0066ab74e4dc3b53ff5f92fd9314a",
  name: "searchUsers",
  filename: "src/server/internal-api.ts"
}, (opts) => searchUsers.__executeServer(opts));
const searchUsers = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(searchUsers_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/users", {
    params: {
      query: {
        email: data?.email,
        tenantId: data?.tenantId,
        page: data?.page
      }
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  return payload ?? {
    data: []
  };
});
const getUser_createServerFn_handler = createServerRpc({
  id: "0f40640e3b35c0977bf78642588eb873c46fdfa614fe6b4a91a15d9d91bda51d",
  name: "getUser",
  filename: "src/server/internal-api.ts"
}, (opts) => getUser.__executeServer(opts));
const getUser = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(getUser_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/users/{userId}", {
    params: {
      path: {
        userId: data.userId
      }
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  return payload ?? {};
});
const startSupportAccess_createServerFn_handler = createServerRpc({
  id: "ef4489f82e4ef0ce219ae7a9b56b3b3c61fd9b842a7376232e9b8046f9afbdf6",
  name: "startSupportAccess",
  filename: "src/server/internal-api.ts"
}, (opts) => startSupportAccess.__executeServer(opts));
const startSupportAccess = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(startSupportAccess_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const duration = Math.max(60, Math.min(3600, data.duration ?? 900));
  const {
    data: payload,
    error,
    response
  } = await client.POST("/users/{userId}/impersonate", {
    params: {
      path: {
        userId: data.userId
      }
    },
    body: {
      tenantId: data.tenantId,
      duration,
      reason: data.reason
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  if (!payload?.token) {
    throw new Error("Support access token was not returned by internal API");
  }
  await appendAuditEvent({
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    action: "impersonation.start",
    detail: `tenant=${data.tenantId} user=${data.userId} reason=${data.reason}`,
    source: "ui"
  });
  return {
    token: payload.token,
    expiresAt: payload.expiresAt,
    tenantId: payload.tenantId ?? data.tenantId,
    userId: data.userId
  };
});
const getOwnershipStatus_createServerFn_handler = createServerRpc({
  id: "6d9490c0c432df4251a7d52485a35b448c5bff7b22fdb0771bd5580cf8ccd7d8",
  name: "getOwnershipStatus",
  filename: "src/server/internal-api.ts"
}, (opts) => getOwnershipStatus.__executeServer(opts));
const getOwnershipStatus = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(getOwnershipStatus_createServerFn_handler, async ({
  data
}) => {
  const owners = await getTenantOwnerLabels(data?.baseUrl);
  const ownedTenants = owners.filter((tenant) => tenant.ownerId === data.userId).map((tenant) => tenant.name);
  return {
    isOwner: ownedTenants.length > 0,
    isPrimaryOwner: ownedTenants.length > 0,
    canDelete: ownedTenants.length === 0,
    canTransfer: ownedTenants.length > 0,
    ownedTenants
  };
});
const canDeleteUser_createServerFn_handler = createServerRpc({
  id: "7273cb9ae21e0bb8f300e33243997012cf97c42bad0bf197c607d6b928aa4150",
  name: "canDeleteUser",
  filename: "src/server/internal-api.ts"
}, (opts) => canDeleteUser.__executeServer(opts));
const canDeleteUser = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(canDeleteUser_createServerFn_handler, async ({
  data
}) => {
  const owners = await getTenantOwnerLabels(data?.baseUrl);
  const ownedTenants = owners.filter((tenant) => tenant.ownerId === data.userId).map((tenant) => tenant.name);
  if (ownedTenants.length > 0) {
    return {
      canDelete: false,
      reason: "PRIMARY_OWNER",
      message: "This user owns one or more tenants. Transfer ownership before deleting this account.",
      ownedTenants
    };
  }
  return {
    canDelete: true,
    reason: null,
    message: null,
    ownedTenants: []
  };
});
const deleteUser_createServerFn_handler = createServerRpc({
  id: "54f8fdc888d08350069efc99121699c8efa87fb365dee638a76d1e2f59c57a1d",
  name: "deleteUser",
  filename: "src/server/internal-api.ts"
}, (opts) => deleteUser.__executeServer(opts));
const deleteUser = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(deleteUser_createServerFn_handler, async ({
  data
}) => {
  const apiKey = env.INTERNAL_API_KEY;
  const baseUrl = normalizeBaseUrl(data?.baseUrl);
  const response = await fetchWithRetry(`${baseUrl}/users/${data.userId}`, {
    method: "DELETE",
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (!response.ok) {
    const errorPayload = await response.json().catch(() => null);
    throw new Error(normalizeApiError(errorPayload, response));
  }
  await appendAuditEvent({
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    action: "user.delete",
    detail: `User ${data.userId} deleted`,
    source: "ui"
  });
  cache.clear();
  return {
    success: true
  };
});
const requestOwnershipTransfer_createServerFn_handler = createServerRpc({
  id: "4b8a4daffd0487a0d003502250d7dd39379b6b21051fb1c978158f903b409bf3",
  name: "requestOwnershipTransfer",
  filename: "src/server/internal-api.ts"
}, (opts) => requestOwnershipTransfer.__executeServer(opts));
const requestOwnershipTransfer = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(requestOwnershipTransfer_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = normalizeBaseUrl(data?.baseUrl);
  const response = await fetchWithRetry(`${baseUrl}/tenants/${encodeURIComponent(data.tenantId)}/ownership-transfers`, {
    method: "POST",
    headers: getInternalApiHeaders(),
    body: JSON.stringify({
      fromUserId: data.fromUserId,
      toUserId: data.toUserId
    })
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(normalizeApiError(payload, response));
  }
  await appendAuditEvent({
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    action: "ownership.transfer.request",
    detail: `tenant=${data.tenantId} from=${data.fromUserId} to=${data.toUserId}`,
    source: "ui"
  });
  return payload ?? {};
});
const acceptOwnershipTransfer_createServerFn_handler = createServerRpc({
  id: "dbd497d57b4769250296a5de412468c69252ee7f47bef6fb4858b229559deb1f",
  name: "acceptOwnershipTransfer",
  filename: "src/server/internal-api.ts"
}, (opts) => acceptOwnershipTransfer.__executeServer(opts));
const acceptOwnershipTransfer = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(acceptOwnershipTransfer_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = normalizeBaseUrl(data?.baseUrl);
  const response = await fetchWithRetry(`${baseUrl}/ownership-transfers/${encodeURIComponent(data.transferId)}`, {
    method: "POST",
    headers: getInternalApiHeaders(),
    body: JSON.stringify({
      accept: data.accept
    })
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(normalizeApiError(payload, response));
  }
  await appendAuditEvent({
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    action: data.accept ? "ownership.transfer.accept" : "ownership.transfer.reject",
    detail: `transfer=${data.transferId}`,
    source: "ui"
  });
  return payload ?? {};
});
const getOwnershipTransfers_createServerFn_handler = createServerRpc({
  id: "d98bf557f1dfc717daa594ce2281a4c9454d73de531aab0f763a0a4e437597eb",
  name: "getOwnershipTransfers",
  filename: "src/server/internal-api.ts"
}, (opts) => getOwnershipTransfers.__executeServer(opts));
const getOwnershipTransfers = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(getOwnershipTransfers_createServerFn_handler, async ({
  data
}) => {
  const query = new URLSearchParams();
  if (data.userId) query.set("userId", data.userId);
  if (data.tenantId) query.set("tenantId", data.tenantId);
  if (data.status) query.set("status", data.status);
  const baseUrl = normalizeBaseUrl(data?.baseUrl);
  const queryString = query.toString();
  const response = await fetchWithRetry(`${baseUrl}/ownership-transfers${queryString ? `?${queryString}` : ""}`, {
    method: "GET",
    headers: env.INTERNAL_API_KEY ? {
      "X-API-Key": env.INTERNAL_API_KEY
    } : void 0
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(normalizeApiError(payload, response));
  }
  return payload ?? {
    data: []
  };
});
const getTenantOwners_createServerFn_handler = createServerRpc({
  id: "1d8cf0c1f7ffb5c4c9d0ccfa63df3184a4f7c45be9c23383a462d2e42f27f19a",
  name: "getTenantOwners",
  filename: "src/server/internal-api.ts"
}, (opts) => getTenantOwners.__executeServer(opts));
const getTenantOwners = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(getTenantOwners_createServerFn_handler, async ({
  data
}) => {
  const client = getClient(data?.baseUrl);
  const apiKey = env.INTERNAL_API_KEY;
  const {
    data: payload,
    error,
    response
  } = await client.GET("/tenants/{tenantId}", {
    params: {
      path: {
        tenantId: data.tenantId
      }
    },
    headers: apiKey ? {
      "X-API-Key": apiKey
    } : void 0
  });
  if (error) {
    throw new Error(normalizeApiError(error, response));
  }
  const owner = payload?.owner;
  return {
    primaryOwner: owner?.id ? {
      userId: owner.id,
      name: owner.name ?? owner.email ?? owner.id,
      email: owner.email ?? ""
    } : null
  };
});
const recordAudit_createServerFn_handler = createServerRpc({
  id: "6bd180350339b5221bbb88c76c6a1013471b157f53c4e1c6d1b8129ba4ba6ab2",
  name: "recordAudit",
  filename: "src/server/internal-api.ts"
}, (opts) => recordAudit.__executeServer(opts));
const recordAudit = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(recordAudit_createServerFn_handler, async ({
  data
}) => {
  const event = {
    timestamp: data.timestamp ?? (/* @__PURE__ */ new Date()).toISOString(),
    action: data.action,
    detail: data.detail,
    source: "ui"
  };
  await appendAuditEvent(event);
  return {
    ok: true
  };
});
const listAudit_createServerFn_handler = createServerRpc({
  id: "6d352a760c71daf1174415b290eaab48a92bc397ed28ccf5771c2cf812599c50",
  name: "listAudit",
  filename: "src/server/internal-api.ts"
}, (opts) => listAudit.__executeServer(opts));
const listAudit = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(listAudit_createServerFn_handler, async ({
  data
}) => {
  const page = data?.page ?? 1;
  const perPage = data?.perPage ?? 50;
  const offset = (page - 1) * perPage;
  const {
    events,
    integrity
  } = await readAuditEvents({
    action: data?.action,
    since: data?.since,
    until: data?.until,
    limit: perPage,
    offset,
    sort: data?.sort
  });
  const total = await countAuditEvents({
    action: data?.action,
    since: data?.since,
    until: data?.until
  });
  return {
    data: events,
    pagination: {
      page,
      perPage,
      total,
      totalPages: Math.max(1, Math.ceil(total / perPage))
    },
    integrity
  };
});
const downloadAudit_createServerFn_handler = createServerRpc({
  id: "ab7f74ca296f30837046b9fdde3f12fdf7677a0d74b968ecbd5a87da248443ee",
  name: "downloadAudit",
  filename: "src/server/internal-api.ts"
}, (opts) => downloadAudit.__executeServer(opts));
const downloadAudit = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(downloadAudit_createServerFn_handler, async ({
  data
}) => {
  recordAuditExportRequest();
  try {
    const size = await auditFileSize();
    const shouldStream = size > 5e5 && data?.sort !== "desc";
    if (shouldStream) {
      const stream = await streamAuditCsv({
        action: data?.action,
        since: data?.since,
        until: data?.until,
        onBytes: recordAuditExportBytes
      });
      const webStream = Readable.toWeb(stream);
      return new Response(webStream, {
        headers: {
          "Content-Type": "text/csv"
        }
      });
    }
    const {
      events
    } = await readAuditEvents({
      action: data?.action,
      since: data?.since,
      until: data?.until,
      sort: data?.sort
    });
    const header = "timestamp,action,detail,source,seq,valid\n";
    const body = events.map((event) => [event.timestamp, event.action, event.detail, event.source ?? "", event.seq ?? "", event.valid ? "true" : "false"].map((value) => `"${String(value ?? "").replace(/"/g, '""')}"`).join(",")).join("\n");
    const csv = header + body;
    if (csv.length > 5e4) {
      const gz = gzipSync(csv);
      recordAuditExportBytes(gz.byteLength);
      return new Response(gz, {
        headers: {
          "Content-Type": "text/csv",
          "Content-Encoding": "gzip"
        }
      });
    }
    recordAuditExportBytes(Buffer.byteLength(csv));
    return csv;
  } catch (err) {
    recordAuditExportError();
    throw err;
  }
});
export {
  acceptOwnershipTransfer_createServerFn_handler,
  activateTenant_createServerFn_handler,
  canDeleteUser_createServerFn_handler,
  createApiKey_createServerFn_handler,
  createRole_createServerFn_handler,
  createTenant_createServerFn_handler,
  deleteApiKey_createServerFn_handler,
  deleteTenant_createServerFn_handler,
  deleteUser_createServerFn_handler,
  downloadAudit_createServerFn_handler,
  generateInvoice_createServerFn_handler,
  getOrganization_createServerFn_handler,
  getOwnershipStatus_createServerFn_handler,
  getOwnershipTransfers_createServerFn_handler,
  getPlatformOverview_createServerFn_handler,
  getServerStatus_createServerFn_handler,
  getSubscription_createServerFn_handler,
  getTenantAnalytics_createServerFn_handler,
  getTenantDetail_createServerFn_handler,
  getTenantOwners_createServerFn_handler,
  getUiConfig_createServerFn_handler,
  getUiSessionStatus_createServerFn_handler,
  getUsageAnalytics_createServerFn_handler,
  getUser_createServerFn_handler,
  listApiKeys_createServerFn_handler,
  listAudit_createServerFn_handler,
  listFeatureFlags_createServerFn_handler,
  listNotifications_createServerFn_handler,
  listOrganizationMembers_createServerFn_handler,
  listOrganizations_createServerFn_handler,
  listPlatformInvoices_createServerFn_handler,
  listRoles_createServerFn_handler,
  listServiceStatus_createServerFn_handler,
  listSubscriptions_createServerFn_handler,
  listSupportIncidents_createServerFn_handler,
  listSupportTickets_createServerFn_handler,
  listTenants_createServerFn_handler,
  loginUi_createServerFn_handler,
  logoutUi_createServerFn_handler,
  markNotificationsRead_createServerFn_handler,
  migrateTenant_createServerFn_handler,
  recordAudit_createServerFn_handler,
  requestOwnershipTransfer_createServerFn_handler,
  searchUsers_createServerFn_handler,
  startSupportAccess_createServerFn_handler,
  suspendTenant_createServerFn_handler,
  updateFeatureFlag_createServerFn_handler,
  updateRole_createServerFn_handler,
  updateSubscription_createServerFn_handler,
  updateTenant_createServerFn_handler
};
