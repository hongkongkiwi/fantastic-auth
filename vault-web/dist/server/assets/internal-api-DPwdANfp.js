import { c as createServerRpc } from "./createServerRpc-Bd3B-Ah9.js";
import { c as createServerFn, a as getRequest } from "../server.js";
import { a as authMiddleware, b as assertAuthConfigured, s as serverLogger } from "./auth-middleware-CUT-Ooy9.js";
import { promises, createReadStream } from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { Readable, Transform } from "node:stream";
import crypto from "node:crypto";
import { e as env, c as createSession, g as getSessionCookieName, a as getSessionTtlSeconds, p as parseCookie, r as revokeSession } from "./server-DL57AnWM.js";
import { gzipSync } from "node:zlib";
import createClient from "openapi-fetch";
import "@tanstack/history";
import "@tanstack/router-core/ssr/client";
import "@tanstack/router-core";
import "node:async_hooks";
import "@tanstack/router-core/ssr/server";
import "h3-v2";
import "tiny-invariant";
import "seroval";
import "react/jsx-runtime";
import "@tanstack/react-router/ssr/server";
import "@tanstack/react-router";
import "@t3-oss/env-core";
import "zod";
const AUDIT_DIR = path.join(process.cwd(), ".data");
const AUDIT_FILE = path.join(AUDIT_DIR, "audit.log");
const AUDIT_HASH_VERSION = 1;
const GENESIS_HASH = "genesis";
const AUDIT_STORAGE = env.INTERNAL_UI_AUDIT_STORAGE || "file";
const ensureAuditFile = async () => {
  if (AUDIT_STORAGE !== "file") {
    const { serverLogger: serverLogger2 } = await import("./auth-middleware-CUT-Ooy9.js").then((n) => n.c);
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
const createInternalClient = (baseUrl) => createClient({
  baseUrl,
  fetch: (input) => fetchWithRetry(input)
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
const requireUiToken = (data) => {
  const requiredToken = env.INTERNAL_UI_TOKEN;
  if (!requiredToken) return;
  if (!data?.uiToken || data.uiToken !== requiredToken) {
    throw new Error("Invalid internal UI token");
  }
};
const mockOwnershipData = {
  "user-1": {
    primaryOwnedTenants: ["tenant-1", "tenant-2"],
    ownedTenants: ["tenant-1", "tenant-2", "tenant-3"]
  },
  "user-2": {
    primaryOwnedTenants: ["tenant-3"],
    ownedTenants: ["tenant-3"]
  }
};
const mockTransferRequests = [];
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
  requireUiToken(data);
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
  requireUiToken(data);
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
  requireUiToken(data);
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
  requireUiToken(data);
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
  requireUiToken(data);
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
  requireUiToken(data);
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
  requireUiToken(data);
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
  requireUiToken(data);
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
  requireUiToken(data);
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
  requireUiToken(data);
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
  requireUiToken(data);
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
  requireUiToken(data);
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
  requireUiToken(data);
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
}).inputValidator((input) => input).handler(getServerStatus_createServerFn_handler, async () => {
  assertAuthConfigured();
  return {
    hasApiKey: Boolean(env.INTERNAL_API_KEY),
    hasUiToken: Boolean(env.INTERNAL_UI_TOKEN),
    hasUiPassword: Boolean(env.INTERNAL_UI_PASSWORD),
    defaultBaseUrl: env.INTERNAL_API_BASE_URL || DEFAULT_BASE_URL
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
  const requiredPassword = env.INTERNAL_UI_PASSWORD;
  if (!requiredPassword) {
    throw new Error("UI password not configured");
  }
  if (!data?.password || data.password !== requiredPassword) {
    throw new Error("Invalid UI password");
  }
  const session = createSession();
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
    revokeSession(token);
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
}).middleware([authMiddleware]).handler(getUiSessionStatus_createServerFn_handler, async () => ({
  ok: true
}));
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
  requireUiToken(data);
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
  requireUiToken(data);
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
  requireUiToken(data);
  const ownership = mockOwnershipData[data.userId] || {
    primaryOwnedTenants: [],
    ownedTenants: []
  };
  const status = {
    isOwner: ownership.ownedTenants.length > 0,
    isPrimaryOwner: ownership.primaryOwnedTenants.length > 0,
    canDelete: ownership.primaryOwnedTenants.length === 0,
    canTransfer: ownership.primaryOwnedTenants.length > 0,
    ownedTenants: ownership.ownedTenants
  };
  return status;
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
  requireUiToken(data);
  const ownership = mockOwnershipData[data.userId] || {
    primaryOwnedTenants: []
  };
  if (ownership.primaryOwnedTenants.length > 0) {
    return {
      canDelete: false,
      reason: "PRIMARY_OWNER",
      message: `Cannot delete account. You are the primary owner of ${ownership.primaryOwnedTenants.length} tenant(s). Please transfer ownership first.`,
      ownedTenants: ownership.primaryOwnedTenants
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
  requireUiToken(data);
  const ownership = mockOwnershipData[data.userId];
  if (ownership && ownership.primaryOwnedTenants.length > 0) {
    throw new Error(`Cannot delete user: Primary owner of ${ownership.primaryOwnedTenants.length} tenant(s). Transfer ownership first.`);
  }
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
  requireUiToken(data);
  const ownership = mockOwnershipData[data.fromUserId];
  if (!ownership || !ownership.primaryOwnedTenants.includes(data.tenantId)) {
    throw new Error("Only the primary owner can transfer ownership");
  }
  const transferRequest = {
    id: `transfer-${Date.now()}`,
    tenantId: data.tenantId,
    tenantName: "Tenant Name",
    // Would fetch from DB
    fromUserId: data.fromUserId,
    fromUserName: "Current Owner",
    // Would fetch from DB
    toUserId: data.toUserId,
    toUserName: "New Owner",
    // Would fetch from DB
    toUserEmail: "new@owner.com",
    // Would fetch from DB
    status: "pending",
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1e3).toISOString()
    // 7 days
  };
  mockTransferRequests.push(transferRequest);
  await appendAuditEvent({
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    action: "ownership.transfer.request",
    detail: `Ownership transfer requested for tenant ${data.tenantId} from ${data.fromUserId} to ${data.toUserId}`,
    source: "ui"
  });
  return transferRequest;
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
  requireUiToken(data);
  const transfer = mockTransferRequests.find((t) => t.id === data.transferId);
  if (!transfer) {
    throw new Error("Transfer request not found");
  }
  if (transfer.status !== "pending") {
    throw new Error(`Transfer request is already ${transfer.status}`);
  }
  if (new Date(transfer.expiresAt) < /* @__PURE__ */ new Date()) {
    transfer.status = "expired";
    throw new Error("Transfer request has expired");
  }
  transfer.status = data.accept ? "accepted" : "rejected";
  if (data.accept) {
    const fromOwnership = mockOwnershipData[transfer.fromUserId];
    const toOwnership = mockOwnershipData[transfer.toUserId] || {
      primaryOwnedTenants: [],
      ownedTenants: []
    };
    if (fromOwnership) {
      fromOwnership.primaryOwnedTenants = fromOwnership.primaryOwnedTenants.filter((id) => id !== transfer.tenantId);
      fromOwnership.ownedTenants = fromOwnership.ownedTenants.filter((id) => id !== transfer.tenantId);
    }
    toOwnership.primaryOwnedTenants.push(transfer.tenantId);
    toOwnership.ownedTenants.push(transfer.tenantId);
    mockOwnershipData[transfer.toUserId] = toOwnership;
  }
  await appendAuditEvent({
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    action: data.accept ? "ownership.transfer.accept" : "ownership.transfer.reject",
    detail: `Ownership transfer ${data.accept ? "accepted" : "rejected"} for tenant ${transfer.tenantId}`,
    source: "ui"
  });
  return transfer;
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
  requireUiToken(data);
  let transfers = mockTransferRequests;
  if (data.userId) {
    transfers = transfers.filter((t) => t.fromUserId === data.userId || t.toUserId === data.userId);
  }
  if (data.tenantId) {
    transfers = transfers.filter((t) => t.tenantId === data.tenantId);
  }
  if (data.status) {
    transfers = transfers.filter((t) => t.status === data.status);
  }
  return {
    data: transfers
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
  requireUiToken(data);
  let primaryOwner = null;
  for (const [userId, ownership] of Object.entries(mockOwnershipData)) {
    if (ownership.primaryOwnedTenants.includes(data.tenantId)) {
      primaryOwner = {
        userId,
        name: "Owner Name",
        // Would fetch from DB
        email: "owner@example.com"
        // Would fetch from DB
      };
      break;
    }
  }
  return {
    primaryOwner
    // Would also return other owners/admins
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
  requireUiToken(data);
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
  requireUiToken(data);
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
  requireUiToken(data);
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
  createTenant_createServerFn_handler,
  deleteTenant_createServerFn_handler,
  deleteUser_createServerFn_handler,
  downloadAudit_createServerFn_handler,
  generateInvoice_createServerFn_handler,
  getOwnershipStatus_createServerFn_handler,
  getOwnershipTransfers_createServerFn_handler,
  getPlatformOverview_createServerFn_handler,
  getServerStatus_createServerFn_handler,
  getSubscription_createServerFn_handler,
  getTenantDetail_createServerFn_handler,
  getTenantOwners_createServerFn_handler,
  getUiConfig_createServerFn_handler,
  getUiSessionStatus_createServerFn_handler,
  getUser_createServerFn_handler,
  listAudit_createServerFn_handler,
  listSubscriptions_createServerFn_handler,
  listTenants_createServerFn_handler,
  loginUi_createServerFn_handler,
  logoutUi_createServerFn_handler,
  migrateTenant_createServerFn_handler,
  recordAudit_createServerFn_handler,
  requestOwnershipTransfer_createServerFn_handler,
  searchUsers_createServerFn_handler,
  suspendTenant_createServerFn_handler,
  updateSubscription_createServerFn_handler,
  updateTenant_createServerFn_handler
};
