import { jsx } from "react/jsx-runtime";
import { createMemoryHistory } from "@tanstack/history";
import { mergeHeaders } from "@tanstack/router-core/ssr/client";
import { parseRedirect, isRedirect, defaultSerovalPlugins, makeSerovalPlugin, rootRouteId, createRawStreamRPCPlugin, isNotFound, createSerializationAdapter, isResolvedRedirect, executeRewriteInput } from "@tanstack/router-core";
import { AsyncLocalStorage } from "node:async_hooks";
import { getNormalizedURL, getOrigin, attachRouterServerSsrUtils } from "@tanstack/router-core/ssr/server";
import { H3Event, toResponse } from "h3-v2";
import invariant from "tiny-invariant";
import { toCrossJSONStream, fromJSON, toCrossJSONAsync } from "seroval";
import { defineHandlerCallback, renderRouterToStream } from "@tanstack/react-router/ssr/server";
import { RouterProvider, useRouter, isRedirect as isRedirect$1 } from "@tanstack/react-router";
import * as React from "react";
function StartServer(props) {
  return /* @__PURE__ */ jsx(RouterProvider, { router: props.router });
}
const defaultStreamHandler = defineHandlerCallback(
  ({ request, router, responseHeaders }) => renderRouterToStream({
    request,
    router,
    responseHeaders,
    children: /* @__PURE__ */ jsx(StartServer, { router })
  })
);
const TSS_FORMDATA_CONTEXT = "__TSS_CONTEXT";
const TSS_SERVER_FUNCTION = /* @__PURE__ */ Symbol.for("TSS_SERVER_FUNCTION");
const TSS_SERVER_FUNCTION_FACTORY = /* @__PURE__ */ Symbol.for(
  "TSS_SERVER_FUNCTION_FACTORY"
);
const X_TSS_SERIALIZED = "x-tss-serialized";
const X_TSS_RAW_RESPONSE = "x-tss-raw";
const TSS_CONTENT_TYPE_FRAMED = "application/x-tss-framed";
const FrameType = {
  /** Seroval JSON chunk (NDJSON line) */
  JSON: 0,
  /** Raw stream data chunk */
  CHUNK: 1,
  /** Raw stream end (EOF) */
  END: 2,
  /** Raw stream error */
  ERROR: 3
};
const FRAME_HEADER_SIZE = 9;
const TSS_FRAMED_PROTOCOL_VERSION = 1;
const TSS_CONTENT_TYPE_FRAMED_VERSIONED = `${TSS_CONTENT_TYPE_FRAMED}; v=${TSS_FRAMED_PROTOCOL_VERSION}`;
const GLOBAL_STORAGE_KEY = /* @__PURE__ */ Symbol.for("tanstack-start:start-storage-context");
const globalObj$2 = globalThis;
if (!globalObj$2[GLOBAL_STORAGE_KEY]) {
  globalObj$2[GLOBAL_STORAGE_KEY] = new AsyncLocalStorage();
}
const startStorage = globalObj$2[GLOBAL_STORAGE_KEY];
async function runWithStartContext(context, fn) {
  return startStorage.run(context, fn);
}
function getStartContext(opts) {
  const context = startStorage.getStore();
  if (!context && opts?.throwIfNotFound !== false) {
    throw new Error(
      `No Start context found in AsyncLocalStorage. Make sure you are using the function within the server runtime.`
    );
  }
  return context;
}
const getStartOptions = () => getStartContext().startOptions;
const getStartContextServerOnly = getStartContext;
function isSafeKey(key) {
  return key !== "__proto__" && key !== "constructor" && key !== "prototype";
}
function safeObjectMerge(target, source) {
  const result = /* @__PURE__ */ Object.create(null);
  if (target) {
    for (const key of Object.keys(target)) {
      if (isSafeKey(key)) result[key] = target[key];
    }
  }
  if (source && typeof source === "object") {
    for (const key of Object.keys(source)) {
      if (isSafeKey(key)) result[key] = source[key];
    }
  }
  return result;
}
function createNullProtoObject(source) {
  if (!source) return /* @__PURE__ */ Object.create(null);
  const obj = /* @__PURE__ */ Object.create(null);
  for (const key of Object.keys(source)) {
    if (isSafeKey(key)) obj[key] = source[key];
  }
  return obj;
}
const createServerFn = (options, __opts) => {
  const resolvedOptions = __opts || options || {};
  if (typeof resolvedOptions.method === "undefined") {
    resolvedOptions.method = "GET";
  }
  const res = {
    options: resolvedOptions,
    middleware: (middleware) => {
      const newMiddleware = [...resolvedOptions.middleware || []];
      middleware.map((m) => {
        if (TSS_SERVER_FUNCTION_FACTORY in m) {
          if (m.options.middleware) {
            newMiddleware.push(...m.options.middleware);
          }
        } else {
          newMiddleware.push(m);
        }
      });
      const newOptions = {
        ...resolvedOptions,
        middleware: newMiddleware
      };
      const res2 = createServerFn(void 0, newOptions);
      res2[TSS_SERVER_FUNCTION_FACTORY] = true;
      return res2;
    },
    inputValidator: (inputValidator) => {
      const newOptions = { ...resolvedOptions, inputValidator };
      return createServerFn(void 0, newOptions);
    },
    handler: (...args) => {
      const [extractedFn, serverFn] = args;
      const newOptions = { ...resolvedOptions, extractedFn, serverFn };
      const resolvedMiddleware = [
        ...newOptions.middleware || [],
        serverFnBaseToMiddleware(newOptions)
      ];
      return Object.assign(
        async (opts) => {
          const result = await executeMiddleware$1(resolvedMiddleware, "client", {
            ...extractedFn,
            ...newOptions,
            data: opts?.data,
            headers: opts?.headers,
            signal: opts?.signal,
            fetch: opts?.fetch,
            context: createNullProtoObject()
          });
          const redirect = parseRedirect(result.error);
          if (redirect) {
            throw redirect;
          }
          if (result.error) throw result.error;
          return result.result;
        },
        {
          // This copies over the URL, function ID
          ...extractedFn,
          // The extracted function on the server-side calls
          // this function
          __executeServer: async (opts) => {
            const startContext = getStartContextServerOnly();
            const serverContextAfterGlobalMiddlewares = startContext.contextAfterGlobalMiddlewares;
            const ctx = {
              ...extractedFn,
              ...opts,
              // Ensure we use the full serverFnMeta from the provider file's extractedFn
              // (which has id, name, filename) rather than the partial one from SSR/client
              // callers (which only has id)
              serverFnMeta: extractedFn.serverFnMeta,
              // Use safeObjectMerge for opts.context which comes from client
              context: safeObjectMerge(
                serverContextAfterGlobalMiddlewares,
                opts.context
              ),
              request: startContext.request
            };
            const result = await executeMiddleware$1(
              resolvedMiddleware,
              "server",
              ctx
            ).then((d) => ({
              // Only send the result and sendContext back to the client
              result: d.result,
              error: d.error,
              context: d.sendContext
            }));
            return result;
          }
        }
      );
    }
  };
  const fun = (options2) => {
    const newOptions = {
      ...resolvedOptions,
      ...options2
    };
    return createServerFn(void 0, newOptions);
  };
  return Object.assign(fun, res);
};
async function executeMiddleware$1(middlewares, env, opts) {
  const globalMiddlewares = getStartOptions()?.functionMiddleware || [];
  let flattenedMiddlewares = flattenMiddlewares([
    ...globalMiddlewares,
    ...middlewares
  ]);
  if (env === "server") {
    const startContext = getStartContextServerOnly({ throwIfNotFound: false });
    if (startContext?.executedRequestMiddlewares) {
      flattenedMiddlewares = flattenedMiddlewares.filter(
        (m) => !startContext.executedRequestMiddlewares.has(m)
      );
    }
  }
  const callNextMiddleware = async (ctx) => {
    const nextMiddleware = flattenedMiddlewares.shift();
    if (!nextMiddleware) {
      return ctx;
    }
    try {
      if ("inputValidator" in nextMiddleware.options && nextMiddleware.options.inputValidator && env === "server") {
        ctx.data = await execValidator(
          nextMiddleware.options.inputValidator,
          ctx.data
        );
      }
      let middlewareFn = void 0;
      if (env === "client") {
        if ("client" in nextMiddleware.options) {
          middlewareFn = nextMiddleware.options.client;
        }
      } else if ("server" in nextMiddleware.options) {
        middlewareFn = nextMiddleware.options.server;
      }
      if (middlewareFn) {
        const userNext = async (userCtx = {}) => {
          const nextCtx = {
            ...ctx,
            ...userCtx,
            context: safeObjectMerge(ctx.context, userCtx.context),
            sendContext: safeObjectMerge(ctx.sendContext, userCtx.sendContext),
            headers: mergeHeaders(ctx.headers, userCtx.headers),
            _callSiteFetch: ctx._callSiteFetch,
            fetch: ctx._callSiteFetch ?? userCtx.fetch ?? ctx.fetch,
            result: userCtx.result !== void 0 ? userCtx.result : userCtx instanceof Response ? userCtx : ctx.result,
            error: userCtx.error ?? ctx.error
          };
          const result2 = await callNextMiddleware(nextCtx);
          if (result2.error) {
            throw result2.error;
          }
          return result2;
        };
        const result = await middlewareFn({
          ...ctx,
          next: userNext
        });
        if (isRedirect(result)) {
          return {
            ...ctx,
            error: result
          };
        }
        if (result instanceof Response) {
          return {
            ...ctx,
            result
          };
        }
        if (!result) {
          throw new Error(
            "User middleware returned undefined. You must call next() or return a result in your middlewares."
          );
        }
        return result;
      }
      return callNextMiddleware(ctx);
    } catch (error) {
      return {
        ...ctx,
        error
      };
    }
  };
  return callNextMiddleware({
    ...opts,
    headers: opts.headers || {},
    sendContext: opts.sendContext || {},
    context: opts.context || createNullProtoObject(),
    _callSiteFetch: opts.fetch
  });
}
function flattenMiddlewares(middlewares, maxDepth = 100) {
  const seen = /* @__PURE__ */ new Set();
  const flattened = [];
  const recurse = (middleware, depth) => {
    if (depth > maxDepth) {
      throw new Error(
        `Middleware nesting depth exceeded maximum of ${maxDepth}. Check for circular references.`
      );
    }
    middleware.forEach((m) => {
      if (m.options.middleware) {
        recurse(m.options.middleware, depth + 1);
      }
      if (!seen.has(m)) {
        seen.add(m);
        flattened.push(m);
      }
    });
  };
  recurse(middlewares, 0);
  return flattened;
}
async function execValidator(validator, input) {
  if (validator == null) return {};
  if ("~standard" in validator) {
    const result = await validator["~standard"].validate(input);
    if (result.issues)
      throw new Error(JSON.stringify(result.issues, void 0, 2));
    return result.value;
  }
  if ("parse" in validator) {
    return validator.parse(input);
  }
  if (typeof validator === "function") {
    return validator(input);
  }
  throw new Error("Invalid validator type!");
}
function serverFnBaseToMiddleware(options) {
  return {
    "~types": void 0,
    options: {
      inputValidator: options.inputValidator,
      client: async ({ next, sendContext, fetch: fetch2, ...ctx }) => {
        const payload = {
          ...ctx,
          // switch the sendContext over to context
          context: sendContext,
          fetch: fetch2
        };
        const res = await options.extractedFn?.(payload);
        return next(res);
      },
      server: async ({ next, ...ctx }) => {
        const result = await options.serverFn?.(ctx);
        return next({
          ...ctx,
          result
        });
      }
    }
  };
}
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
    server: (server2) => {
      return createMiddleware(
        {},
        Object.assign(resolvedOptions, { server: server2 })
      );
    }
  };
};
function getDefaultSerovalPlugins() {
  const start2 = getStartOptions();
  const adapters = start2?.serializationAdapters;
  return [
    ...adapters?.map(makeSerovalPlugin) ?? [],
    ...defaultSerovalPlugins
  ];
}
const GLOBAL_EVENT_STORAGE_KEY$1 = /* @__PURE__ */ Symbol.for("tanstack-start:event-storage");
const globalObj$1 = globalThis;
if (!globalObj$1[GLOBAL_EVENT_STORAGE_KEY$1]) {
  globalObj$1[GLOBAL_EVENT_STORAGE_KEY$1] = new AsyncLocalStorage();
}
const eventStorage$1 = globalObj$1[GLOBAL_EVENT_STORAGE_KEY$1];
function isPromiseLike(value) {
  return typeof value.then === "function";
}
function getSetCookieValues(headers) {
  const headersWithSetCookie = headers;
  if (typeof headersWithSetCookie.getSetCookie === "function") {
    return headersWithSetCookie.getSetCookie();
  }
  const value = headers.get("set-cookie");
  return value ? [value] : [];
}
function mergeEventResponseHeaders(response, event) {
  if (response.ok) {
    return;
  }
  const eventSetCookies = getSetCookieValues(event.res.headers);
  if (eventSetCookies.length === 0) {
    return;
  }
  const responseSetCookies = getSetCookieValues(response.headers);
  response.headers.delete("set-cookie");
  for (const cookie of responseSetCookies) {
    response.headers.append("set-cookie", cookie);
  }
  for (const cookie of eventSetCookies) {
    response.headers.append("set-cookie", cookie);
  }
}
function attachResponseHeaders(value, event) {
  if (isPromiseLike(value)) {
    return value.then((resolved) => {
      if (resolved instanceof Response) {
        mergeEventResponseHeaders(resolved, event);
      }
      return resolved;
    });
  }
  if (value instanceof Response) {
    mergeEventResponseHeaders(value, event);
  }
  return value;
}
function requestHandler(handler) {
  return (request, requestOpts) => {
    const h3Event = new H3Event(request);
    const response = eventStorage$1.run(
      { h3Event },
      () => handler(request, requestOpts)
    );
    return toResponse(attachResponseHeaders(response, h3Event), h3Event);
  };
}
function getH3Event$1() {
  const event = eventStorage$1.getStore();
  if (!event) {
    throw new Error(
      `No StartEvent found in AsyncLocalStorage. Make sure you are using the function within the server runtime.`
    );
  }
  return event.h3Event;
}
function getResponse() {
  const event = getH3Event$1();
  return event.res;
}
async function getStartManifest(matchedRoutes) {
  const { tsrStartManifest } = await import("./assets/_tanstack-start-manifest_v-BNSE_xTD.js");
  const startManifest = tsrStartManifest();
  const rootRoute = startManifest.routes[rootRouteId] = startManifest.routes[rootRouteId] || {};
  rootRoute.assets = rootRoute.assets || [];
  let injectedHeadScripts;
  const manifest2 = {
    routes: Object.fromEntries(
      Object.entries(startManifest.routes).flatMap(([k, v]) => {
        const result = {};
        let hasData = false;
        if (v.preloads && v.preloads.length > 0) {
          result["preloads"] = v.preloads;
          hasData = true;
        }
        if (v.assets && v.assets.length > 0) {
          result["assets"] = v.assets;
          hasData = true;
        }
        if (!hasData) {
          return [];
        }
        return [[k, result]];
      })
    )
  };
  return {
    manifest: manifest2,
    clientEntry: startManifest.clientEntry,
    injectedHeadScripts
  };
}
const textEncoder$1 = new TextEncoder();
const EMPTY_PAYLOAD = new Uint8Array(0);
function encodeFrame(type, streamId, payload) {
  const frame = new Uint8Array(FRAME_HEADER_SIZE + payload.length);
  frame[0] = type;
  frame[1] = streamId >>> 24 & 255;
  frame[2] = streamId >>> 16 & 255;
  frame[3] = streamId >>> 8 & 255;
  frame[4] = streamId & 255;
  frame[5] = payload.length >>> 24 & 255;
  frame[6] = payload.length >>> 16 & 255;
  frame[7] = payload.length >>> 8 & 255;
  frame[8] = payload.length & 255;
  frame.set(payload, FRAME_HEADER_SIZE);
  return frame;
}
function encodeJSONFrame(json) {
  return encodeFrame(FrameType.JSON, 0, textEncoder$1.encode(json));
}
function encodeChunkFrame(streamId, chunk) {
  return encodeFrame(FrameType.CHUNK, streamId, chunk);
}
function encodeEndFrame(streamId) {
  return encodeFrame(FrameType.END, streamId, EMPTY_PAYLOAD);
}
function encodeErrorFrame(streamId, error) {
  const message = error instanceof Error ? error.message : String(error ?? "Unknown error");
  return encodeFrame(FrameType.ERROR, streamId, textEncoder$1.encode(message));
}
function createMultiplexedStream(jsonStream, rawStreams) {
  let activePumps = 1 + rawStreams.size;
  let controllerRef = null;
  let cancelled = false;
  const cancelReaders = [];
  const safeEnqueue = (chunk) => {
    if (cancelled || !controllerRef) return;
    try {
      controllerRef.enqueue(chunk);
    } catch {
    }
  };
  const safeError = (err) => {
    if (cancelled || !controllerRef) return;
    try {
      controllerRef.error(err);
    } catch {
    }
  };
  const safeClose = () => {
    if (cancelled || !controllerRef) return;
    try {
      controllerRef.close();
    } catch {
    }
  };
  const checkComplete = () => {
    activePumps--;
    if (activePumps === 0) {
      safeClose();
    }
  };
  return new ReadableStream({
    start(controller) {
      controllerRef = controller;
      cancelReaders.length = 0;
      const pumpJSON = async () => {
        const reader = jsonStream.getReader();
        cancelReaders.push(() => {
          reader.cancel().catch(() => {
          });
        });
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (cancelled) break;
            if (done) break;
            safeEnqueue(encodeJSONFrame(value));
          }
        } catch (error) {
          safeError(error);
        } finally {
          reader.releaseLock();
          checkComplete();
        }
      };
      const pumpRawStream = async (streamId, stream) => {
        const reader = stream.getReader();
        cancelReaders.push(() => {
          reader.cancel().catch(() => {
          });
        });
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (cancelled) break;
            if (done) {
              safeEnqueue(encodeEndFrame(streamId));
              break;
            }
            safeEnqueue(encodeChunkFrame(streamId, value));
          }
        } catch (error) {
          safeEnqueue(encodeErrorFrame(streamId, error));
        } finally {
          reader.releaseLock();
          checkComplete();
        }
      };
      pumpJSON();
      for (const [streamId, stream] of rawStreams) {
        pumpRawStream(streamId, stream);
      }
    },
    cancel() {
      cancelled = true;
      controllerRef = null;
      for (const cancelReader of cancelReaders) {
        cancelReader();
      }
      cancelReaders.length = 0;
    }
  });
}
const manifest = { "911819bcdb0ac36df37529995fbcc19319f1c13d411900322765b0b4689b6866": {
  functionName: "getUiConfig_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "7d1a3f2af301fa41e490368f34e8f8ae0e023376272e5b7ac61e60058bac7fc8": {
  functionName: "listTenants_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "c17ddf115d90cefc85f473daf8f20cdfdd867d5d820175d0b75dec148a580824": {
  functionName: "listSubscriptions_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "dc593bf19a58f90a9ef7d91fc3ff660548f04d725398ce4e2b726ba87ed08215": {
  functionName: "createTenant_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "c033dd462548d27447f8832a9453c6309e8118540920eeedf3890d19468800e1": {
  functionName: "getTenantDetail_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "a622107254c770bdbd2e7ecb7020f047b0e88c3cb653041ff9dce5d41d892c9a": {
  functionName: "updateSubscription_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "b33359e75789a3827c72557916ba7a42a77edc25f32840131f88b83d62bbba40": {
  functionName: "getPlatformOverview_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "6e790c4843fa64087b09ea889d35fd2e8cdc0528e5b11a3c7e5f4662d874e863": {
  functionName: "getUsageAnalytics_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "5aba7518da0ee86bc4b21f1387f4ef7ef67de6189c9bf000d68952120cbb0b67": {
  functionName: "getTenantAnalytics_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "2d1974e77be9521065178bba432c7ee8a925d552f6a5f0276a6d638df8be4e3a": {
  functionName: "listFeatureFlags_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "e815b707c6424f3284f4beb7f77f61b1b488727e9d69ed5ad25eb3991d841dab": {
  functionName: "updateFeatureFlag_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "f64805bca92b126ddfe2186a93600233eb5dac7711eeeedf9005a6d6d152f545": {
  functionName: "listOrganizations_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "57ae7773025d2d02b9b4d337bf0f49633e23f9d9f49d2556ec828780ee4784ae": {
  functionName: "getOrganization_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "cce320e10e1a8e65e57e2a6b3f3beadb719dd70297c52668726fc81ef5ff743d": {
  functionName: "listOrganizationMembers_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "94db58d8167408f3279f7071fedc83f32279d5a2f1b067913bbebfddd43f95ea": {
  functionName: "listRoles_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "caf715d889b2bc776f8384bd2e654c78eed939be8bffaeb36475f57e3b604c74": {
  functionName: "createRole_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "4c8adbf2bdd9a5eed2f49d44acb7e4c32832d8a6a5a5c570d514360807da981d": {
  functionName: "updateRole_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "4f6ae767327a0a1bea64094162ea2025b3ffbad335386eaf6786cd234d8abfbc": {
  functionName: "listApiKeys_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "396af684ee9b727d29a146d6c5a4aeddc6acb2e5a8cb1554b324756d218cf816": {
  functionName: "createApiKey_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "11393555b2981f30bac815a3639e326fc9d92a779e6f704fa01896197e6a2385": {
  functionName: "deleteApiKey_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "bd0dd0a37253ba5c75a0fe75533ebfe5dc5882902a083a90829941a4285551f7": {
  functionName: "listNotifications_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "d2a3ef54ab9d79e273211fd40725d3f56959510c1d1f8b5dee6a1dbfb61a3cdd": {
  functionName: "markNotificationsRead_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "13e11b3b84a0ce0a939c985ef8c9ddab2d51685946b03864fbe985841da9bf4e": {
  functionName: "listSupportTickets_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "34bc7b65748fbdc2a5b7a3f9d8c53f227faf65c469130d4ea732c4c2fc7d3d70": {
  functionName: "listSupportIncidents_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "e371a416bea511d55a8582ecc0694c224f1a9ad7d9045f37943f920ebb431039": {
  functionName: "listServiceStatus_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "5712a129ee0706a23bdfae0ed0e8a7ae984787e2e35da1aa75c73801a2f204bd": {
  functionName: "listPlatformInvoices_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "77e5f5691ce2dd50a3ce2eeebaa0957eacbc8916d5276f38090ff1db9835ef4f": {
  functionName: "updateTenant_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "1f0cb82e8b0fdf3f27529d6d0650e6a5afd677f7094ac88451fa184d0fc32a5c": {
  functionName: "suspendTenant_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "06e1013355e060cedec5dc139f3bc60dace737992ee136c376dcc772e9288476": {
  functionName: "activateTenant_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "8253edfece41c96365eedab52199fc01ee193962b935f88fc3178f10d3f47220": {
  functionName: "generateInvoice_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "3f953bf1783c56e47338ca1a36de00c411a55923561ecb1c21c8509ab79914e0": {
  functionName: "deleteTenant_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "900a121f7b0003a30714380df8a7cb4ea9927fda9130796bec5b0981533898f7": {
  functionName: "migrateTenant_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "bd68d543ffba4fce418155a90da2d6283713bf27a3bb77bfc11e2b373fdd8150": {
  functionName: "getSubscription_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "a22e95df85e1fd83c6049d7e397debc0eaa965fc4a65df8650d7f990655e2f0e": {
  functionName: "getServerStatus_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "bd6fedde815c5158f58327da98a5cc46dd2a9ce1c6d90216a3ec2801c61ee5df": {
  functionName: "loginUi_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "c83c165d725911da0a2d10bf9b4081d342982df3a4a1cb0005f655a148062e88": {
  functionName: "logoutUi_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "1db4956858288ffaf948aceb54510258587a817b9ce0750abd62db2175097a61": {
  functionName: "getUiSessionStatus_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "52b693a0d0986e1b88869bd1b2f3ad89e5d0066ab74e4dc3b53ff5f92fd9314a": {
  functionName: "searchUsers_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "0f40640e3b35c0977bf78642588eb873c46fdfa614fe6b4a91a15d9d91bda51d": {
  functionName: "getUser_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "ef4489f82e4ef0ce219ae7a9b56b3b3c61fd9b842a7376232e9b8046f9afbdf6": {
  functionName: "startSupportAccess_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "6d9490c0c432df4251a7d52485a35b448c5bff7b22fdb0771bd5580cf8ccd7d8": {
  functionName: "getOwnershipStatus_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "7273cb9ae21e0bb8f300e33243997012cf97c42bad0bf197c607d6b928aa4150": {
  functionName: "canDeleteUser_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "54f8fdc888d08350069efc99121699c8efa87fb365dee638a76d1e2f59c57a1d": {
  functionName: "deleteUser_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "4b8a4daffd0487a0d003502250d7dd39379b6b21051fb1c978158f903b409bf3": {
  functionName: "requestOwnershipTransfer_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "dbd497d57b4769250296a5de412468c69252ee7f47bef6fb4858b229559deb1f": {
  functionName: "acceptOwnershipTransfer_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "d98bf557f1dfc717daa594ce2281a4c9454d73de531aab0f763a0a4e437597eb": {
  functionName: "getOwnershipTransfers_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "1d8cf0c1f7ffb5c4c9d0ccfa63df3184a4f7c45be9c23383a462d2e42f27f19a": {
  functionName: "getTenantOwners_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "6bd180350339b5221bbb88c76c6a1013471b157f53c4e1c6d1b8129ba4ba6ab2": {
  functionName: "recordAudit_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "6d352a760c71daf1174415b290eaab48a92bc397ed28ccf5771c2cf812599c50": {
  functionName: "listAudit_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "ab7f74ca296f30837046b9fdde3f12fdf7677a0d74b968ecbd5a87da248443ee": {
  functionName: "downloadAudit_createServerFn_handler",
  importer: () => import("./assets/internal-api-C2ape4vd.js")
}, "b92e70e16f392b15ad8c13d909d159d9277a8cea40153a7d152372a6e6cb34ef": {
  functionName: "getHostedConfig_createServerFn_handler",
  importer: () => import("./assets/api-BtlEQN9l.js")
}, "4c4c6efb431cb3e467a6afa9464ba1af0373f18bc7d8f2ade3f6c4ca87cf460a": {
  functionName: "hostedSignIn_createServerFn_handler",
  importer: () => import("./assets/api-BtlEQN9l.js")
}, "b5af2b0f5b3bfef7350538f597333f57e07504f99fcbe1b508ce57d168cbea67": {
  functionName: "hostedSignUp_createServerFn_handler",
  importer: () => import("./assets/api-BtlEQN9l.js")
}, "622b84adf3123c35c2afd21c2c10615a5d4b9aa6a92ce81bccb916f5063294fb": {
  functionName: "hostedOAuthStart_createServerFn_handler",
  importer: () => import("./assets/api-BtlEQN9l.js")
}, "d4155fbcbe598960305caaa0460634889bef4ebf55939027f3c8729a9d0d4a74": {
  functionName: "hostedOAuthCallback_createServerFn_handler",
  importer: () => import("./assets/api-BtlEQN9l.js")
}, "188843d40400af4d3cb0176f40ac9e09380c3c2ff8b3b2a63e04559317674d7c": {
  functionName: "hostedSendMagicLink_createServerFn_handler",
  importer: () => import("./assets/api-BtlEQN9l.js")
}, "1ca42db0c2d7c66f24cfff9cb30ebd7016860272f0cdd353442eeca73c52638f": {
  functionName: "hostedRequestPasswordReset_createServerFn_handler",
  importer: () => import("./assets/api-BtlEQN9l.js")
}, "bd9cff8d3b9ce4f4e6e3cfb824b074e8b83564e739d2a433cd2f837974ae3e65": {
  functionName: "hostedVerifyEmail_createServerFn_handler",
  importer: () => import("./assets/api-BtlEQN9l.js")
}, "eba5296fd712cc1e557da6d47dae2405baaa57df15aaf6c6a8d1953200ec95ca": {
  functionName: "hostedVerifyMfa_createServerFn_handler",
  importer: () => import("./assets/api-BtlEQN9l.js")
}, "e88a814d5a618e7e6649b95cd90ac8cada5115df1d3fdefefd210a9fc9369e17": {
  functionName: "hostedListOrganizations_createServerFn_handler",
  importer: () => import("./assets/api-BtlEQN9l.js")
}, "00caa7e83ac2160de123c0d3a6fc13e26979131b0e5342bfa9e5f1f9ee4edd43": {
  functionName: "hostedSwitchOrganization_createServerFn_handler",
  importer: () => import("./assets/api-BtlEQN9l.js")
}, "74b76322f432f923b54acfb6d8cdc556b05cbc5adeb8065dff2a0bf954828322": {
  functionName: "hostedCreateOrganization_createServerFn_handler",
  importer: () => import("./assets/api-BtlEQN9l.js")
}, "bffb1b1898bf60e6171ff14d1b3a016bba0489e0e74026e9ac02d0bf7c7f45ad": {
  functionName: "hostedWebAuthnChallenge_createServerFn_handler",
  importer: () => import("./assets/api-BtlEQN9l.js")
} };
async function getServerFnById(id) {
  const serverFnInfo = manifest[id];
  if (!serverFnInfo) {
    throw new Error("Server function info not found for " + id);
  }
  const fnModule = await serverFnInfo.importer();
  if (!fnModule) {
    console.info("serverFnInfo", serverFnInfo);
    throw new Error("Server function module not resolved for " + id);
  }
  const action = fnModule[serverFnInfo.functionName];
  if (!action) {
    console.info("serverFnInfo", serverFnInfo);
    console.info("fnModule", fnModule);
    throw new Error(
      `Server function module export not resolved for serverFn ID: ${id}`
    );
  }
  return action;
}
let serovalPlugins = void 0;
const textEncoder = new TextEncoder();
const FORM_DATA_CONTENT_TYPES = [
  "multipart/form-data",
  "application/x-www-form-urlencoded"
];
const MAX_PAYLOAD_SIZE = 1e6;
const handleServerAction = async ({
  request,
  context,
  serverFnId
}) => {
  const method = request.method;
  const methodUpper = method.toUpperCase();
  const methodLower = method.toLowerCase();
  const url = new URL(request.url);
  const action = await getServerFnById(serverFnId);
  const isServerFn = request.headers.get("x-tsr-serverFn") === "true";
  if (!serovalPlugins) {
    serovalPlugins = getDefaultSerovalPlugins();
  }
  const contentType = request.headers.get("Content-Type");
  function parsePayload(payload) {
    const parsedPayload = fromJSON(payload, { plugins: serovalPlugins });
    return parsedPayload;
  }
  const response = await (async () => {
    try {
      let serializeResult = function(res2) {
        let nonStreamingBody = void 0;
        const alsResponse = getResponse();
        if (res2 !== void 0) {
          const rawStreams = /* @__PURE__ */ new Map();
          const rawStreamPlugin = createRawStreamRPCPlugin(
            (id, stream2) => {
              rawStreams.set(id, stream2);
            }
          );
          const plugins = [rawStreamPlugin, ...serovalPlugins || []];
          let done = false;
          const callbacks = {
            onParse: (value) => {
              nonStreamingBody = value;
            },
            onDone: () => {
              done = true;
            },
            onError: (error) => {
              throw error;
            }
          };
          toCrossJSONStream(res2, {
            refs: /* @__PURE__ */ new Map(),
            plugins,
            onParse(value) {
              callbacks.onParse(value);
            },
            onDone() {
              callbacks.onDone();
            },
            onError: (error) => {
              callbacks.onError(error);
            }
          });
          if (done && rawStreams.size === 0) {
            return new Response(
              nonStreamingBody ? JSON.stringify(nonStreamingBody) : void 0,
              {
                status: alsResponse.status,
                statusText: alsResponse.statusText,
                headers: {
                  "Content-Type": "application/json",
                  [X_TSS_SERIALIZED]: "true"
                }
              }
            );
          }
          if (rawStreams.size > 0) {
            const jsonStream = new ReadableStream({
              start(controller) {
                callbacks.onParse = (value) => {
                  controller.enqueue(JSON.stringify(value) + "\n");
                };
                callbacks.onDone = () => {
                  try {
                    controller.close();
                  } catch {
                  }
                };
                callbacks.onError = (error) => controller.error(error);
                if (nonStreamingBody !== void 0) {
                  callbacks.onParse(nonStreamingBody);
                }
              }
            });
            const multiplexedStream = createMultiplexedStream(
              jsonStream,
              rawStreams
            );
            return new Response(multiplexedStream, {
              status: alsResponse.status,
              statusText: alsResponse.statusText,
              headers: {
                "Content-Type": TSS_CONTENT_TYPE_FRAMED_VERSIONED,
                [X_TSS_SERIALIZED]: "true"
              }
            });
          }
          const stream = new ReadableStream({
            start(controller) {
              callbacks.onParse = (value) => controller.enqueue(
                textEncoder.encode(JSON.stringify(value) + "\n")
              );
              callbacks.onDone = () => {
                try {
                  controller.close();
                } catch (error) {
                  controller.error(error);
                }
              };
              callbacks.onError = (error) => controller.error(error);
              if (nonStreamingBody !== void 0) {
                callbacks.onParse(nonStreamingBody);
              }
            }
          });
          return new Response(stream, {
            status: alsResponse.status,
            statusText: alsResponse.statusText,
            headers: {
              "Content-Type": "application/x-ndjson",
              [X_TSS_SERIALIZED]: "true"
            }
          });
        }
        return new Response(void 0, {
          status: alsResponse.status,
          statusText: alsResponse.statusText
        });
      };
      let res = await (async () => {
        if (FORM_DATA_CONTENT_TYPES.some(
          (type) => contentType && contentType.includes(type)
        )) {
          invariant(
            methodLower !== "get",
            "GET requests with FormData payloads are not supported"
          );
          const formData = await request.formData();
          const serializedContext = formData.get(TSS_FORMDATA_CONTEXT);
          formData.delete(TSS_FORMDATA_CONTEXT);
          const params = {
            context,
            data: formData,
            method: methodUpper
          };
          if (typeof serializedContext === "string") {
            try {
              const parsedContext = JSON.parse(serializedContext);
              const deserializedContext = fromJSON(parsedContext, {
                plugins: serovalPlugins
              });
              if (typeof deserializedContext === "object" && deserializedContext) {
                params.context = safeObjectMerge(
                  context,
                  deserializedContext
                );
              }
            } catch (e) {
              if (false) ;
            }
          }
          return await action(params);
        }
        if (methodLower === "get") {
          const payloadParam = url.searchParams.get("payload");
          if (payloadParam && payloadParam.length > MAX_PAYLOAD_SIZE) {
            throw new Error("Payload too large");
          }
          const payload2 = payloadParam ? parsePayload(JSON.parse(payloadParam)) : {};
          payload2.context = safeObjectMerge(context, payload2.context);
          payload2.method = methodUpper;
          return await action(payload2);
        }
        if (methodLower !== "post") {
          throw new Error("expected POST method");
        }
        let jsonPayload;
        if (contentType?.includes("application/json")) {
          jsonPayload = await request.json();
        }
        const payload = jsonPayload ? parsePayload(jsonPayload) : {};
        payload.context = safeObjectMerge(payload.context, context);
        payload.method = methodUpper;
        return await action(payload);
      })();
      const unwrapped = res.result || res.error;
      if (isNotFound(res)) {
        res = isNotFoundResponse(res);
      }
      if (!isServerFn) {
        return unwrapped;
      }
      if (unwrapped instanceof Response) {
        if (isRedirect(unwrapped)) {
          return unwrapped;
        }
        unwrapped.headers.set(X_TSS_RAW_RESPONSE, "true");
        return unwrapped;
      }
      return serializeResult(res);
    } catch (error) {
      if (error instanceof Response) {
        return error;
      }
      if (isNotFound(error)) {
        return isNotFoundResponse(error);
      }
      console.info();
      console.info("Server Fn Error!");
      console.info();
      console.error(error);
      console.info();
      const serializedError = JSON.stringify(
        await Promise.resolve(
          toCrossJSONAsync(error, {
            refs: /* @__PURE__ */ new Map(),
            plugins: serovalPlugins
          })
        )
      );
      const response2 = getResponse();
      return new Response(serializedError, {
        status: response2.status ?? 500,
        statusText: response2.statusText,
        headers: {
          "Content-Type": "application/json",
          [X_TSS_SERIALIZED]: "true"
        }
      });
    }
  })();
  return response;
};
function isNotFoundResponse(error) {
  const { headers, ...rest } = error;
  return new Response(JSON.stringify(rest), {
    status: 404,
    headers: {
      "Content-Type": "application/json",
      ...headers || {}
    }
  });
}
function resolveTransformConfig(transform) {
  if (typeof transform === "string") {
    const prefix = transform;
    return {
      type: "transform",
      transformFn: ({ url }) => `${prefix}${url}`,
      cache: true
    };
  }
  if (typeof transform === "function") {
    return {
      type: "transform",
      transformFn: transform,
      cache: true
    };
  }
  if ("createTransform" in transform && transform.createTransform) {
    return {
      type: "createTransform",
      createTransform: transform.createTransform,
      cache: transform.cache !== false
    };
  }
  const transformFn = typeof transform.transform === "string" ? (({ url }) => `${transform.transform}${url}`) : transform.transform;
  return {
    type: "transform",
    transformFn,
    cache: transform.cache !== false
  };
}
function buildClientEntryScriptTag(clientEntry, injectedHeadScripts) {
  const clientEntryLiteral = JSON.stringify(clientEntry);
  let script = `import(${clientEntryLiteral})`;
  if (injectedHeadScripts) {
    script = `${injectedHeadScripts};${script}`;
  }
  return {
    tag: "script",
    attrs: {
      type: "module",
      async: true
    },
    children: script
  };
}
function transformManifestUrls(source, transformFn, opts) {
  return (async () => {
    const manifest2 = opts?.clone ? structuredClone(source.manifest) : source.manifest;
    for (const route of Object.values(manifest2.routes)) {
      if (route.preloads) {
        route.preloads = await Promise.all(
          route.preloads.map(
            (url) => Promise.resolve(transformFn({ url, type: "modulepreload" }))
          )
        );
      }
      if (route.assets) {
        for (const asset of route.assets) {
          if (asset.tag === "link" && asset.attrs?.href) {
            asset.attrs.href = await Promise.resolve(
              transformFn({
                url: asset.attrs.href,
                type: "stylesheet"
              })
            );
          }
        }
      }
    }
    const transformedClientEntry = await Promise.resolve(
      transformFn({
        url: source.clientEntry,
        type: "clientEntry"
      })
    );
    const rootRoute = manifest2.routes[rootRouteId];
    if (rootRoute) {
      rootRoute.assets = rootRoute.assets || [];
      rootRoute.assets.push(
        buildClientEntryScriptTag(
          transformedClientEntry,
          source.injectedHeadScripts
        )
      );
    }
    return manifest2;
  })();
}
function buildManifestWithClientEntry(source) {
  const scriptTag = buildClientEntryScriptTag(
    source.clientEntry,
    source.injectedHeadScripts
  );
  const baseRootRoute = source.manifest.routes[rootRouteId];
  const routes = {
    ...source.manifest.routes,
    ...baseRootRoute ? {
      [rootRouteId]: {
        ...baseRootRoute,
        assets: [...baseRootRoute.assets || [], scriptTag]
      }
    } : {}
  };
  return { routes };
}
const HEADERS = {
  TSS_SHELL: "X-TSS_SHELL"
};
const ServerFunctionSerializationAdapter = createSerializationAdapter({
  key: "$TSS/serverfn",
  test: (v) => {
    if (typeof v !== "function") return false;
    if (!(TSS_SERVER_FUNCTION in v)) return false;
    return !!v[TSS_SERVER_FUNCTION];
  },
  toSerializable: ({ serverFnMeta }) => ({ functionId: serverFnMeta.id }),
  fromSerializable: ({ functionId }) => {
    const fn = async (opts, signal) => {
      const serverFn = await getServerFnById(functionId);
      const result = await serverFn(opts ?? {}, signal);
      return result.result;
    };
    return fn;
  }
});
function getStartResponseHeaders(opts) {
  const headers = mergeHeaders(
    {
      "Content-Type": "text/html; charset=utf-8"
    },
    ...opts.router.state.matches.map((match) => {
      return match.headers;
    })
  );
  return headers;
}
let entriesPromise;
let baseManifestPromise;
let cachedFinalManifestPromise;
async function loadEntries() {
  const routerEntry = await import("./assets/router-BqFKwE1w.js").then((n) => n.v);
  const startEntry = await Promise.resolve().then(() => start);
  return { startEntry, routerEntry };
}
function getEntries() {
  if (!entriesPromise) {
    entriesPromise = loadEntries();
  }
  return entriesPromise;
}
function getBaseManifest(matchedRoutes) {
  if (!baseManifestPromise) {
    baseManifestPromise = getStartManifest();
  }
  return baseManifestPromise;
}
async function resolveManifest(matchedRoutes, transformFn, cache) {
  const base = await getBaseManifest();
  const computeFinalManifest = async () => {
    return transformFn ? await transformManifestUrls(base, transformFn, { clone: !cache }) : buildManifestWithClientEntry(base);
  };
  if (!transformFn || cache) {
    if (!cachedFinalManifestPromise) {
      cachedFinalManifestPromise = computeFinalManifest();
    }
    return cachedFinalManifestPromise;
  }
  return computeFinalManifest();
}
const ROUTER_BASEPATH = "/";
const SERVER_FN_BASE = "/_serverFn/";
const IS_PRERENDERING = process.env.TSS_PRERENDERING === "true";
const IS_SHELL_ENV = process.env.TSS_SHELL === "true";
const ERR_NO_RESPONSE = "Internal Server Error";
const ERR_NO_DEFER = "Internal Server Error";
function throwRouteHandlerError() {
  throw new Error(ERR_NO_RESPONSE);
}
function throwIfMayNotDefer() {
  throw new Error(ERR_NO_DEFER);
}
function isSpecialResponse(value) {
  return value instanceof Response || isRedirect(value);
}
function handleCtxResult(result) {
  if (isSpecialResponse(result)) {
    return { response: result };
  }
  return result;
}
function executeMiddleware(middlewares, ctx) {
  let index = -1;
  const next = async (nextCtx) => {
    if (nextCtx) {
      if (nextCtx.context) {
        ctx.context = safeObjectMerge(ctx.context, nextCtx.context);
      }
      for (const key of Object.keys(nextCtx)) {
        if (key !== "context") {
          ctx[key] = nextCtx[key];
        }
      }
    }
    index++;
    const middleware = middlewares[index];
    if (!middleware) return ctx;
    let result;
    try {
      result = await middleware({ ...ctx, next });
    } catch (err) {
      if (isSpecialResponse(err)) {
        ctx.response = err;
        return ctx;
      }
      throw err;
    }
    const normalized = handleCtxResult(result);
    if (normalized) {
      if (normalized.response !== void 0) {
        ctx.response = normalized.response;
      }
      if (normalized.context) {
        ctx.context = safeObjectMerge(ctx.context, normalized.context);
      }
    }
    return ctx;
  };
  return next();
}
function handlerToMiddleware(handler, mayDefer = false) {
  if (mayDefer) {
    return handler;
  }
  return async (ctx) => {
    const response = await handler({ ...ctx, next: throwIfMayNotDefer });
    if (!response) {
      throwRouteHandlerError();
    }
    return response;
  };
}
function createStartHandler(cbOrOptions) {
  const cb = typeof cbOrOptions === "function" ? cbOrOptions : cbOrOptions.handler;
  const transformAssetUrlsOption = typeof cbOrOptions === "function" ? void 0 : cbOrOptions.transformAssetUrls;
  const warmupTransformManifest = !!transformAssetUrlsOption && typeof transformAssetUrlsOption === "object" && transformAssetUrlsOption.warmup === true;
  const resolvedTransformConfig = transformAssetUrlsOption ? resolveTransformConfig(transformAssetUrlsOption) : void 0;
  const cache = resolvedTransformConfig ? resolvedTransformConfig.cache : true;
  let cachedCreateTransformPromise;
  const getTransformFn = async (opts) => {
    if (!resolvedTransformConfig) return void 0;
    if (resolvedTransformConfig.type === "createTransform") {
      if (cache) {
        if (!cachedCreateTransformPromise) {
          cachedCreateTransformPromise = Promise.resolve(
            resolvedTransformConfig.createTransform(opts)
          );
        }
        return cachedCreateTransformPromise;
      }
      return resolvedTransformConfig.createTransform(opts);
    }
    return resolvedTransformConfig.transformFn;
  };
  if (warmupTransformManifest && cache && true && !cachedFinalManifestPromise) {
    const warmupPromise = (async () => {
      const base = await getBaseManifest();
      const transformFn = await getTransformFn({ warmup: true });
      return transformFn ? await transformManifestUrls(base, transformFn, { clone: false }) : buildManifestWithClientEntry(base);
    })();
    cachedFinalManifestPromise = warmupPromise;
    warmupPromise.catch(() => {
      if (cachedFinalManifestPromise === warmupPromise) {
        cachedFinalManifestPromise = void 0;
      }
      cachedCreateTransformPromise = void 0;
    });
  }
  const startRequestResolver = async (request, requestOpts) => {
    let router = null;
    let cbWillCleanup = false;
    try {
      const { url, handledProtocolRelativeURL } = getNormalizedURL(request.url);
      const href = url.pathname + url.search + url.hash;
      const origin = getOrigin(request);
      if (handledProtocolRelativeURL) {
        return Response.redirect(url, 308);
      }
      const entries = await getEntries();
      const startOptions = await entries.startEntry.startInstance?.getOptions() || {};
      const serializationAdapters = [
        ...startOptions.serializationAdapters || [],
        ServerFunctionSerializationAdapter
      ];
      const requestStartOptions = {
        ...startOptions,
        serializationAdapters
      };
      const flattenedRequestMiddlewares = startOptions.requestMiddleware ? flattenMiddlewares(startOptions.requestMiddleware) : [];
      const executedRequestMiddlewares = new Set(
        flattenedRequestMiddlewares
      );
      const getRouter = async () => {
        if (router) return router;
        router = await entries.routerEntry.getRouter();
        let isShell = IS_SHELL_ENV;
        if (IS_PRERENDERING && !isShell) {
          isShell = request.headers.get(HEADERS.TSS_SHELL) === "true";
        }
        const history = createMemoryHistory({
          initialEntries: [href]
        });
        router.update({
          history,
          isShell,
          isPrerendering: IS_PRERENDERING,
          origin: router.options.origin ?? origin,
          ...{
            defaultSsr: requestStartOptions.defaultSsr,
            serializationAdapters: [
              ...requestStartOptions.serializationAdapters,
              ...router.options.serializationAdapters || []
            ]
          },
          basepath: ROUTER_BASEPATH
        });
        return router;
      };
      if (SERVER_FN_BASE && url.pathname.startsWith(SERVER_FN_BASE)) {
        const serverFnId = url.pathname.slice(SERVER_FN_BASE.length).split("/")[0];
        if (!serverFnId) {
          throw new Error("Invalid server action param for serverFnId");
        }
        const serverFnHandler = async ({ context }) => {
          return runWithStartContext(
            {
              getRouter,
              startOptions: requestStartOptions,
              contextAfterGlobalMiddlewares: context,
              request,
              executedRequestMiddlewares
            },
            () => handleServerAction({
              request,
              context: requestOpts?.context,
              serverFnId
            })
          );
        };
        const middlewares2 = flattenedRequestMiddlewares.map(
          (d) => d.options.server
        );
        const ctx2 = await executeMiddleware([...middlewares2, serverFnHandler], {
          request,
          context: createNullProtoObject(requestOpts?.context)
        });
        return handleRedirectResponse(ctx2.response, request, getRouter);
      }
      const executeRouter = async (serverContext, matchedRoutes) => {
        const acceptHeader = request.headers.get("Accept") || "*/*";
        const acceptParts = acceptHeader.split(",");
        const supportedMimeTypes = ["*/*", "text/html"];
        const isSupported = supportedMimeTypes.some(
          (mimeType) => acceptParts.some((part) => part.trim().startsWith(mimeType))
        );
        if (!isSupported) {
          return Response.json(
            { error: "Only HTML requests are supported here" },
            { status: 500 }
          );
        }
        const manifest2 = await resolveManifest(
          matchedRoutes,
          await getTransformFn({ warmup: false, request }),
          cache
        );
        const routerInstance = await getRouter();
        attachRouterServerSsrUtils({
          router: routerInstance,
          manifest: manifest2
        });
        routerInstance.update({ additionalContext: { serverContext } });
        await routerInstance.load();
        if (routerInstance.state.redirect) {
          return routerInstance.state.redirect;
        }
        await routerInstance.serverSsr.dehydrate();
        const responseHeaders = getStartResponseHeaders({
          router: routerInstance
        });
        cbWillCleanup = true;
        return cb({
          request,
          router: routerInstance,
          responseHeaders
        });
      };
      const requestHandlerMiddleware = async ({ context }) => {
        return runWithStartContext(
          {
            getRouter,
            startOptions: requestStartOptions,
            contextAfterGlobalMiddlewares: context,
            request,
            executedRequestMiddlewares
          },
          async () => {
            try {
              return await handleServerRoutes({
                getRouter,
                request,
                url,
                executeRouter,
                context,
                executedRequestMiddlewares
              });
            } catch (err) {
              if (err instanceof Response) {
                return err;
              }
              throw err;
            }
          }
        );
      };
      const middlewares = flattenedRequestMiddlewares.map(
        (d) => d.options.server
      );
      const ctx = await executeMiddleware(
        [...middlewares, requestHandlerMiddleware],
        { request, context: createNullProtoObject(requestOpts?.context) }
      );
      return handleRedirectResponse(ctx.response, request, getRouter);
    } finally {
      if (router && !cbWillCleanup) {
        router.serverSsr?.cleanup();
      }
      router = null;
    }
  };
  return requestHandler(startRequestResolver);
}
async function handleRedirectResponse(response, request, getRouter) {
  if (!isRedirect(response)) {
    return response;
  }
  if (isResolvedRedirect(response)) {
    if (request.headers.get("x-tsr-serverFn") === "true") {
      return Response.json(
        { ...response.options, isSerializedRedirect: true },
        { headers: response.headers }
      );
    }
    return response;
  }
  const opts = response.options;
  if (opts.to && typeof opts.to === "string" && !opts.to.startsWith("/")) {
    throw new Error(
      `Server side redirects must use absolute paths via the 'href' or 'to' options. The redirect() method's "to" property accepts an internal path only. Use the "href" property to provide an external URL. Received: ${JSON.stringify(opts)}`
    );
  }
  if (["params", "search", "hash"].some(
    (d) => typeof opts[d] === "function"
  )) {
    throw new Error(
      `Server side redirects must use static search, params, and hash values and do not support functional values. Received functional values for: ${Object.keys(
        opts
      ).filter((d) => typeof opts[d] === "function").map((d) => `"${d}"`).join(", ")}`
    );
  }
  const router = await getRouter();
  const redirect = router.resolveRedirect(response);
  if (request.headers.get("x-tsr-serverFn") === "true") {
    return Response.json(
      { ...response.options, isSerializedRedirect: true },
      { headers: response.headers }
    );
  }
  return redirect;
}
async function handleServerRoutes({
  getRouter,
  request,
  url,
  executeRouter,
  context,
  executedRequestMiddlewares
}) {
  const router = await getRouter();
  const rewrittenUrl = executeRewriteInput(router.rewrite, url);
  const pathname = rewrittenUrl.pathname;
  const { matchedRoutes, foundRoute, routeParams } = router.getMatchedRoutes(pathname);
  const isExactMatch = foundRoute && routeParams["**"] === void 0;
  const routeMiddlewares = [];
  for (const route of matchedRoutes) {
    const serverMiddleware = route.options.server?.middleware;
    if (serverMiddleware) {
      const flattened = flattenMiddlewares(serverMiddleware);
      for (const m of flattened) {
        if (!executedRequestMiddlewares.has(m)) {
          routeMiddlewares.push(m.options.server);
        }
      }
    }
  }
  const server2 = foundRoute?.options.server;
  if (server2?.handlers && isExactMatch) {
    const handlers = typeof server2.handlers === "function" ? server2.handlers({ createHandlers: (d) => d }) : server2.handlers;
    const requestMethod = request.method.toUpperCase();
    const handler = handlers[requestMethod] ?? handlers["ANY"];
    if (handler) {
      const mayDefer = !!foundRoute.options.component;
      if (typeof handler === "function") {
        routeMiddlewares.push(handlerToMiddleware(handler, mayDefer));
      } else {
        if (handler.middleware?.length) {
          const handlerMiddlewares = flattenMiddlewares(handler.middleware);
          for (const m of handlerMiddlewares) {
            routeMiddlewares.push(m.options.server);
          }
        }
        if (handler.handler) {
          routeMiddlewares.push(handlerToMiddleware(handler.handler, mayDefer));
        }
      }
    }
  }
  routeMiddlewares.push(
    (ctx2) => executeRouter(ctx2.context, matchedRoutes)
  );
  const ctx = await executeMiddleware(routeMiddlewares, {
    request,
    context,
    params: routeParams,
    pathname
  });
  return ctx.response;
}
const fetch = createStartHandler(defaultStreamHandler);
function createServerEntry(entry) {
  return {
    async fetch(...args) {
      return await entry.fetch(...args);
    }
  };
}
const server = createServerEntry({ fetch });
const createServerRpc = (serverFnMeta, splitImportFn) => {
  const url = "/_serverFn/" + serverFnMeta.id;
  return Object.assign(splitImportFn, {
    url,
    serverFnMeta,
    [TSS_SERVER_FUNCTION]: true
  });
};
function useServerFn(serverFn) {
  const router = useRouter();
  return React.useCallback(
    async (...args) => {
      try {
        const res = await serverFn(...args);
        if (isRedirect$1(res)) {
          throw res;
        }
        return res;
      } catch (err) {
        if (isRedirect$1(err)) {
          err.options._fromLocation = router.state.location;
          return router.navigate(router.resolveRedirect(err).options);
        }
        throw err;
      }
    },
    [router, serverFn]
  );
}
const GLOBAL_EVENT_STORAGE_KEY = /* @__PURE__ */ Symbol.for("tanstack-start:event-storage");
const globalObj = globalThis;
if (!globalObj[GLOBAL_EVENT_STORAGE_KEY]) {
  globalObj[GLOBAL_EVENT_STORAGE_KEY] = new AsyncLocalStorage();
}
const eventStorage = globalObj[GLOBAL_EVENT_STORAGE_KEY];
function getH3Event() {
  const event = eventStorage.getStore();
  if (!event) {
    throw new Error(
      `No StartEvent found in AsyncLocalStorage. Make sure you are using the function within the server runtime.`
    );
  }
  return event.h3Event;
}
function getRequest() {
  const event = getH3Event();
  return event.req;
}
const startInstance = void 0;
const start = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  startInstance
}, Symbol.toStringTag, { value: "Module" }));
const createSsrRpc = (functionId, importer) => {
  const url = "/_serverFn/" + functionId;
  const serverFnMeta = { id: functionId };
  const fn = async (...args) => {
    const serverFn = await getServerFnById(functionId);
    return serverFn(...args);
  };
  return Object.assign(fn, {
    url,
    serverFnMeta,
    [TSS_SERVER_FUNCTION]: true
  });
};
export {
  createServerFn as a,
  createSsrRpc as b,
  createServerRpc as c,
  createServerEntry,
  createMiddleware as d,
  server as default,
  getRequest as g,
  useServerFn as u
};
