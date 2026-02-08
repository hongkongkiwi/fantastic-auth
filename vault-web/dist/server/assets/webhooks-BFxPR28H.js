import { jsxs, jsx } from "react/jsx-runtime";
import { Suspense, lazy } from "react";
import { P as PageHeader } from "./router-BDwxh4pl.js";
import { C as Card } from "./Card-Brxgy2gk.js";
import { a as Skeleton } from "./Skeleton-CdKpSX4m.js";
import "@tanstack/react-router";
import "sonner";
import "../server.js";
import "@tanstack/history";
import "@tanstack/router-core/ssr/client";
import "@tanstack/router-core";
import "node:async_hooks";
import "@tanstack/router-core/ssr/server";
import "h3-v2";
import "tiny-invariant";
import "seroval";
import "@tanstack/react-router/ssr/server";
import "./auth-middleware-CUT-Ooy9.js";
import "./server-DL57AnWM.js";
import "@t3-oss/env-core";
import "zod";
import "framer-motion";
import "lucide-react";
import "clsx";
import "tailwind-merge";
import "@radix-ui/react-slot";
import "class-variance-authority";
import "@radix-ui/react-dialog";
import "cmdk";
import "@sentry/react";
const WebhookManager = lazy(() => import("./WebhookManager-_0p5z3Y4.js").then((mod) => ({
  default: mod.WebhookManager
})));
function WebhooksSettingsPage() {
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "Webhook Settings", description: "Configure endpoints to receive real-time event notifications", breadcrumbs: [{
      label: "Settings",
      href: "/settings"
    }, {
      label: "Webhooks"
    }] }),
    /* @__PURE__ */ jsx(Card, { className: "p-6", children: /* @__PURE__ */ jsx(Suspense, { fallback: /* @__PURE__ */ jsx(Skeleton, { className: "h-72 w-full" }), children: /* @__PURE__ */ jsx(WebhookManager, {}) }) })
  ] });
}
export {
  WebhooksSettingsPage as component
};
