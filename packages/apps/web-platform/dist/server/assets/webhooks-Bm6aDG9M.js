import { jsxs, jsx } from "react/jsx-runtime";
import { Suspense, lazy } from "react";
import { P as PageHeader } from "./router-BqFKwE1w.js";
import { C as Card } from "./Card-DiqECnNB.js";
import { a as Skeleton } from "./Skeleton-RwodY-mL.js";
import "@tanstack/react-router";
import "@t3-oss/env-core";
import "zod";
import "sonner";
import "framer-motion";
import "lucide-react";
import "clsx";
import "tailwind-merge";
import "@radix-ui/react-slot";
import "class-variance-authority";
import "@radix-ui/react-dialog";
import "cmdk";
import "@radix-ui/react-checkbox";
import "@radix-ui/react-label";
import "@sentry/react";
const WebhookManager = lazy(() => import("./WebhookManager-DxcbpfaX.js").then((mod) => ({
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
