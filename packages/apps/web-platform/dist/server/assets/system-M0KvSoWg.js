import { jsxs, jsx } from "react/jsx-runtime";
import { useMemo } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { Server, Activity, Shield, ToggleLeft, CheckCircle2, AlertCircle } from "lucide-react";
import { t as toast, P as PageHeader, B as Button, a as Badge } from "./router-BqFKwE1w.js";
import { C as Card } from "./Card-DiqECnNB.js";
import { T as Tabs, a as TabsList, b as TabsTrigger, c as TabsContent } from "./Tabs-Dlqc7sYx.js";
import { S as Switch } from "./Switch-DnK4UYa_.js";
import { useQueryClient, useQuery, useMutation } from "@tanstack/react-query";
import { u as useServerFn } from "../server.js";
import { l as listFeatureFlags, u as updateFeatureFlag } from "./internal-api-DaRn9LSO.js";
import "@tanstack/react-router";
import "@t3-oss/env-core";
import "zod";
import "sonner";
import "clsx";
import "tailwind-merge";
import "@radix-ui/react-slot";
import "class-variance-authority";
import "@radix-ui/react-dialog";
import "cmdk";
import "@radix-ui/react-checkbox";
import "@radix-ui/react-label";
import "@sentry/react";
import "@radix-ui/react-tabs";
import "@radix-ui/react-switch";
import "@tanstack/history";
import "@tanstack/router-core/ssr/client";
import "@tanstack/router-core";
import "node:async_hooks";
import "@tanstack/router-core/ssr/server";
import "h3-v2";
import "tiny-invariant";
import "seroval";
import "@tanstack/react-router/ssr/server";
import "./auth-middleware-Bbw8ptVi.js";
import "ioredis";
import "./server-Dz7KC5sb.js";
import "./logger-D87hn870.js";
import "loglayer";
const flagsMock = [{
  id: "ff-1",
  name: "New Billing Engine",
  key: "billing_v2",
  description: "Enable the new billing pipeline for eligible tenants",
  enabled: true,
  rolloutPercentage: 25
}, {
  id: "ff-2",
  name: "Realtime Audit",
  key: "audit_stream",
  description: "Stream audit events to configured destinations",
  enabled: false,
  rolloutPercentage: 0
}];
const healthChecks = [{
  service: "API",
  status: "healthy",
  latency: "120ms"
}, {
  service: "Auth",
  status: "healthy",
  latency: "95ms"
}, {
  service: "Billing",
  status: "degraded",
  latency: "420ms"
}, {
  service: "Webhooks",
  status: "healthy",
  latency: "160ms"
}];
function SystemPage() {
  const prefersReducedMotion = useReducedMotion();
  const queryClient = useQueryClient();
  const listFeatureFlagsFn = useServerFn(listFeatureFlags);
  const updateFeatureFlagFn = useServerFn(updateFeatureFlag);
  const {
    data: featureFlags,
    isLoading
  } = useQuery({
    queryKey: ["feature-flags"],
    queryFn: () => listFeatureFlagsFn({
      data: {}
    })
  });
  const flags = useMemo(() => {
    if (!featureFlags || featureFlags.length === 0) return flagsMock;
    return featureFlags;
  }, [featureFlags]);
  const updateMutation = useMutation({
    mutationFn: async (payload) => {
      return updateFeatureFlagFn({
        data: {
          flagId: payload.flagId,
          enabled: payload.enabled,
          rolloutPercentage: payload.rolloutPercentage
        }
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["feature-flags"]
      });
      toast.success("Feature flag updated");
    },
    onError: () => toast.error("Failed to update feature flag")
  });
  const toggleFlag = (flag) => {
    if (!flag.id) return;
    updateMutation.mutate({
      flagId: flag.id,
      enabled: !flag.enabled
    });
  };
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "System", description: "Health, feature flags, and maintenance controls", breadcrumbs: [{
      label: "System"
    }], actions: /* @__PURE__ */ jsxs(Button, { variant: "outline", children: [
      /* @__PURE__ */ jsx(Server, { className: "mr-2 h-4 w-4" }),
      "Run Diagnostics"
    ] }) }),
    /* @__PURE__ */ jsxs(Tabs, { defaultValue: "health", className: "space-y-6", children: [
      /* @__PURE__ */ jsxs(TabsList, { className: "flex flex-wrap", children: [
        /* @__PURE__ */ jsx(TabsTrigger, { value: "health", children: "Health" }),
        /* @__PURE__ */ jsx(TabsTrigger, { value: "flags", children: "Feature Flags" }),
        /* @__PURE__ */ jsx(TabsTrigger, { value: "maintenance", children: "Maintenance" })
      ] }),
      /* @__PURE__ */ jsx(TabsContent, { value: "health", className: "space-y-4", children: /* @__PURE__ */ jsx("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-4", children: healthChecks.map((check, index) => /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
        opacity: 0,
        y: 10
      }, animate: {
        opacity: 1,
        y: 0
      }, transition: prefersReducedMotion ? {
        duration: 0
      } : {
        delay: index * 0.05
      }, children: /* @__PURE__ */ jsx(Card, { className: "p-6", children: /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
        /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
          /* @__PURE__ */ jsx(Activity, { className: "h-5 w-5 text-primary" }),
          /* @__PURE__ */ jsxs("div", { children: [
            /* @__PURE__ */ jsx("p", { className: "font-medium", children: check.service }),
            /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground", children: [
              "Latency ",
              check.latency
            ] })
          ] })
        ] }),
        /* @__PURE__ */ jsx(Badge, { variant: check.status === "healthy" ? "success" : "warning", children: check.status })
      ] }) }) }, check.service)) }) }),
      /* @__PURE__ */ jsx(TabsContent, { value: "flags", className: "space-y-4", children: /* @__PURE__ */ jsx("div", { className: "space-y-4", children: flags.map((flag) => /* @__PURE__ */ jsx(Card, { className: "p-6", children: /* @__PURE__ */ jsxs("div", { className: "flex items-start justify-between gap-4", children: [
        /* @__PURE__ */ jsxs("div", { children: [
          /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsx(Shield, { className: "h-5 w-5 text-primary" }),
            /* @__PURE__ */ jsx("h3", { className: "font-semibold", children: flag.name }),
            /* @__PURE__ */ jsx(Badge, { variant: "secondary", className: "font-mono text-xs", children: flag.key })
          ] }),
          /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground mt-2", children: flag.description }),
          /* @__PURE__ */ jsxs("p", { className: "text-xs text-muted-foreground mt-2", children: [
            "Rollout: ",
            flag.rolloutPercentage ?? 0,
            "%"
          ] })
        ] }),
        /* @__PURE__ */ jsx("div", { className: "flex items-center gap-2", children: /* @__PURE__ */ jsx(Switch, { checked: Boolean(flag.enabled), onCheckedChange: () => toggleFlag(flag), disabled: isLoading || updateMutation.isPending }) })
      ] }) }, flag.id)) }) }),
      /* @__PURE__ */ jsxs(TabsContent, { value: "maintenance", className: "space-y-4", children: [
        /* @__PURE__ */ jsx(Card, { className: "p-6", children: /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
          /* @__PURE__ */ jsxs("div", { children: [
            /* @__PURE__ */ jsx("h3", { className: "font-semibold", children: "Maintenance Mode" }),
            /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Pause logins and API traffic" })
          ] }),
          /* @__PURE__ */ jsx(Switch, {})
        ] }) }),
        /* @__PURE__ */ jsxs(Card, { className: "p-6", children: [
          /* @__PURE__ */ jsxs("div", { className: "flex items-start justify-between gap-4", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
              /* @__PURE__ */ jsx(ToggleLeft, { className: "h-5 w-5 text-primary" }),
              /* @__PURE__ */ jsxs("div", { children: [
                /* @__PURE__ */ jsx("h4", { className: "font-medium", children: "Background Jobs" }),
                /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Queue processing and webhooks" })
              ] })
            ] }),
            /* @__PURE__ */ jsxs(Badge, { variant: "success", className: "flex items-center gap-1", children: [
              /* @__PURE__ */ jsx(CheckCircle2, { className: "h-3 w-3" }),
              "Healthy"
            ] })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "mt-4 flex items-start justify-between gap-4", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
              /* @__PURE__ */ jsx(AlertCircle, { className: "h-5 w-5 text-amber-500" }),
              /* @__PURE__ */ jsxs("div", { children: [
                /* @__PURE__ */ jsx("h4", { className: "font-medium", children: "Email Delivery" }),
                /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Retry queue delayed" })
              ] })
            ] }),
            /* @__PURE__ */ jsx(Badge, { variant: "warning", children: "Degraded" })
          ] })
        ] })
      ] })
    ] })
  ] });
}
export {
  SystemPage as component
};
