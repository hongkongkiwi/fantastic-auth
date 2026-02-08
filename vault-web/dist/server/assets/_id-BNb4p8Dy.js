import { jsxs, jsx, Fragment } from "react/jsx-runtime";
import { useParams, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { AlertCircle, CheckCircle2, Pause, Play, Trash2, Users, CreditCard, Calendar, Activity, User } from "lucide-react";
import { u as useServerFn, B as Button, H as formatDate, n as formatDateTime, P as PageHeader, j as cn, S as StatCard, k as formatNumber, o as formatRelativeTime, C as ConfirmDialog, t as toast, I as getTenantDetail, z as deleteTenant, A as activateTenant, E as suspendTenant } from "./router-BDwxh4pl.js";
import { C as Card, d as CardContent, a as CardHeader, b as CardTitle, c as CardDescription } from "./Card-Brxgy2gk.js";
import { B as Badge } from "./Badge-DmGWtXSM.js";
import { T as Tabs, a as TabsList, b as TabsTrigger, c as TabsContent } from "./Tabs-c0ts_20e.js";
import { a as Skeleton } from "./Skeleton-CdKpSX4m.js";
import { ResponsiveContainer, AreaChart, CartesianGrid, XAxis, YAxis, Tooltip, Area } from "recharts";
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
import "clsx";
import "tailwind-merge";
import "@radix-ui/react-slot";
import "class-variance-authority";
import "@radix-ui/react-dialog";
import "cmdk";
import "@sentry/react";
import "@radix-ui/react-tabs";
const usageData = [{
  day: "Mon",
  apiCalls: 1200,
  users: 45
}, {
  day: "Tue",
  apiCalls: 1800,
  users: 52
}, {
  day: "Wed",
  apiCalls: 2400,
  users: 58
}, {
  day: "Thu",
  apiCalls: 2100,
  users: 61
}, {
  day: "Fri",
  apiCalls: 2800,
  users: 65
}, {
  day: "Sat",
  apiCalls: 1500,
  users: 42
}, {
  day: "Sun",
  apiCalls: 1200,
  users: 38
}];
const now = Date.now();
const recentActivity = [{
  id: 1,
  action: "User Login",
  user: "john@example.com",
  timestamp: new Date(now - 2 * 60 * 1e3).toISOString(),
  status: "success"
}, {
  id: 2,
  action: "API Key Created",
  user: "admin",
  timestamp: new Date(now - 15 * 60 * 1e3).toISOString(),
  status: "success"
}, {
  id: 3,
  action: "Password Reset",
  user: "jane@example.com",
  timestamp: new Date(now - 60 * 60 * 1e3).toISOString(),
  status: "success"
}, {
  id: 4,
  action: "Failed Login",
  user: "unknown",
  timestamp: new Date(now - 2 * 60 * 60 * 1e3).toISOString(),
  status: "error"
}];
function TenantDetailPage() {
  const {
    id
  } = useParams({
    from: "/tenants/$id"
  });
  const [tenant, setTenant] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [dialogState, setDialogState] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const prefersReducedMotion = useReducedMotion();
  const getTenantFn = useServerFn(getTenantDetail);
  const suspendTenantFn = useServerFn(suspendTenant);
  const activateTenantFn = useServerFn(activateTenant);
  const deleteTenantFn = useServerFn(deleteTenant);
  useEffect(() => {
    const fetchTenant = async () => {
      try {
        const data = await getTenantFn({
          data: {
            tenantId: id
          }
        });
        setTenant(data);
      } catch (error) {
        toast.error("Failed to load tenant details");
      } finally {
        setIsLoading(false);
      }
    };
    fetchTenant();
  }, [id]);
  const handleAction = async () => {
    if (!tenant || !dialogState) return;
    if (!tenant.id) {
      toast.error("Tenant ID is missing");
      return;
    }
    setIsSubmitting(true);
    try {
      switch (dialogState) {
        case "suspend":
          await suspendTenantFn({
            data: {
              tenantId: tenant.id
            }
          });
          toast.success("Tenant suspended");
          break;
        case "activate":
          await activateTenantFn({
            data: {
              tenantId: tenant.id
            }
          });
          toast.success("Tenant activated");
          break;
        case "delete":
          await deleteTenantFn({
            data: {
              tenantId: tenant.id
            }
          });
          toast.success("Tenant deleted");
          window.location.href = "/tenants";
          return;
      }
      const updated = await getTenantFn({
        data: {
          tenantId: id
        }
      });
      setTenant(updated);
    } catch (error) {
      toast.error(`Failed to ${dialogState} tenant`);
    } finally {
      setIsSubmitting(false);
      setDialogState(null);
    }
  };
  const statusConfig = {
    active: {
      label: "Active",
      variant: "success",
      icon: CheckCircle2
    },
    suspended: {
      label: "Suspended",
      variant: "warning",
      icon: AlertCircle
    },
    inactive: {
      label: "Inactive",
      variant: "destructive",
      icon: AlertCircle
    }
  };
  if (isLoading) {
    return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
      /* @__PURE__ */ jsx(Skeleton, { className: "h-8 w-48" }),
      /* @__PURE__ */ jsx("div", { className: "grid grid-cols-1 md:grid-cols-4 gap-4", children: [...Array(4)].map((_, i) => /* @__PURE__ */ jsx(Skeleton, { variant: "card" }, i)) }),
      /* @__PURE__ */ jsx(Skeleton, { variant: "card", className: "h-96" })
    ] });
  }
  if (!tenant) {
    return /* @__PURE__ */ jsxs("div", { className: "flex flex-col items-center justify-center py-20", children: [
      /* @__PURE__ */ jsx(AlertCircle, { className: "h-12 w-12 text-muted-foreground mb-4" }),
      /* @__PURE__ */ jsx("h2", { className: "text-xl font-semibold", children: "Tenant not found" }),
      /* @__PURE__ */ jsx("p", { className: "text-muted-foreground mb-4", children: "The tenant you're looking for doesn't exist" }),
      /* @__PURE__ */ jsx(Button, { asChild: true, children: /* @__PURE__ */ jsx(Link, { to: "/tenants", children: "Back to Tenants" }) })
    ] });
  }
  const statusKey = tenant.status ?? "inactive";
  const status = statusConfig[statusKey] || statusConfig.inactive;
  const StatusIcon = status.icon;
  const planKey = tenant.plan ?? "unknown";
  const planLabel = planKey === "unknown" ? "Unknown" : planKey.charAt(0).toUpperCase() + planKey.slice(1);
  const createdAtLabel = tenant.createdAt ? formatDate(tenant.createdAt) : "—";
  const createdAtDateTime = tenant.createdAt ? formatDateTime(tenant.createdAt) : "—";
  const updatedAtDateTime = tenant.updatedAt ? formatDateTime(tenant.updatedAt) : createdAtDateTime;
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: tenant.name ?? "Tenant", description: tenant.slug ?? "—", breadcrumbs: [{
      label: "Tenants",
      href: "/tenants"
    }, {
      label: tenant.name ?? "Tenant"
    }], actions: /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
      tenant.status === "active" ? /* @__PURE__ */ jsxs(Button, { variant: "outline", onClick: () => setDialogState("suspend"), children: [
        /* @__PURE__ */ jsx(Pause, { className: "mr-2 h-4 w-4" }),
        "Suspend"
      ] }) : /* @__PURE__ */ jsxs(Button, { variant: "outline", onClick: () => setDialogState("activate"), children: [
        /* @__PURE__ */ jsx(Play, { className: "mr-2 h-4 w-4" }),
        "Activate"
      ] }),
      /* @__PURE__ */ jsxs(Button, { variant: "destructive", onClick: () => setDialogState("delete"), children: [
        /* @__PURE__ */ jsx(Trash2, { className: "mr-2 h-4 w-4" }),
        "Delete"
      ] })
    ] }) }),
    /* @__PURE__ */ jsx(Card, { className: cn("border-l-4", tenant.status === "active" ? "border-l-green-500" : "border-l-amber-500"), children: /* @__PURE__ */ jsxs(CardContent, { className: "flex items-center justify-between py-4", children: [
      /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-4", children: [
        /* @__PURE__ */ jsx("div", { className: cn("p-2 rounded-full", tenant.status === "active" ? "bg-green-500/10" : "bg-amber-500/10"), children: /* @__PURE__ */ jsx(StatusIcon, { className: cn("h-5 w-5", tenant.status === "active" ? "text-green-600" : "text-amber-600") }) }),
        /* @__PURE__ */ jsxs("div", { children: [
          /* @__PURE__ */ jsx("p", { className: "font-medium", children: status.label }),
          /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: tenant.status === "active" ? "All services operational" : "Tenant access restricted" })
        ] })
      ] }),
      /* @__PURE__ */ jsx(Badge, { variant: status.variant, size: "lg", children: status.label })
    ] }) }),
    /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4", children: [
      /* @__PURE__ */ jsx(StatCard, { title: "Total Users", value: formatNumber(tenant.usage?.currentUsers ?? 0), icon: /* @__PURE__ */ jsx(Users, { className: "h-5 w-5" }), color: "blue" }),
      /* @__PURE__ */ jsx(StatCard, { title: "Plan", value: planLabel, icon: /* @__PURE__ */ jsx(CreditCard, { className: "h-5 w-5" }), color: "purple" }),
      /* @__PURE__ */ jsx(StatCard, { title: "Created", value: createdAtLabel, icon: /* @__PURE__ */ jsx(Calendar, { className: "h-5 w-5" }), color: "green" }),
      /* @__PURE__ */ jsx(StatCard, { title: "API Calls (24h)", value: formatNumber(2450), trend: {
        value: 12,
        isPositive: true
      }, icon: /* @__PURE__ */ jsx(Activity, { className: "h-5 w-5" }), color: "amber" })
    ] }),
    /* @__PURE__ */ jsxs(Tabs, { defaultValue: "overview", className: "space-y-6", children: [
      /* @__PURE__ */ jsxs(TabsList, { children: [
        /* @__PURE__ */ jsx(TabsTrigger, { value: "overview", children: "Overview" }),
        /* @__PURE__ */ jsx(TabsTrigger, { value: "usage", children: "Usage" }),
        /* @__PURE__ */ jsx(TabsTrigger, { value: "activity", children: "Activity" }),
        /* @__PURE__ */ jsx(TabsTrigger, { value: "settings", children: "Settings" })
      ] }),
      /* @__PURE__ */ jsx(TabsContent, { value: "overview", className: "space-y-6", children: /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-1 lg:grid-cols-2 gap-6", children: [
        /* @__PURE__ */ jsxs(Card, { children: [
          /* @__PURE__ */ jsx(CardHeader, { children: /* @__PURE__ */ jsx(CardTitle, { children: "Tenant Details" }) }),
          /* @__PURE__ */ jsx(CardContent, { className: "space-y-4", children: /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-2 gap-4", children: [
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Tenant ID" }),
              /* @__PURE__ */ jsx("p", { className: "font-medium font-mono text-sm", children: tenant.id ?? "—" })
            ] }),
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Slug" }),
              /* @__PURE__ */ jsx("p", { className: "font-medium", children: tenant.slug ?? "—" })
            ] }),
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Plan" }),
              /* @__PURE__ */ jsx(Badge, { variant: planKey === "enterprise" ? "warning" : planKey === "pro" ? "success" : "default", children: planLabel })
            ] }),
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Status" }),
              /* @__PURE__ */ jsx(Badge, { variant: status.variant, children: status.label })
            ] }),
            tenant.customDomain && /* @__PURE__ */ jsxs("div", { className: "col-span-2", children: [
              /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Custom Domain" }),
              /* @__PURE__ */ jsx("p", { className: "font-medium", children: tenant.customDomain })
            ] }),
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Created" }),
              /* @__PURE__ */ jsx("p", { className: "font-medium", children: createdAtDateTime })
            ] }),
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Last Updated" }),
              /* @__PURE__ */ jsx("p", { className: "font-medium", children: updatedAtDateTime })
            ] })
          ] }) })
        ] }),
        /* @__PURE__ */ jsxs(Card, { children: [
          /* @__PURE__ */ jsx(CardHeader, { children: /* @__PURE__ */ jsx(CardTitle, { children: "Owner Information" }) }),
          /* @__PURE__ */ jsx(CardContent, { className: "space-y-4", children: tenant.owner ? /* @__PURE__ */ jsxs(Fragment, { children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-4", children: [
              /* @__PURE__ */ jsx("div", { className: "h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center", children: /* @__PURE__ */ jsx(User, { className: "h-6 w-6 text-primary" }) }),
              /* @__PURE__ */ jsxs("div", { children: [
                /* @__PURE__ */ jsx("p", { className: "font-medium", children: tenant.owner.name || "Unknown" }),
                /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: tenant.owner.email ?? "unknown" })
              ] })
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "pt-4 border-t space-y-2", children: [
              /* @__PURE__ */ jsxs("div", { className: "flex justify-between text-sm", children: [
                /* @__PURE__ */ jsx("span", { className: "text-muted-foreground", children: "Email Verified" }),
                /* @__PURE__ */ jsx(Badge, { variant: "success", children: "Yes" })
              ] }),
              /* @__PURE__ */ jsxs("div", { className: "flex justify-between text-sm", children: [
                /* @__PURE__ */ jsx("span", { className: "text-muted-foreground", children: "Last Login" }),
                /* @__PURE__ */ jsx("span", { children: "2 hours ago" })
              ] })
            ] })
          ] }) : /* @__PURE__ */ jsxs("div", { className: "text-center py-8 text-muted-foreground", children: [
            /* @__PURE__ */ jsx(User, { className: "h-12 w-12 mx-auto mb-2 opacity-50" }),
            /* @__PURE__ */ jsx("p", { children: "No owner assigned" })
          ] }) })
        ] })
      ] }) }),
      /* @__PURE__ */ jsxs(TabsContent, { value: "usage", className: "space-y-6", children: [
        /* @__PURE__ */ jsxs(Card, { children: [
          /* @__PURE__ */ jsxs(CardHeader, { children: [
            /* @__PURE__ */ jsx(CardTitle, { children: "API Usage (Last 7 Days)" }),
            /* @__PURE__ */ jsx(CardDescription, { children: "Daily API calls and active users" })
          ] }),
          /* @__PURE__ */ jsx(CardContent, { children: /* @__PURE__ */ jsx("div", { className: "h-[300px]", children: /* @__PURE__ */ jsx(ResponsiveContainer, { width: "100%", height: "100%", children: /* @__PURE__ */ jsxs(AreaChart, { data: usageData, children: [
            /* @__PURE__ */ jsx("defs", { children: /* @__PURE__ */ jsxs("linearGradient", { id: "colorApi", x1: "0", y1: "0", x2: "0", y2: "1", children: [
              /* @__PURE__ */ jsx("stop", { offset: "5%", stopColor: "#6366f1", stopOpacity: 0.3 }),
              /* @__PURE__ */ jsx("stop", { offset: "95%", stopColor: "#6366f1", stopOpacity: 0 })
            ] }) }),
            /* @__PURE__ */ jsx(CartesianGrid, { strokeDasharray: "3 3", stroke: "#e2e8f0" }),
            /* @__PURE__ */ jsx(XAxis, { dataKey: "day", stroke: "#64748b", fontSize: 12 }),
            /* @__PURE__ */ jsx(YAxis, { stroke: "#64748b", fontSize: 12 }),
            /* @__PURE__ */ jsx(Tooltip, {}),
            /* @__PURE__ */ jsx(Area, { type: "monotone", dataKey: "apiCalls", stroke: "#6366f1", strokeWidth: 2, fillOpacity: 1, fill: "url(#colorApi)", name: "API Calls" })
          ] }) }) }) })
        ] }),
        /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-1 md:grid-cols-3 gap-4", children: [
          /* @__PURE__ */ jsx(Card, { children: /* @__PURE__ */ jsxs(CardContent, { className: "pt-6", children: [
            /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "API Calls (This Month)" }),
            /* @__PURE__ */ jsx("p", { className: "text-2xl font-bold mt-1", children: formatNumber(45200) }),
            /* @__PURE__ */ jsx("p", { className: "text-sm text-green-600 mt-1", children: "↑ 12% from last month" })
          ] }) }),
          /* @__PURE__ */ jsx(Card, { children: /* @__PURE__ */ jsxs(CardContent, { className: "pt-6", children: [
            /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Storage Used" }),
            /* @__PURE__ */ jsx("p", { className: "text-2xl font-bold mt-1", children: "2.4 GB" }),
            /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground mt-1", children: "of 10 GB limit" })
          ] }) }),
          /* @__PURE__ */ jsx(Card, { children: /* @__PURE__ */ jsxs(CardContent, { className: "pt-6", children: [
            /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Active Sessions" }),
            /* @__PURE__ */ jsx("p", { className: "text-2xl font-bold mt-1", children: formatNumber(156) }),
            /* @__PURE__ */ jsx("p", { className: "text-sm text-green-600 mt-1", children: "↑ 5% from yesterday" })
          ] }) })
        ] })
      ] }),
      /* @__PURE__ */ jsx(TabsContent, { value: "activity", className: "space-y-6", children: /* @__PURE__ */ jsxs(Card, { children: [
        /* @__PURE__ */ jsx(CardHeader, { children: /* @__PURE__ */ jsx(CardTitle, { children: "Recent Activity" }) }),
        /* @__PURE__ */ jsx(CardContent, { children: /* @__PURE__ */ jsx("div", { className: "space-y-4", children: recentActivity.map((activity, index) => /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
          opacity: 0,
          x: -20
        }, animate: {
          opacity: 1,
          x: 0
        }, transition: prefersReducedMotion ? {
          duration: 0
        } : {
          delay: index * 0.05
        }, className: "flex items-start gap-4 p-3 rounded-lg hover:bg-muted/50 transition-colors", children: [
          /* @__PURE__ */ jsx("div", { className: cn("p-2 rounded-full shrink-0", activity.status === "success" && "bg-green-500/10 text-green-600", activity.status === "error" && "bg-red-500/10 text-red-600"), children: activity.status === "success" ? /* @__PURE__ */ jsx(CheckCircle2, { className: "h-4 w-4" }) : /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4" }) }),
          /* @__PURE__ */ jsxs("div", { className: "flex-1", children: [
            /* @__PURE__ */ jsx("p", { className: "text-sm font-medium", children: activity.action }),
            /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: activity.user })
          ] }),
          /* @__PURE__ */ jsx("span", { className: "text-xs text-muted-foreground", children: /* @__PURE__ */ jsx("span", { title: activity.timestamp, children: formatRelativeTime(activity.timestamp) }) })
        ] }, activity.id)) }) })
      ] }) }),
      /* @__PURE__ */ jsx(TabsContent, { value: "settings", className: "space-y-6", children: /* @__PURE__ */ jsxs(Card, { children: [
        /* @__PURE__ */ jsxs(CardHeader, { children: [
          /* @__PURE__ */ jsx(CardTitle, { children: "Danger Zone" }),
          /* @__PURE__ */ jsx(CardDescription, { children: "Destructive actions for this tenant" })
        ] }),
        /* @__PURE__ */ jsx(CardContent, { className: "space-y-4", children: /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between p-4 border border-destructive/20 rounded-lg bg-destructive/5", children: [
          /* @__PURE__ */ jsxs("div", { children: [
            /* @__PURE__ */ jsx("p", { className: "font-medium text-destructive", children: "Delete Tenant" }),
            /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Permanently delete this tenant and all associated data" })
          ] }),
          /* @__PURE__ */ jsx(Button, { variant: "destructive", onClick: () => setDialogState("delete"), children: "Delete" })
        ] }) })
      ] }) })
    ] }),
    /* @__PURE__ */ jsx(ConfirmDialog, { isOpen: dialogState === "suspend", onClose: () => setDialogState(null), onConfirm: handleAction, title: "Suspend Tenant", description: `Are you sure you want to suspend "${tenant.name}"? This will prevent users from accessing the tenant.`, confirmText: "Suspend", variant: "destructive", isLoading: isSubmitting }),
    /* @__PURE__ */ jsx(ConfirmDialog, { isOpen: dialogState === "activate", onClose: () => setDialogState(null), onConfirm: handleAction, title: "Activate Tenant", description: `Are you sure you want to activate "${tenant.name}"?`, confirmText: "Activate", isLoading: isSubmitting }),
    /* @__PURE__ */ jsx(ConfirmDialog, { isOpen: dialogState === "delete", onClose: () => setDialogState(null), onConfirm: handleAction, title: "Delete Tenant", description: `Are you sure you want to delete "${tenant.name}"? This action cannot be undone.`, confirmText: "Delete", variant: "destructive", isLoading: isSubmitting })
  ] });
}
export {
  TenantDetailPage as component
};
