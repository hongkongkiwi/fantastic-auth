import { jsxs, jsx, Fragment } from "react/jsx-runtime";
import { useState, useEffect, Suspense, lazy } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { Building2, Users, CreditCard, Activity, CheckCircle2, AlertCircle } from "lucide-react";
import { u as useServerFn, P as PageHeader, S as StatCard, k as formatNumber, v as formatCurrency, o as formatRelativeTime, w as getPlatformOverview } from "./router-BDwxh4pl.js";
import { C as Card, a as CardHeader, b as CardTitle, c as CardDescription, d as CardContent } from "./Card-Brxgy2gk.js";
import { B as Badge } from "./Badge-DmGWtXSM.js";
import { S as SkeletonStatCard, a as Skeleton } from "./Skeleton-CdKpSX4m.js";
import { c as clientLogger } from "./client-logger-hw3lJpbz.js";
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
import "clsx";
import "tailwind-merge";
import "@radix-ui/react-slot";
import "class-variance-authority";
import "@radix-ui/react-dialog";
import "cmdk";
import "@sentry/react";
const GrowthChart = lazy(() => import("./GrowthChart-C6Nbsonk.js"));
const PlanDistributionChart = lazy(() => import("./PlanDistributionChart-iC-Qyeyw.js"));
const tenantGrowthData = [{
  month: "Jan",
  tenants: 45,
  users: 1200
}, {
  month: "Feb",
  tenants: 52,
  users: 1450
}, {
  month: "Mar",
  tenants: 58,
  users: 1680
}, {
  month: "Apr",
  tenants: 65,
  users: 1920
}, {
  month: "May",
  tenants: 72,
  users: 2150
}, {
  month: "Jun",
  tenants: 85,
  users: 2480
}];
const planDistribution = [{
  name: "Free",
  value: 35,
  color: "#94a3b8"
}, {
  name: "Starter",
  value: 28,
  color: "#6366f1"
}, {
  name: "Pro",
  value: 18,
  color: "#8b5cf6"
}, {
  name: "Enterprise",
  value: 4,
  color: "#ec4899"
}];
const now = Date.now();
const recentActivity = [{
  id: 1,
  action: "Tenant Created",
  tenant: "Acme Corp",
  user: "John Doe",
  timestamp: new Date(now - 2 * 60 * 1e3).toISOString(),
  status: "success"
}, {
  id: 2,
  action: "Subscription Updated",
  tenant: "TechStart Inc",
  user: "Jane Smith",
  timestamp: new Date(now - 5 * 60 * 1e3).toISOString(),
  status: "success"
}, {
  id: 3,
  action: "User Suspended",
  tenant: "Beta LLC",
  user: "Admin",
  timestamp: new Date(now - 12 * 60 * 1e3).toISOString(),
  status: "warning"
}, {
  id: 4,
  action: "Invoice Generated",
  tenant: "Gamma Co",
  user: "System",
  timestamp: new Date(now - 15 * 60 * 1e3).toISOString(),
  status: "success"
}, {
  id: 5,
  action: "Payment Failed",
  tenant: "Delta Ltd",
  user: "System",
  timestamp: new Date(now - 23 * 60 * 1e3).toISOString(),
  status: "error"
}];
function DashboardPage() {
  const [isLoading, setIsLoading] = useState(true);
  const [overview, setOverview] = useState(null);
  const getOverview = useServerFn(getPlatformOverview);
  const prefersReducedMotion = useReducedMotion();
  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await getOverview({
          data: {}
        });
        setOverview(data);
      } catch (error) {
        clientLogger.error("Failed to fetch overview", error);
      } finally {
        setIsLoading(false);
      }
    };
    fetchData();
  }, [getOverview]);
  const trends = {
    tenants: {
      value: 12,
      isPositive: true
    },
    users: {
      value: 8.5,
      isPositive: true
    },
    mrr: {
      value: 15.3,
      isPositive: true
    },
    apiCalls: {
      value: 3.2,
      isPositive: false
    }
  };
  return /* @__PURE__ */ jsxs("div", { className: "space-y-8", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "Dashboard", description: "Overview of your platform's performance and key metrics" }),
    /* @__PURE__ */ jsx("div", { className: "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4", children: isLoading ? /* @__PURE__ */ jsxs(Fragment, { children: [
      /* @__PURE__ */ jsx(SkeletonStatCard, {}),
      /* @__PURE__ */ jsx(SkeletonStatCard, {}),
      /* @__PURE__ */ jsx(SkeletonStatCard, {}),
      /* @__PURE__ */ jsx(SkeletonStatCard, {})
    ] }) : /* @__PURE__ */ jsxs(Fragment, { children: [
      /* @__PURE__ */ jsx(StatCard, { title: "Total Tenants", value: formatNumber(overview?.tenants?.total ?? 85), trend: trends.tenants, icon: /* @__PURE__ */ jsx(Building2, { className: "h-5 w-5" }), color: "blue" }),
      /* @__PURE__ */ jsx(StatCard, { title: "Active Users", value: formatNumber(overview?.users?.total ?? 2480), trend: trends.users, icon: /* @__PURE__ */ jsx(Users, { className: "h-5 w-5" }), color: "green" }),
      /* @__PURE__ */ jsx(StatCard, { title: "Monthly Revenue", value: formatCurrency(overview?.revenue?.mrr ?? 12500), trend: trends.mrr, icon: /* @__PURE__ */ jsx(CreditCard, { className: "h-5 w-5" }), color: "purple" }),
      /* @__PURE__ */ jsx(StatCard, { title: "API Calls (24h)", value: formatNumber(overview?.system?.totalApiCalls24h ?? 45200), trend: trends.apiCalls, icon: /* @__PURE__ */ jsx(Activity, { className: "h-5 w-5" }), color: "amber" })
    ] }) }),
    /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-1 lg:grid-cols-3 gap-6", children: [
      /* @__PURE__ */ jsxs(Card, { className: "lg:col-span-2", children: [
        /* @__PURE__ */ jsxs(CardHeader, { className: "flex flex-row items-center justify-between", children: [
          /* @__PURE__ */ jsxs("div", { children: [
            /* @__PURE__ */ jsx(CardTitle, { children: "Growth Overview" }),
            /* @__PURE__ */ jsx(CardDescription, { children: "Tenant and user growth over the last 6 months" })
          ] }),
          /* @__PURE__ */ jsx(Badge, { variant: "muted", children: "Last 6 months" })
        ] }),
        /* @__PURE__ */ jsx(CardContent, { children: /* @__PURE__ */ jsx("div", { className: "h-[300px]", children: /* @__PURE__ */ jsx(Suspense, { fallback: /* @__PURE__ */ jsx(Skeleton, { className: "h-[300px] w-full" }), children: /* @__PURE__ */ jsx(GrowthChart, { data: tenantGrowthData }) }) }) })
      ] }),
      /* @__PURE__ */ jsxs(Card, { children: [
        /* @__PURE__ */ jsxs(CardHeader, { children: [
          /* @__PURE__ */ jsx(CardTitle, { children: "Plan Distribution" }),
          /* @__PURE__ */ jsx(CardDescription, { children: "Breakdown by subscription tier" })
        ] }),
        /* @__PURE__ */ jsxs(CardContent, { children: [
          /* @__PURE__ */ jsx("div", { className: "h-[200px]", children: /* @__PURE__ */ jsx(Suspense, { fallback: /* @__PURE__ */ jsx(Skeleton, { className: "h-[200px] w-full" }), children: /* @__PURE__ */ jsx(PlanDistributionChart, { data: planDistribution }) }) }),
          /* @__PURE__ */ jsx("div", { className: "mt-4 space-y-2", children: planDistribution.map((plan) => /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between text-sm", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
              /* @__PURE__ */ jsx("div", { className: "w-3 h-3 rounded-full", style: {
                backgroundColor: plan.color
              } }),
              /* @__PURE__ */ jsx("span", { className: "text-muted-foreground", children: plan.name })
            ] }),
            /* @__PURE__ */ jsxs("span", { className: "font-medium", children: [
              plan.value,
              "%"
            ] })
          ] }, plan.name)) })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-1 lg:grid-cols-3 gap-6", children: [
      /* @__PURE__ */ jsxs(Card, { className: "lg:col-span-2", children: [
        /* @__PURE__ */ jsxs(CardHeader, { children: [
          /* @__PURE__ */ jsx(CardTitle, { children: "Recent Activity" }),
          /* @__PURE__ */ jsx(CardDescription, { children: "Latest actions across the platform" })
        ] }),
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
          /* @__PURE__ */ jsxs("div", { className: cn("p-2 rounded-full shrink-0", activity.status === "success" && "bg-green-500/10 text-green-600", activity.status === "warning" && "bg-amber-500/10 text-amber-600", activity.status === "error" && "bg-red-500/10 text-red-600"), children: [
            activity.status === "success" && /* @__PURE__ */ jsx(CheckCircle2, { className: "h-4 w-4" }),
            activity.status === "warning" && /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4" }),
            activity.status === "error" && /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4" })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "flex-1 min-w-0", children: [
            /* @__PURE__ */ jsx("p", { className: "text-sm font-medium", children: activity.action }),
            /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground", children: [
              activity.tenant,
              " • ",
              activity.user
            ] })
          ] }),
          /* @__PURE__ */ jsx("span", { className: "text-xs text-muted-foreground whitespace-nowrap", children: /* @__PURE__ */ jsx("span", { title: activity.timestamp, children: formatRelativeTime(activity.timestamp) }) })
        ] }, activity.id)) }) })
      ] }),
      /* @__PURE__ */ jsxs(Card, { children: [
        /* @__PURE__ */ jsxs(CardHeader, { children: [
          /* @__PURE__ */ jsx(CardTitle, { children: "System Status" }),
          /* @__PURE__ */ jsx(CardDescription, { children: "Current platform health" })
        ] }),
        /* @__PURE__ */ jsxs(CardContent, { children: [
          /* @__PURE__ */ jsx("div", { className: "space-y-4", children: [{
            name: "API Gateway",
            status: "operational",
            latency: "45ms"
          }, {
            name: "Database",
            status: "operational",
            latency: "12ms"
          }, {
            name: "Auth Service",
            status: "operational",
            latency: "28ms"
          }, {
            name: "Email Service",
            status: "degraded",
            latency: "340ms"
          }].map((service) => /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
              /* @__PURE__ */ jsx("div", { className: cn("w-2 h-2 rounded-full", service.status === "operational" && "bg-green-500", service.status === "degraded" && "bg-amber-500", service.status === "down" && "bg-red-500") }),
              /* @__PURE__ */ jsx("span", { className: "text-sm font-medium", children: service.name })
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
              /* @__PURE__ */ jsx("span", { className: "text-xs text-muted-foreground", children: service.latency }),
              /* @__PURE__ */ jsx(Badge, { variant: service.status === "operational" ? "success" : service.status === "degraded" ? "warning" : "destructive", size: "sm", children: service.status })
            ] })
          ] }, service.name)) }),
          /* @__PURE__ */ jsxs("div", { className: "mt-6 pt-6 border-t", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between text-sm", children: [
              /* @__PURE__ */ jsx("span", { className: "text-muted-foreground", children: "Uptime (30d)" }),
              /* @__PURE__ */ jsx("span", { className: "font-medium", children: "99.98%" })
            ] }),
            /* @__PURE__ */ jsx("div", { className: "mt-2 h-2 bg-muted rounded-full overflow-hidden", children: /* @__PURE__ */ jsx("div", { className: "h-full w-[99.98%] bg-green-500 rounded-full" }) })
          ] })
        ] })
      ] })
    ] })
  ] });
}
function cn(...classes) {
  return classes.filter(Boolean).join(" ");
}
export {
  DashboardPage as component
};
