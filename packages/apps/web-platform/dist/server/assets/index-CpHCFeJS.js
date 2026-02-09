import { jsxs, jsx, Fragment } from "react/jsx-runtime";
import { useState, useEffect, Suspense, lazy } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { Info, Building2, Users, CreditCard, Activity, CheckCircle2, AlertCircle } from "lucide-react";
import { P as PageHeader, S as StatCard, i as formatNumber, j as formatCurrency, a as Badge, c as cn, h as formatRelativeTime } from "./router-BqFKwE1w.js";
import { C as Card, d as CardContent, b as CardTitle, c as CardDescription, a as CardHeader } from "./Card-DiqECnNB.js";
import { S as SkeletonStatCard, a as Skeleton } from "./Skeleton-RwodY-mL.js";
import { u as useServerFn } from "../server.js";
import { b as getPlatformOverview } from "./internal-api-DaRn9LSO.js";
import { c as clientLogger } from "./client-logger-DdKNJYmy.js";
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
const GrowthChart = lazy(() => import("./GrowthChart-C6Nbsonk.js"));
const PlanDistributionChart = lazy(() => import("./PlanDistributionChart-iC-Qyeyw.js"));
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
  const hasNoData = !isLoading && !overview;
  const dashboard = overview;
  const trend = (value) => typeof value === "number" ? {
    value: Math.abs(value),
    isPositive: value >= 0
  } : void 0;
  return /* @__PURE__ */ jsxs("div", { className: "space-y-8", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "Dashboard", description: "Overview of your platform's performance and key metrics" }),
    hasNoData ? /* @__PURE__ */ jsx(Card, { children: /* @__PURE__ */ jsxs(CardContent, { className: "flex flex-col items-center justify-center py-12 text-center", children: [
      /* @__PURE__ */ jsx(Info, { className: "h-12 w-12 text-muted-foreground mb-4" }),
      /* @__PURE__ */ jsx(CardTitle, { className: "text-lg mb-2", children: "No Data Available" }),
      /* @__PURE__ */ jsx(CardDescription, { children: "Platform overview data is not available. Please check back later or contact support." })
    ] }) }) : /* @__PURE__ */ jsxs(Fragment, { children: [
      /* @__PURE__ */ jsx("div", { className: "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4", children: isLoading ? /* @__PURE__ */ jsxs(Fragment, { children: [
        /* @__PURE__ */ jsx(SkeletonStatCard, {}),
        /* @__PURE__ */ jsx(SkeletonStatCard, {}),
        /* @__PURE__ */ jsx(SkeletonStatCard, {}),
        /* @__PURE__ */ jsx(SkeletonStatCard, {})
      ] }) : /* @__PURE__ */ jsxs(Fragment, { children: [
        /* @__PURE__ */ jsx(StatCard, { title: "Total Tenants", value: formatNumber(overview?.tenants?.total ?? 0), trend: trend(dashboard?.tenants?.trend), icon: /* @__PURE__ */ jsx(Building2, { className: "h-5 w-5" }), color: "blue" }),
        /* @__PURE__ */ jsx(StatCard, { title: "Active Users", value: formatNumber(overview?.users?.total ?? 0), trend: trend(dashboard?.users?.trend), icon: /* @__PURE__ */ jsx(Users, { className: "h-5 w-5" }), color: "green" }),
        /* @__PURE__ */ jsx(StatCard, { title: "Monthly Revenue", value: formatCurrency(overview?.revenue?.mrr ?? 0), trend: trend(dashboard?.revenue?.trend), icon: /* @__PURE__ */ jsx(CreditCard, { className: "h-5 w-5" }), color: "purple" }),
        /* @__PURE__ */ jsx(StatCard, { title: "API Calls (24h)", value: formatNumber(overview?.system?.totalApiCalls24h ?? 0), trend: trend(dashboard?.system?.apiCallsTrend), icon: /* @__PURE__ */ jsx(Activity, { className: "h-5 w-5" }), color: "amber" })
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
          /* @__PURE__ */ jsx(CardContent, { children: /* @__PURE__ */ jsx("div", { className: "h-[300px]", children: /* @__PURE__ */ jsx(Suspense, { fallback: /* @__PURE__ */ jsx(Skeleton, { className: "h-[300px] w-full" }), children: dashboard?.growth?.length ? /* @__PURE__ */ jsx(GrowthChart, { data: dashboard.growth }) : /* @__PURE__ */ jsx("div", { className: "flex items-center justify-center h-full text-muted-foreground", children: "No growth data available" }) }) }) })
        ] }),
        /* @__PURE__ */ jsxs(Card, { children: [
          /* @__PURE__ */ jsxs(CardHeader, { children: [
            /* @__PURE__ */ jsx(CardTitle, { children: "Plan Distribution" }),
            /* @__PURE__ */ jsx(CardDescription, { children: "Breakdown by subscription tier" })
          ] }),
          /* @__PURE__ */ jsxs(CardContent, { children: [
            /* @__PURE__ */ jsx("div", { className: "h-[200px]", children: /* @__PURE__ */ jsx(Suspense, { fallback: /* @__PURE__ */ jsx(Skeleton, { className: "h-[200px] w-full" }), children: dashboard?.planDistribution?.length ? /* @__PURE__ */ jsx(PlanDistributionChart, { data: dashboard.planDistribution }) : /* @__PURE__ */ jsx("div", { className: "flex items-center justify-center h-full text-muted-foreground", children: "No plan data available" }) }) }),
            dashboard?.planDistribution?.length ? /* @__PURE__ */ jsx("div", { className: "mt-4 space-y-2", children: dashboard.planDistribution.map((plan) => /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between text-sm", children: [
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
            ] }, plan.name)) }) : null
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-1 lg:grid-cols-3 gap-6", children: [
        /* @__PURE__ */ jsxs(Card, { className: "lg:col-span-2", children: [
          /* @__PURE__ */ jsxs(CardHeader, { children: [
            /* @__PURE__ */ jsx(CardTitle, { children: "Recent Activity" }),
            /* @__PURE__ */ jsx(CardDescription, { children: "Latest actions across the platform" })
          ] }),
          /* @__PURE__ */ jsx(CardContent, { children: dashboard?.recentActivity?.length ? /* @__PURE__ */ jsx("div", { className: "space-y-4", children: dashboard.recentActivity.map((activity, index) => /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
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
              (activity.status === "warning" || activity.status === "error") && /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4" })
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
          ] }, activity.id)) }) : /* @__PURE__ */ jsxs("div", { className: "text-center py-8 text-muted-foreground", children: [
            /* @__PURE__ */ jsx(Info, { className: "h-8 w-8 mx-auto mb-2" }),
            /* @__PURE__ */ jsx("p", { children: "No recent activity" })
          ] }) })
        ] }),
        /* @__PURE__ */ jsxs(Card, { children: [
          /* @__PURE__ */ jsxs(CardHeader, { children: [
            /* @__PURE__ */ jsx(CardTitle, { children: "System Status" }),
            /* @__PURE__ */ jsx(CardDescription, { children: "Current platform health" })
          ] }),
          /* @__PURE__ */ jsx(CardContent, { children: dashboard?.systemStatus?.services?.length ? /* @__PURE__ */ jsxs(Fragment, { children: [
            /* @__PURE__ */ jsx("div", { className: "space-y-4", children: dashboard.systemStatus.services.map((service) => /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
              /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
                /* @__PURE__ */ jsx("div", { className: cn("w-2 h-2 rounded-full", service.status === "operational" && "bg-green-500", service.status === "degraded" && "bg-amber-500", service.status === "down" && "bg-red-500"), "aria-hidden": "true" }),
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
                /* @__PURE__ */ jsxs("span", { className: "font-medium", children: [
                  dashboard.systemStatus.uptime,
                  "%"
                ] })
              ] }),
              /* @__PURE__ */ jsx("div", { className: "mt-2 h-2 bg-muted rounded-full overflow-hidden", children: /* @__PURE__ */ jsx("div", { className: "h-full bg-green-500 rounded-full", style: {
                width: `${dashboard.systemStatus.uptime}%`
              } }) })
            ] })
          ] }) : /* @__PURE__ */ jsxs("div", { className: "text-center py-8 text-muted-foreground", children: [
            /* @__PURE__ */ jsx(Info, { className: "h-8 w-8 mx-auto mb-2" }),
            /* @__PURE__ */ jsx("p", { children: "System status unavailable" })
          ] }) })
        ] })
      ] })
    ] })
  ] });
}
export {
  DashboardPage as component
};
