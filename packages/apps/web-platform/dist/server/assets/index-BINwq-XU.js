import { jsxs, jsx } from "react/jsx-runtime";
import { Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { DollarSign, TrendingUp, CheckCircle2, AlertCircle, FileText, MoreHorizontal, Download } from "lucide-react";
import { P as PageHeader, S as StatCard, j as formatCurrency, B as Button, c as cn, a as Badge, t as toast } from "./router-BqFKwE1w.js";
import { D as DataTable, a as createStatusBadge, b as createDateCell } from "./DataTable-qvjqCqsN.js";
import { C as Card, a as CardHeader, b as CardTitle, c as CardDescription, d as CardContent } from "./Card-DiqECnNB.js";
import { T as Tabs, a as TabsList, b as TabsTrigger, c as TabsContent } from "./Tabs-Dlqc7sYx.js";
import { D as DropdownMenu, a as DropdownMenuTrigger, b as DropdownMenuContent, c as DropdownMenuItem } from "./DropdownMenu-B1r5JY9H.js";
import { u as useServerFn } from "../server.js";
import { h as listSubscriptions } from "./internal-api-DaRn9LSO.js";
import { ResponsiveContainer, AreaChart, CartesianGrid, XAxis, YAxis, Tooltip, Area, BarChart, Bar } from "recharts";
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
import "@tanstack/react-table";
import "./Input-D8nMsmC2.js";
import "@radix-ui/react-tabs";
import "@radix-ui/react-dropdown-menu";
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
const revenueData = [{
  month: "Jan",
  revenue: 12500,
  target: 12e3
}, {
  month: "Feb",
  revenue: 14200,
  target: 13e3
}, {
  month: "Mar",
  revenue: 15800,
  target: 14e3
}, {
  month: "Apr",
  revenue: 17100,
  target: 15e3
}, {
  month: "May",
  revenue: 18900,
  target: 16e3
}, {
  month: "Jun",
  revenue: 21500,
  target: 18e3
}];
const statusConfig = {
  active: {
    label: "Active",
    variant: "success"
  },
  past_due: {
    label: "Past Due",
    variant: "warning"
  },
  canceled: {
    label: "Canceled",
    variant: "destructive"
  },
  trialing: {
    label: "Trialing",
    variant: "default"
  }
};
function BillingPage() {
  const [subscriptions, setSubscriptions] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("overview");
  const prefersReducedMotion = useReducedMotion();
  const listSubscriptionsFn = useServerFn(listSubscriptions);
  useEffect(() => {
    const fetchSubscriptions = async () => {
      setIsLoading(true);
      try {
        const result = await listSubscriptionsFn({
          data: {}
        });
        setSubscriptions(result.data || []);
      } catch (error) {
        toast.error("Failed to load subscriptions");
      } finally {
        setIsLoading(false);
      }
    };
    fetchSubscriptions();
  }, []);
  const columns = [{
    accessorKey: "tenantId",
    header: "Tenant",
    cell: ({
      row
    }) => /* @__PURE__ */ jsxs("div", { children: [
      /* @__PURE__ */ jsx("p", { className: "font-medium", children: row.getValue("tenantId") || "—" }),
      /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: row.original.id ?? "—" })
    ] })
  }, {
    accessorKey: "plan",
    header: "Plan",
    cell: ({
      getValue
    }) => /* @__PURE__ */ jsx(Badge, { variant: getValue() === "enterprise" ? "warning" : getValue() === "pro" ? "success" : "default", children: getValue().charAt(0).toUpperCase() + getValue().slice(1) })
  }, {
    accessorKey: "status",
    header: "Status",
    cell: createStatusBadge(statusConfig)
  }, {
    accessorKey: "amount",
    header: "Amount",
    cell: ({
      row
    }) => formatCurrency(row.original.amount?.total ?? 0)
  }, {
    accessorKey: "currentPeriodEnd",
    header: "Renews",
    cell: createDateCell()
  }, {
    id: "actions",
    header: "",
    cell: () => /* @__PURE__ */ jsxs(DropdownMenu, { children: [
      /* @__PURE__ */ jsx(DropdownMenuTrigger, { asChild: true, children: /* @__PURE__ */ jsx(Button, { variant: "ghost", size: "icon-sm", "aria-label": "Open subscription actions", children: /* @__PURE__ */ jsx(MoreHorizontal, { className: "h-4 w-4" }) }) }),
      /* @__PURE__ */ jsxs(DropdownMenuContent, { align: "end", children: [
        /* @__PURE__ */ jsxs(DropdownMenuItem, { children: [
          /* @__PURE__ */ jsx(FileText, { className: "mr-2 h-4 w-4" }),
          "View Invoices"
        ] }),
        /* @__PURE__ */ jsxs(DropdownMenuItem, { children: [
          /* @__PURE__ */ jsx(Download, { className: "mr-2 h-4 w-4" }),
          "Download Statement"
        ] })
      ] })
    ] })
  }];
  const stats = {
    mrr: 21500,
    arr: 258e3,
    growth: 12.5,
    activeSubs: subscriptions.length || 85,
    pastDue: 3
  };
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "Billing", description: "Manage subscriptions, invoices, and revenue", breadcrumbs: [{
      label: "Billing"
    }] }),
    /* @__PURE__ */ jsxs(Tabs, { value: activeTab, onValueChange: setActiveTab, className: "space-y-6", children: [
      /* @__PURE__ */ jsxs(TabsList, { children: [
        /* @__PURE__ */ jsx(TabsTrigger, { value: "overview", children: "Overview" }),
        /* @__PURE__ */ jsx(TabsTrigger, { value: "subscriptions", children: "Subscriptions" }),
        /* @__PURE__ */ jsx(TabsTrigger, { value: "invoices", children: "Invoices" })
      ] }),
      /* @__PURE__ */ jsxs(TabsContent, { value: "overview", className: "space-y-6", children: [
        /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4", children: [
          /* @__PURE__ */ jsx(StatCard, { title: "Monthly Recurring Revenue", value: formatCurrency(stats.mrr), trend: {
            value: stats.growth,
            isPositive: true
          }, icon: /* @__PURE__ */ jsx(DollarSign, { className: "h-5 w-5" }), color: "green" }),
          /* @__PURE__ */ jsx(StatCard, { title: "Annual Run Rate", value: formatCurrency(stats.arr), icon: /* @__PURE__ */ jsx(TrendingUp, { className: "h-5 w-5" }), color: "blue" }),
          /* @__PURE__ */ jsx(StatCard, { title: "Active Subscriptions", value: stats.activeSubs, icon: /* @__PURE__ */ jsx(CheckCircle2, { className: "h-5 w-5" }), color: "purple" }),
          /* @__PURE__ */ jsx(StatCard, { title: "Past Due", value: stats.pastDue, icon: /* @__PURE__ */ jsx(AlertCircle, { className: "h-5 w-5" }), color: "rose" })
        ] }),
        /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-1 lg:grid-cols-2 gap-6", children: [
          /* @__PURE__ */ jsxs(Card, { children: [
            /* @__PURE__ */ jsxs(CardHeader, { children: [
              /* @__PURE__ */ jsx(CardTitle, { children: "Revenue Overview" }),
              /* @__PURE__ */ jsx(CardDescription, { children: "Monthly recurring revenue vs target" })
            ] }),
            /* @__PURE__ */ jsx(CardContent, { children: /* @__PURE__ */ jsx("div", { className: "h-[300px]", children: /* @__PURE__ */ jsx(ResponsiveContainer, { width: "100%", height: "100%", children: /* @__PURE__ */ jsxs(AreaChart, { data: revenueData, children: [
              /* @__PURE__ */ jsx("defs", { children: /* @__PURE__ */ jsxs("linearGradient", { id: "colorRevenue", x1: "0", y1: "0", x2: "0", y2: "1", children: [
                /* @__PURE__ */ jsx("stop", { offset: "5%", stopColor: "#10b981", stopOpacity: 0.3 }),
                /* @__PURE__ */ jsx("stop", { offset: "95%", stopColor: "#10b981", stopOpacity: 0 })
              ] }) }),
              /* @__PURE__ */ jsx(CartesianGrid, { strokeDasharray: "3 3", stroke: "#e2e8f0" }),
              /* @__PURE__ */ jsx(XAxis, { dataKey: "month", stroke: "#64748b", fontSize: 12 }),
              /* @__PURE__ */ jsx(YAxis, { stroke: "#64748b", fontSize: 12, tickFormatter: (v) => `$${Number(v) / 1e3}k` }),
              /* @__PURE__ */ jsx(Tooltip, { formatter: (value) => formatCurrency(Number(value ?? 0)) }),
              /* @__PURE__ */ jsx(Area, { type: "monotone", dataKey: "revenue", stroke: "#10b981", strokeWidth: 2, fillOpacity: 1, fill: "url(#colorRevenue)", name: "Revenue" })
            ] }) }) }) })
          ] }),
          /* @__PURE__ */ jsxs(Card, { children: [
            /* @__PURE__ */ jsxs(CardHeader, { children: [
              /* @__PURE__ */ jsx(CardTitle, { children: "Plan Distribution" }),
              /* @__PURE__ */ jsx(CardDescription, { children: "Subscriptions by plan tier" })
            ] }),
            /* @__PURE__ */ jsx(CardContent, { children: /* @__PURE__ */ jsx("div", { className: "h-[300px]", children: /* @__PURE__ */ jsx(ResponsiveContainer, { width: "100%", height: "100%", children: /* @__PURE__ */ jsxs(BarChart, { data: [{
              name: "Free",
              value: 35
            }, {
              name: "Starter",
              value: 28
            }, {
              name: "Pro",
              value: 18
            }, {
              name: "Enterprise",
              value: 4
            }], children: [
              /* @__PURE__ */ jsx(CartesianGrid, { strokeDasharray: "3 3", stroke: "#e2e8f0" }),
              /* @__PURE__ */ jsx(XAxis, { dataKey: "name", stroke: "#64748b", fontSize: 12 }),
              /* @__PURE__ */ jsx(YAxis, { stroke: "#64748b", fontSize: 12 }),
              /* @__PURE__ */ jsx(Tooltip, {}),
              /* @__PURE__ */ jsx(Bar, { dataKey: "value", fill: "#6366f1", radius: [4, 4, 0, 0] })
            ] }) }) }) })
          ] })
        ] }),
        /* @__PURE__ */ jsxs(Card, { children: [
          /* @__PURE__ */ jsxs(CardHeader, { className: "flex flex-row items-center justify-between", children: [
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx(CardTitle, { children: "Recent Invoices" }),
              /* @__PURE__ */ jsx(CardDescription, { children: "Latest billing activity" })
            ] }),
            /* @__PURE__ */ jsx(Button, { variant: "outline", size: "sm", asChild: true, children: /* @__PURE__ */ jsx(Link, { to: "/billing", children: "View All" }) })
          ] }),
          /* @__PURE__ */ jsx(CardContent, { children: /* @__PURE__ */ jsx("div", { className: "space-y-4", children: [{
            id: "INV-001",
            tenant: "Acme Corp",
            amount: 299,
            status: "paid",
            date: "2024-01-15"
          }, {
            id: "INV-002",
            tenant: "TechStart Inc",
            amount: 99,
            status: "paid",
            date: "2024-01-14"
          }, {
            id: "INV-003",
            tenant: "Beta LLC",
            amount: 599,
            status: "pending",
            date: "2024-01-13"
          }, {
            id: "INV-004",
            tenant: "Gamma Co",
            amount: 99,
            status: "overdue",
            date: "2024-01-10"
          }].map((invoice, index) => /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
            opacity: 0,
            x: -20
          }, animate: {
            opacity: 1,
            x: 0
          }, transition: prefersReducedMotion ? {
            duration: 0
          } : {
            delay: index * 0.05
          }, className: "flex items-center justify-between p-3 rounded-lg hover:bg-muted/50 transition-colors", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-4", children: [
              /* @__PURE__ */ jsx("div", { className: cn("p-2 rounded-full", invoice.status === "paid" && "bg-green-500/10 text-green-600", invoice.status === "pending" && "bg-amber-500/10 text-amber-600", invoice.status === "overdue" && "bg-red-500/10 text-red-600"), children: /* @__PURE__ */ jsx(FileText, { className: "h-4 w-4" }) }),
              /* @__PURE__ */ jsxs("div", { children: [
                /* @__PURE__ */ jsx("p", { className: "font-medium", children: invoice.id }),
                /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: invoice.tenant })
              ] })
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-4", children: [
              /* @__PURE__ */ jsx("span", { className: "font-medium", children: formatCurrency(invoice.amount) }),
              /* @__PURE__ */ jsx(Badge, { variant: invoice.status === "paid" ? "success" : invoice.status === "pending" ? "warning" : "destructive", children: invoice.status })
            ] })
          ] }, invoice.id)) }) })
        ] })
      ] }),
      /* @__PURE__ */ jsx(TabsContent, { value: "subscriptions", className: "space-y-6", children: /* @__PURE__ */ jsx(Card, { children: /* @__PURE__ */ jsx(DataTable, { columns, data: subscriptions, isLoading, searchable: true, searchPlaceholder: "Search subscriptions…", pagination: true, pageSize: 10, exportable: true, exportFileName: "subscriptions" }) }) }),
      /* @__PURE__ */ jsx(TabsContent, { value: "invoices", className: "space-y-6", children: /* @__PURE__ */ jsxs(Card, { className: "p-12 text-center", children: [
        /* @__PURE__ */ jsx(FileText, { className: "h-12 w-12 text-muted-foreground mx-auto mb-4" }),
        /* @__PURE__ */ jsx("h3", { className: "text-lg font-semibold", children: "Invoice Management" }),
        /* @__PURE__ */ jsx("p", { className: "text-muted-foreground mt-1", children: "Full invoice management coming soon" })
      ] }) })
    ] })
  ] });
}
export {
  BillingPage as component
};
