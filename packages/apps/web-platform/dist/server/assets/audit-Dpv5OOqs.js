import { jsxs, jsx } from "react/jsx-runtime";
import * as React from "react";
import { useState, useEffect } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { ChevronDown, Download, Shield, Calendar, ClipboardList, Eye, ShieldAlert, LogOut, User, AlertCircle, CheckCircle2, Settings, Building2 } from "lucide-react";
import { c as cn, e as env, P as PageHeader, B as Button, b as Alert, d as AlertTitle, f as AlertDescription, a as Badge, t as toast, g as formatDateTime, h as formatRelativeTime } from "./router-BqFKwE1w.js";
import { D as DataTable } from "./DataTable-qvjqCqsN.js";
import { C as Card, a as CardHeader, b as CardTitle, d as CardContent } from "./Card-DiqECnNB.js";
import { I as Input } from "./Input-D8nMsmC2.js";
import { T as Tabs, a as TabsList, b as TabsTrigger, c as TabsContent } from "./Tabs-Dlqc7sYx.js";
import { u as useServerFn } from "../server.js";
import { a as listAudit, d as downloadAudit } from "./internal-api-DaRn9LSO.js";
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
import "@tanstack/react-table";
import "@radix-ui/react-tabs";
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
const Select = React.forwardRef(
  ({
    className,
    options,
    label,
    error,
    helperText,
    placeholder,
    onChange,
    fullWidth,
    id,
    ...props
  }, ref) => {
    const selectId = id || React.useId();
    const hasError = !!error;
    return /* @__PURE__ */ jsxs("div", { className: cn("space-y-1.5", fullWidth && "w-full"), children: [
      label && /* @__PURE__ */ jsxs(
        "label",
        {
          htmlFor: selectId,
          className: "text-sm font-medium text-foreground",
          children: [
            label,
            props.required && /* @__PURE__ */ jsx("span", { className: "text-destructive ml-1", children: "*" })
          ]
        }
      ),
      /* @__PURE__ */ jsxs("div", { className: "relative", children: [
        /* @__PURE__ */ jsxs(
          "select",
          {
            id: selectId,
            className: cn(
              "flex h-10 w-full appearance-none rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background transition-colors transition-shadow duration-200",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
              "disabled:cursor-not-allowed disabled:opacity-50",
              "hover:border-muted-foreground/30",
              hasError && "border-destructive focus-visible:ring-destructive",
              className
            ),
            ref,
            onChange: (e) => onChange?.(e.target.value),
            "aria-invalid": hasError,
            "aria-describedby": hasError ? `${selectId}-error` : void 0,
            ...props,
            children: [
              placeholder && /* @__PURE__ */ jsx("option", { value: "", disabled: true, children: placeholder }),
              options.map((option) => /* @__PURE__ */ jsx(
                "option",
                {
                  value: option.value,
                  disabled: option.disabled,
                  children: option.label
                },
                option.value
              ))
            ]
          }
        ),
        /* @__PURE__ */ jsx(ChevronDown, { className: "absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground pointer-events-none", "aria-hidden": "true" })
      ] }),
      hasError ? /* @__PURE__ */ jsx(
        "p",
        {
          id: `${selectId}-error`,
          className: "text-sm text-destructive animate-fade-in",
          children: error
        }
      ) : helperText ? /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: helperText }) : null
    ] });
  }
);
Select.displayName = "Select";
const actionIcons = {
  "tenant.create": /* @__PURE__ */ jsx(Building2, { className: "h-4 w-4", "aria-hidden": "true" }),
  "tenant.update": /* @__PURE__ */ jsx(Settings, { className: "h-4 w-4", "aria-hidden": "true" }),
  "tenant.suspend": /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4", "aria-hidden": "true" }),
  "tenant.activate": /* @__PURE__ */ jsx(CheckCircle2, { className: "h-4 w-4", "aria-hidden": "true" }),
  "tenant.delete": /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4", "aria-hidden": "true" }),
  "user.create": /* @__PURE__ */ jsx(User, { className: "h-4 w-4", "aria-hidden": "true" }),
  "auth.login": /* @__PURE__ */ jsx(Shield, { className: "h-4 w-4", "aria-hidden": "true" }),
  "auth.logout": /* @__PURE__ */ jsx(Shield, { className: "h-4 w-4", "aria-hidden": "true" }),
  // Impersonation actions
  "impersonation.start": /* @__PURE__ */ jsx(Eye, { className: "h-4 w-4", "aria-hidden": "true" }),
  "impersonation.end": /* @__PURE__ */ jsx(LogOut, { className: "h-4 w-4", "aria-hidden": "true" }),
  "impersonation.action": /* @__PURE__ */ jsx(ShieldAlert, { className: "h-4 w-4", "aria-hidden": "true" })
};
const actionColors = {
  "tenant.create": "bg-blue-500/10 text-blue-600",
  "tenant.update": "bg-slate-500/10 text-slate-600",
  "tenant.suspend": "bg-amber-500/10 text-amber-600",
  "tenant.activate": "bg-green-500/10 text-green-600",
  "tenant.delete": "bg-red-500/10 text-red-600",
  "user.create": "bg-purple-500/10 text-purple-600",
  "auth.login": "bg-emerald-500/10 text-emerald-600",
  "auth.logout": "bg-gray-500/10 text-gray-600",
  // Impersonation - highlighted in amber
  "impersonation.start": "bg-amber-500/10 text-amber-600",
  "impersonation.end": "bg-gray-500/10 text-gray-600",
  "impersonation.action": "bg-orange-500/10 text-orange-600"
};
const actionLabels = {
  "tenant.create": "Tenant Created",
  "tenant.update": "Tenant Updated",
  "tenant.suspend": "Tenant Suspended",
  "tenant.activate": "Tenant Activated",
  "tenant.delete": "Tenant Deleted",
  "tenant.migrate": "Tenant Migrated",
  "user.create": "User Created",
  "user.update": "User Updated",
  "user.delete": "User Deleted",
  "auth.login": "Login",
  "auth.logout": "Logout",
  "auth.expired": "Session Expired",
  "subscription.update": "Subscription Updated",
  "invoice.generate": "Invoice Generated",
  // Impersonation labels
  "impersonation.start": "Support Access Started",
  "impersonation.end": "Support Access Ended",
  "impersonation.action": "Action During Support Access"
};
const filterOptions = [{
  value: "",
  label: "All Actions"
}, {
  value: "tenant",
  label: "Tenant Actions"
}, {
  value: "user",
  label: "User Actions"
}, {
  value: "auth",
  label: "Authentication"
}, {
  value: "subscription",
  label: "Billing"
}, {
  value: "impersonation",
  label: "Support Access"
}];
function AuditPage() {
  const supportImpersonationEnabled = env.VITE_ENABLE_SUPPORT_IMPERSONATION === "true";
  const [events, setEvents] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [dateRange, setDateRange] = useState({
    since: "",
    until: ""
  });
  const [activeTab, setActiveTab] = useState("platform");
  const prefersReducedMotion = useReducedMotion();
  const listAuditFn = useServerFn(listAudit);
  const downloadAuditFn = useServerFn(downloadAudit);
  const fetchAudit = async (page = 1) => {
    setIsLoading(true);
    try {
      const result = await listAuditFn({
        data: {
          action: filter || void 0,
          since: dateRange.since || void 0,
          until: dateRange.until || void 0,
          page,
          perPage: 50,
          sort: "desc"
        }
      });
      setEvents(result.data || []);
    } catch (error) {
      toast.error("Failed to load audit logs");
    } finally {
      setIsLoading(false);
    }
  };
  useEffect(() => {
    fetchAudit();
  }, [filter, dateRange]);
  const handleDownload = async () => {
    try {
      const result = await downloadAuditFn({
        data: {
          action: filter || void 0,
          since: dateRange.since || void 0,
          until: dateRange.until || void 0
        }
      });
      const blob = new Blob([result], {
        type: "text/csv"
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `audit-log-${(/* @__PURE__ */ new Date()).toISOString().split("T")[0]}.csv`;
      link.click();
      URL.revokeObjectURL(url);
      toast.success("Audit log downloaded");
    } catch (error) {
      toast.error("Failed to download audit log");
    }
  };
  const impersonationEvents = events.filter((event) => (event.action || "").startsWith("impersonation"));
  const platformEvents = events.filter((event) => !(event.action || "").startsWith("impersonation"));
  const displayEvents = activeTab === "platform" ? platformEvents : activeTab === "impersonation" ? impersonationEvents : events;
  const columns = [{
    accessorKey: "timestamp",
    header: "Time",
    cell: ({
      getValue
    }) => {
      const date = getValue();
      return /* @__PURE__ */ jsxs("div", { className: "flex flex-col", children: [
        /* @__PURE__ */ jsx("span", { className: "text-sm", children: formatDateTime(date) }),
        /* @__PURE__ */ jsx("span", { className: "text-xs text-muted-foreground", children: formatRelativeTime(date) })
      ] });
    }
  }, {
    accessorKey: "action",
    header: "Action",
    cell: ({
      getValue
    }) => {
      const action = getValue();
      const icon = actionIcons[action] || /* @__PURE__ */ jsx(ClipboardList, { className: "h-4 w-4", "aria-hidden": "true" });
      const colorClass = actionColors[action] || "bg-gray-500/10 text-gray-600";
      const label = actionLabels[action] || action;
      return /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
        /* @__PURE__ */ jsx("div", { className: cn("p-2 rounded-full", colorClass), children: icon }),
        /* @__PURE__ */ jsx("span", { className: "font-medium", children: label })
      ] });
    }
  }, {
    accessorKey: "actor",
    header: "Actor",
    cell: ({
      row,
      getValue
    }) => {
      const actor = getValue();
      const isImpersonation = row.original.action?.startsWith("impersonation");
      return /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsx("span", { className: "text-sm", children: actor }),
        isImpersonation && /* @__PURE__ */ jsx(Badge, { variant: "warning", className: "text-xs", children: "Support Access" })
      ] });
    }
  }, {
    accessorKey: "tenantName",
    header: "Tenant",
    cell: ({
      getValue
    }) => {
      const tenant = getValue();
      if (!tenant) return /* @__PURE__ */ jsx("span", { className: "text-muted-foreground", children: "—" });
      return /* @__PURE__ */ jsx(Badge, { variant: "secondary", className: "font-mono text-xs", children: tenant });
    }
  }, {
    accessorKey: "detail",
    header: "Details",
    cell: ({
      getValue
    }) => /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground max-w-md truncate", children: getValue() })
  }, {
    accessorKey: "source",
    header: "Source",
    cell: ({
      getValue
    }) => {
      const source = getValue();
      return /* @__PURE__ */ jsx(Badge, { variant: source === "ui" ? "default" : "secondary", children: source?.toUpperCase() || "API" });
    }
  }];
  const stats = {
    today: 245,
    thisWeek: 1847,
    thisMonth: 8934,
    impersonationSessions: supportImpersonationEnabled ? impersonationEvents.filter((e) => e.action === "impersonation.start").length : 0
  };
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "Platform Audit Logs", description: "Track all platform administrative actions and support access sessions", breadcrumbs: [{
      label: "Platform Audit"
    }], actions: /* @__PURE__ */ jsx(Button, { variant: "outline", leftIcon: /* @__PURE__ */ jsx(Download, { className: "h-4 w-4" }), onClick: handleDownload, children: "Export CSV" }) }),
    /* @__PURE__ */ jsxs(Alert, { children: [
      /* @__PURE__ */ jsx(Shield, { className: "h-4 w-4" }),
      /* @__PURE__ */ jsx(AlertTitle, { children: "Privacy & Accountability" }),
      /* @__PURE__ */ jsx(AlertDescription, { children: "This audit log tracks all platform-level actions. Support access sessions (impersonation) are logged separately and include the reason for access and duration. All actions taken during support access are attributed to the platform admin." })
    ] }),
    /* @__PURE__ */ jsx("div", { className: "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4", children: [{
      label: "Today",
      value: stats.today,
      icon: Calendar,
      color: "blue"
    }, {
      label: "This Week",
      value: stats.thisWeek,
      icon: ClipboardList,
      color: "green"
    }, {
      label: "This Month",
      value: stats.thisMonth,
      icon: ClipboardList,
      color: "purple"
    }, {
      label: "Support Sessions",
      value: stats.impersonationSessions,
      icon: Eye,
      color: "amber"
    }].map((stat, index) => /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
      opacity: 0,
      y: 20
    }, animate: {
      opacity: 1,
      y: 0
    }, transition: prefersReducedMotion ? {
      duration: 0
    } : {
      delay: index * 0.1
    }, children: /* @__PURE__ */ jsx(Card, { className: "p-6 card-hover", children: /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: stat.label }),
        /* @__PURE__ */ jsx("p", { className: "text-2xl font-bold mt-1", children: stat.value.toLocaleString() })
      ] }),
      /* @__PURE__ */ jsx("div", { className: cn("p-3 rounded-lg", `bg-${stat.color}-500/10`), children: /* @__PURE__ */ jsx(stat.icon, { className: cn("h-5 w-5", `text-${stat.color}-600`) }) })
    ] }) }) }, stat.label)) }),
    /* @__PURE__ */ jsxs(Tabs, { value: activeTab, onValueChange: setActiveTab, className: "space-y-6", children: [
      /* @__PURE__ */ jsxs(TabsList, { children: [
        /* @__PURE__ */ jsx(TabsTrigger, { value: "all", children: "All Events" }),
        /* @__PURE__ */ jsx(TabsTrigger, { value: "platform", children: "Platform Actions" }),
        supportImpersonationEnabled ? /* @__PURE__ */ jsxs(TabsTrigger, { value: "impersonation", className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsx(Eye, { className: "h-4 w-4" }),
          "Support Access",
          impersonationEvents.length > 0 && /* @__PURE__ */ jsx(Badge, { variant: "secondary", className: "ml-1 text-xs", children: impersonationEvents.length })
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxs(TabsContent, { value: "all", className: "space-y-6", children: [
        /* @__PURE__ */ jsx(FiltersCard, { filter, setFilter, dateRange, setDateRange, onClear: () => {
          setFilter("");
          setDateRange({
            since: "",
            until: ""
          });
        } }),
        /* @__PURE__ */ jsx(AuditTable, { columns, data: displayEvents, isLoading, emptyMessage: "No audit events found" })
      ] }),
      /* @__PURE__ */ jsxs(TabsContent, { value: "platform", className: "space-y-6", children: [
        /* @__PURE__ */ jsx(FiltersCard, { filter, setFilter, dateRange, setDateRange, onClear: () => {
          setFilter("");
          setDateRange({
            since: "",
            until: ""
          });
        } }),
        /* @__PURE__ */ jsx(AuditTable, { columns, data: displayEvents, isLoading, emptyMessage: "No platform actions found" })
      ] }),
      supportImpersonationEnabled ? /* @__PURE__ */ jsxs(TabsContent, { value: "impersonation", className: "space-y-6", children: [
        /* @__PURE__ */ jsx(FiltersCard, { filter, setFilter, dateRange, setDateRange, onClear: () => {
          setFilter("");
          setDateRange({
            since: "",
            until: ""
          });
        } }),
        /* @__PURE__ */ jsx(AuditTable, { columns, data: displayEvents, isLoading, emptyMessage: "No support access events found" })
      ] }) : null
    ] })
  ] });
}
function FiltersCard({
  filter,
  setFilter,
  dateRange,
  setDateRange,
  onClear
}) {
  return /* @__PURE__ */ jsxs(Card, { children: [
    /* @__PURE__ */ jsx(CardHeader, { children: /* @__PURE__ */ jsx(CardTitle, { className: "text-base", children: "Filters" }) }),
    /* @__PURE__ */ jsx(CardContent, { children: /* @__PURE__ */ jsxs("div", { className: "flex flex-col sm:flex-row gap-4", children: [
      /* @__PURE__ */ jsx("div", { className: "w-full sm:w-64", children: /* @__PURE__ */ jsx(Select, { label: "Action Type", options: filterOptions, value: filter, onChange: (value) => setFilter(value), name: "actionFilter", autoComplete: "off" }) }),
      /* @__PURE__ */ jsx("div", { className: "w-full sm:w-48", children: /* @__PURE__ */ jsx(Input, { label: "From", type: "date", value: dateRange.since, onChange: (e) => setDateRange({
        ...dateRange,
        since: e.target.value
      }), name: "sinceDate", autoComplete: "off" }) }),
      /* @__PURE__ */ jsx("div", { className: "w-full sm:w-48", children: /* @__PURE__ */ jsx(Input, { label: "To", type: "date", value: dateRange.until, onChange: (e) => setDateRange({
        ...dateRange,
        until: e.target.value
      }), name: "untilDate", autoComplete: "off" }) }),
      /* @__PURE__ */ jsx("div", { className: "flex items-end", children: /* @__PURE__ */ jsx(Button, { variant: "outline", onClick: onClear, children: "Clear Filters" }) })
    ] }) })
  ] });
}
function AuditTable({
  columns,
  data,
  isLoading,
  emptyMessage
}) {
  return /* @__PURE__ */ jsx(Card, { children: data.length === 0 && !isLoading ? /* @__PURE__ */ jsxs("div", { className: "text-center py-12 text-muted-foreground", children: [
    /* @__PURE__ */ jsx(ClipboardList, { className: "h-12 w-12 mx-auto mb-3 opacity-50" }),
    /* @__PURE__ */ jsx("p", { children: emptyMessage })
  ] }) : /* @__PURE__ */ jsx(DataTable, { columns, data, isLoading, pagination: true, pageSize: 50, exportable: false }) });
}
export {
  AuditPage as component
};
