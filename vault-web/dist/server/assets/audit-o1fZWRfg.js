import { jsxs, jsx } from "react/jsx-runtime";
import * as React from "react";
import { useState, useEffect } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { ChevronDown, Download, Calendar, ClipboardList, AlertCircle, Shield, User, CheckCircle2, Settings, Building2 } from "lucide-react";
import { j as cn, u as useServerFn, P as PageHeader, B as Button, t as toast, n as formatDateTime, o as formatRelativeTime, p as listAudit, q as downloadAudit } from "./router-BDwxh4pl.js";
import { D as DataTable } from "./DataTable-B04i1moJ.js";
import { B as Badge } from "./Badge-DmGWtXSM.js";
import { C as Card, a as CardHeader, b as CardTitle, d as CardContent } from "./Card-Brxgy2gk.js";
import { I as Input } from "./Input-C7MrN6IE.js";
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
import "@tanstack/react-table";
import "@tanstack/react-virtual";
import "./Skeleton-CdKpSX4m.js";
import "./Checkbox-Dbk2YhaG.js";
import "@radix-ui/react-checkbox";
import "./DropdownMenu-CUcXj7WN.js";
import "@radix-ui/react-dropdown-menu";
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
  "auth.logout": /* @__PURE__ */ jsx(Shield, { className: "h-4 w-4", "aria-hidden": "true" })
};
const actionColors = {
  "tenant.create": "bg-blue-500/10 text-blue-600",
  "tenant.update": "bg-slate-500/10 text-slate-600",
  "tenant.suspend": "bg-amber-500/10 text-amber-600",
  "tenant.activate": "bg-green-500/10 text-green-600",
  "tenant.delete": "bg-red-500/10 text-red-600",
  "user.create": "bg-purple-500/10 text-purple-600",
  "auth.login": "bg-emerald-500/10 text-emerald-600",
  "auth.logout": "bg-gray-500/10 text-gray-600"
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
  "invoice.generate": "Invoice Generated"
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
}];
function AuditPage() {
  const [events, setEvents] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [dateRange, setDateRange] = useState({
    since: "",
    until: ""
  });
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
    failed: 12
  };
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "Audit Logs", description: "Track all administrative actions across the platform", breadcrumbs: [{
      label: "Audit Logs"
    }], actions: /* @__PURE__ */ jsx(Button, { variant: "outline", leftIcon: /* @__PURE__ */ jsx(Download, { className: "h-4 w-4" }), onClick: handleDownload, children: "Export CSV" }) }),
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
      label: "Failed Actions",
      value: stats.failed,
      icon: AlertCircle,
      color: "rose"
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
    /* @__PURE__ */ jsxs(Card, { children: [
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
        /* @__PURE__ */ jsx("div", { className: "flex items-end", children: /* @__PURE__ */ jsx(Button, { variant: "outline", onClick: () => {
          setFilter("");
          setDateRange({
            since: "",
            until: ""
          });
        }, children: "Clear Filters" }) })
      ] }) })
    ] }),
    /* @__PURE__ */ jsx(Card, { children: /* @__PURE__ */ jsx(DataTable, { columns, data: events, isLoading, pagination: true, pageSize: 50, exportable: false }) })
  ] });
}
export {
  AuditPage as component
};
