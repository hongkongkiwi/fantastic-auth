import { jsxs, jsx } from "react/jsx-runtime";
import { Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { MoreHorizontal, FileText, Download } from "lucide-react";
import { P as PageHeader, B as Button, t as toast, a as Badge, j as formatCurrency } from "./router-BqFKwE1w.js";
import { C as Card } from "./Card-DiqECnNB.js";
import { D as DataTable, a as createStatusBadge, b as createDateCell } from "./DataTable-qvjqCqsN.js";
import { D as DropdownMenu, a as DropdownMenuTrigger, b as DropdownMenuContent, c as DropdownMenuItem } from "./DropdownMenu-B1r5JY9H.js";
import { u as useServerFn } from "../server.js";
import { h as listSubscriptions } from "./internal-api-DaRn9LSO.js";
import "@t3-oss/env-core";
import "zod";
import "sonner";
import "framer-motion";
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
function BillingSubscriptionsPage() {
  const [subscriptions, setSubscriptions] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
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
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "Subscriptions", description: "Manage active subscriptions", breadcrumbs: [{
      label: "Billing",
      href: "/billing"
    }, {
      label: "Subscriptions"
    }], actions: /* @__PURE__ */ jsx(Button, { variant: "outline", asChild: true, children: /* @__PURE__ */ jsx(Link, { to: "/billing", children: "Back to Billing" }) }) }),
    /* @__PURE__ */ jsx(Card, { children: /* @__PURE__ */ jsx(DataTable, { columns, data: subscriptions, isLoading, searchable: true, searchPlaceholder: "Search subscriptions…", pagination: true, pageSize: 10, exportable: true, exportFileName: "subscriptions" }) })
  ] });
}
export {
  BillingSubscriptionsPage as component
};
