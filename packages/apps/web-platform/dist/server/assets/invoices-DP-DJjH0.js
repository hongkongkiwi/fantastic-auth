import { jsxs, jsx } from "react/jsx-runtime";
import { Link } from "@tanstack/react-router";
import { useState, useMemo, useEffect } from "react";
import { MoreHorizontal, FileText, Download } from "lucide-react";
import { P as PageHeader, B as Button, t as toast, a as Badge, j as formatCurrency } from "./router-BqFKwE1w.js";
import { C as Card } from "./Card-DiqECnNB.js";
import { I as Input } from "./Input-D8nMsmC2.js";
import { D as DataTable } from "./DataTable-qvjqCqsN.js";
import { D as DropdownMenu, a as DropdownMenuTrigger, b as DropdownMenuContent, c as DropdownMenuItem } from "./DropdownMenu-B1r5JY9H.js";
import { u as useServerFn } from "../server.js";
import { p as listPlatformInvoices } from "./internal-api-DaRn9LSO.js";
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
function BillingInvoicesPage() {
  const [invoices, setInvoices] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(10);
  const [statusFilter, setStatusFilter] = useState("all");
  const [tenantFilter, setTenantFilter] = useState("");
  const [createdFrom, setCreatedFrom] = useState("");
  const [createdTo, setCreatedTo] = useState("");
  const [pagination, setPagination] = useState({
    page: 1,
    perPage: 10,
    total: 0,
    totalPages: 1
  });
  const listPlatformInvoicesFn = useServerFn(listPlatformInvoices);
  const pageSizeOptions = useMemo(() => [10, 20, 50, 100], []);
  useEffect(() => {
    const fetchInvoices = async () => {
      setIsLoading(true);
      try {
        const result = await listPlatformInvoicesFn({
          data: {
            page,
            perPage,
            tenantId: tenantFilter.trim() ? tenantFilter.trim() : void 0,
            status: statusFilter === "all" ? void 0 : statusFilter,
            createdFrom: createdFrom || void 0,
            createdTo: createdTo || void 0
          }
        });
        const response = result;
        setInvoices(response.invoices || []);
        setPagination({
          page: response.pagination?.page ?? page,
          perPage: response.pagination?.perPage ?? perPage,
          total: response.pagination?.total ?? response.invoices?.length ?? 0,
          totalPages: response.pagination?.totalPages ?? Math.max(1, Math.ceil((response.invoices?.length ?? 0) / perPage))
        });
      } catch {
        toast.error("Failed to load invoices");
      } finally {
        setIsLoading(false);
      }
    };
    fetchInvoices();
  }, [page, perPage, statusFilter, tenantFilter, createdFrom, createdTo, listPlatformInvoicesFn]);
  const columns = [{
    accessorKey: "id",
    header: "Invoice",
    cell: ({
      row
    }) => /* @__PURE__ */ jsxs("div", { children: [
      /* @__PURE__ */ jsx("p", { className: "font-medium", children: row.original.id }),
      /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: row.original.tenantId })
    ] })
  }, {
    accessorKey: "status",
    header: "Status",
    cell: ({
      getValue
    }) => {
      const status = getValue();
      const variant = status === "paid" ? "success" : status === "open" || status === "draft" ? "warning" : "destructive";
      return /* @__PURE__ */ jsx(Badge, { variant, children: status });
    }
  }, {
    accessorKey: "amount",
    header: "Amount",
    cell: ({
      row
    }) => formatCurrency(row.original.amount || 0)
  }, {
    accessorKey: "createdAt",
    header: "Date",
    cell: ({
      getValue
    }) => new Date(getValue()).toLocaleDateString()
  }, {
    id: "actions",
    header: "",
    cell: ({
      row
    }) => /* @__PURE__ */ jsxs(DropdownMenu, { children: [
      /* @__PURE__ */ jsx(DropdownMenuTrigger, { asChild: true, children: /* @__PURE__ */ jsx(Button, { variant: "ghost", size: "icon-sm", "aria-label": "Invoice actions", children: /* @__PURE__ */ jsx(MoreHorizontal, { className: "h-4 w-4" }) }) }),
      /* @__PURE__ */ jsxs(DropdownMenuContent, { align: "end", children: [
        /* @__PURE__ */ jsxs(DropdownMenuItem, { onClick: () => {
          const url = row.original.pdfUrl;
          if (url) window.open(url, "_blank", "noopener,noreferrer");
        }, children: [
          /* @__PURE__ */ jsx(FileText, { className: "mr-2 h-4 w-4" }),
          "View Invoice"
        ] }),
        /* @__PURE__ */ jsxs(DropdownMenuItem, { onClick: () => {
          const url = row.original.pdfUrl;
          if (url) window.open(url, "_blank", "noopener,noreferrer");
        }, children: [
          /* @__PURE__ */ jsx(Download, { className: "mr-2 h-4 w-4" }),
          "Download PDF"
        ] })
      ] })
    ] })
  }];
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "Invoices", description: "Review invoices across tenants", breadcrumbs: [{
      label: "Billing",
      href: "/billing"
    }, {
      label: "Invoices"
    }], actions: /* @__PURE__ */ jsx(Button, { variant: "outline", asChild: true, children: /* @__PURE__ */ jsx(Link, { to: "/billing", children: "Back to Billing" }) }) }),
    /* @__PURE__ */ jsxs(Card, { children: [
      /* @__PURE__ */ jsxs("div", { className: "flex flex-col lg:flex-row lg:items-end gap-4 border-b px-4 py-4", children: [
        /* @__PURE__ */ jsxs("div", { className: "flex flex-col gap-1", children: [
          /* @__PURE__ */ jsx("label", { className: "text-xs uppercase tracking-wide text-muted-foreground", children: "Status" }),
          /* @__PURE__ */ jsxs("select", { className: "h-9 rounded-md border border-input bg-background px-2 text-sm", value: statusFilter, onChange: (event) => {
            setStatusFilter(event.target.value);
            setPage(1);
          }, children: [
            /* @__PURE__ */ jsx("option", { value: "all", children: "All statuses" }),
            /* @__PURE__ */ jsx("option", { value: "draft", children: "Draft" }),
            /* @__PURE__ */ jsx("option", { value: "open", children: "Open" }),
            /* @__PURE__ */ jsx("option", { value: "paid", children: "Paid" }),
            /* @__PURE__ */ jsx("option", { value: "uncollectible", children: "Uncollectible" }),
            /* @__PURE__ */ jsx("option", { value: "void", children: "Void" })
          ] })
        ] }),
        /* @__PURE__ */ jsxs("div", { className: "flex flex-col gap-1 flex-1", children: [
          /* @__PURE__ */ jsx("label", { className: "text-xs uppercase tracking-wide text-muted-foreground", children: "Tenant ID" }),
          /* @__PURE__ */ jsx(Input, { placeholder: "Tenant UUID", value: tenantFilter, onChange: (event) => {
            setTenantFilter(event.target.value);
            setPage(1);
          } })
        ] }),
        /* @__PURE__ */ jsxs("div", { className: "flex flex-col gap-1", children: [
          /* @__PURE__ */ jsx("label", { className: "text-xs uppercase tracking-wide text-muted-foreground", children: "Created From" }),
          /* @__PURE__ */ jsx(Input, { type: "date", value: createdFrom, onChange: (event) => {
            const value = event.target.value;
            setCreatedFrom(value ? new Date(value).toISOString() : "");
            setPage(1);
          } })
        ] }),
        /* @__PURE__ */ jsxs("div", { className: "flex flex-col gap-1", children: [
          /* @__PURE__ */ jsx("label", { className: "text-xs uppercase tracking-wide text-muted-foreground", children: "Created To" }),
          /* @__PURE__ */ jsx(Input, { type: "date", value: createdTo ? createdTo.slice(0, 10) : "", onChange: (event) => {
            const value = event.target.value;
            if (value) {
              const end = /* @__PURE__ */ new Date(`${value}T23:59:59.999Z`);
              setCreatedTo(end.toISOString());
            } else {
              setCreatedTo("");
            }
            setPage(1);
          } })
        ] })
      ] }),
      /* @__PURE__ */ jsx(DataTable, { columns, data: invoices, isLoading, searchable: true, searchPlaceholder: "Search invoices…", pagination: false, exportable: true, exportFileName: "invoices" }),
      /* @__PURE__ */ jsxs("div", { className: "flex flex-col sm:flex-row items-center justify-between gap-3 border-t px-4 py-3 text-sm text-muted-foreground", children: [
        /* @__PURE__ */ jsxs("div", { children: [
          "Showing page ",
          pagination.page,
          " of ",
          pagination.totalPages,
          " · ",
          pagination.total,
          " total"
        ] }),
        /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsx("span", { children: "Rows" }),
          /* @__PURE__ */ jsx("select", { className: "h-8 rounded-md border border-input bg-background px-2 text-sm", value: perPage, onChange: (event) => {
            const value = Number(event.target.value);
            setPerPage(value);
            setPage(1);
          }, children: pageSizeOptions.map((size) => /* @__PURE__ */ jsx("option", { value: size, children: size }, size)) }),
          /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-1", children: [
            /* @__PURE__ */ jsx(Button, { variant: "outline", size: "sm", onClick: () => setPage(1), disabled: page <= 1 || isLoading, children: "First" }),
            /* @__PURE__ */ jsx(Button, { variant: "outline", size: "sm", onClick: () => setPage((prev) => Math.max(1, prev - 1)), disabled: page <= 1 || isLoading, children: "Prev" }),
            /* @__PURE__ */ jsx(Button, { variant: "outline", size: "sm", onClick: () => setPage((prev) => Math.min(pagination.totalPages, prev + 1)), disabled: page >= pagination.totalPages || isLoading, children: "Next" }),
            /* @__PURE__ */ jsx(Button, { variant: "outline", size: "sm", onClick: () => setPage(pagination.totalPages), disabled: page >= pagination.totalPages || isLoading, children: "Last" })
          ] })
        ] })
      ] })
    ] })
  ] });
}
export {
  BillingInvoicesPage as component
};
