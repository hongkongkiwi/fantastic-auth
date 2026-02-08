import { jsxs, jsx } from "react/jsx-runtime";
import { useNavigate, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { Plus, Building2, MoreHorizontal, FileText, Edit, Pause, Play, Trash2 } from "lucide-react";
import { u as useServerFn, P as PageHeader, B as Button, C as ConfirmDialog, t as toast, k as formatNumber, y as listTenants, z as deleteTenant, A as activateTenant, E as suspendTenant } from "./router-BDwxh4pl.js";
import { D as DataTable, c as createSelectColumn, a as createStatusBadge, b as createDateCell } from "./DataTable-B04i1moJ.js";
import { B as Badge } from "./Badge-DmGWtXSM.js";
import { C as Card } from "./Card-Brxgy2gk.js";
import { D as DropdownMenu, a as DropdownMenuTrigger, b as DropdownMenuContent, c as DropdownMenuItem } from "./DropdownMenu-CUcXj7WN.js";
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
import "./Input-C7MrN6IE.js";
import "./Skeleton-CdKpSX4m.js";
import "./Checkbox-Dbk2YhaG.js";
import "@radix-ui/react-checkbox";
import "@radix-ui/react-dropdown-menu";
const planColors = {
  free: "secondary",
  starter: "info",
  pro: "success",
  enterprise: "warning"
};
const statusConfig = {
  active: {
    label: "Active",
    variant: "success"
  },
  suspended: {
    label: "Suspended",
    variant: "warning"
  },
  inactive: {
    label: "Inactive",
    variant: "destructive"
  }
};
function TenantsPage() {
  const [tenants, setTenants] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedTenant, setSelectedTenant] = useState(null);
  const [dialogState, setDialogState] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const prefersReducedMotion = useReducedMotion();
  const navigate = useNavigate();
  const listTenantsFn = useServerFn(listTenants);
  const suspendTenantFn = useServerFn(suspendTenant);
  const activateTenantFn = useServerFn(activateTenant);
  const deleteTenantFn = useServerFn(deleteTenant);
  const fetchTenants = async () => {
    setIsLoading(true);
    try {
      const result = await listTenantsFn({
        data: {
          page: 1,
          perPage: 50
        }
      });
      setTenants(result.data || []);
    } catch (error) {
      toast.error("Failed to load tenants");
    } finally {
      setIsLoading(false);
    }
  };
  useEffect(() => {
    fetchTenants();
  }, []);
  const handleAction = async () => {
    if (!selectedTenant || !dialogState) return;
    if (!selectedTenant.id) {
      toast.error("Tenant ID is missing");
      return;
    }
    setIsSubmitting(true);
    try {
      switch (dialogState) {
        case "suspend":
          await suspendTenantFn({
            data: {
              tenantId: selectedTenant.id
            }
          });
          toast.success("Tenant suspended successfully");
          break;
        case "activate":
          await activateTenantFn({
            data: {
              tenantId: selectedTenant.id
            }
          });
          toast.success("Tenant activated successfully");
          break;
        case "delete":
          await deleteTenantFn({
            data: {
              tenantId: selectedTenant.id
            }
          });
          toast.success("Tenant deleted successfully");
          break;
      }
      await fetchTenants();
    } catch (error) {
      toast.error(`Failed to ${dialogState} tenant`);
    } finally {
      setIsSubmitting(false);
      setDialogState(null);
      setSelectedTenant(null);
    }
  };
  const columns = [createSelectColumn(), {
    accessorKey: "name",
    header: "Tenant",
    cell: ({
      row
    }) => {
      const tenant = row.original;
      return /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
        /* @__PURE__ */ jsx("div", { className: "h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center", children: /* @__PURE__ */ jsx(Building2, { className: "h-5 w-5 text-primary" }) }),
        /* @__PURE__ */ jsxs("div", { children: [
          /* @__PURE__ */ jsx("p", { className: "font-medium", children: tenant.name ?? "Unnamed tenant" }),
          /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: tenant.slug ?? "—" })
        ] })
      ] });
    }
  }, {
    accessorKey: "plan",
    header: "Plan",
    cell: ({
      getValue
    }) => {
      const plan = String(getValue() ?? "unknown");
      return /* @__PURE__ */ jsx(Badge, { variant: planColors[plan] || "default", children: plan.charAt(0).toUpperCase() + plan.slice(1) });
    }
  }, {
    accessorKey: "status",
    header: "Status",
    cell: createStatusBadge(statusConfig)
  }, {
    accessorKey: "usage.currentUsers",
    header: "Users",
    cell: ({
      row
    }) => formatNumber(row.original.usage?.currentUsers ?? 0)
  }, {
    accessorKey: "createdAt",
    header: "Created",
    cell: createDateCell()
  }, {
    id: "actions",
    header: "",
    cell: ({
      row
    }) => {
      const tenant = row.original;
      return /* @__PURE__ */ jsxs(DropdownMenu, { children: [
        /* @__PURE__ */ jsx(DropdownMenuTrigger, { asChild: true, children: /* @__PURE__ */ jsx(Button, { variant: "ghost", size: "icon-sm", "aria-label": "Open tenant actions", children: /* @__PURE__ */ jsx(MoreHorizontal, { className: "h-4 w-4" }) }) }),
        /* @__PURE__ */ jsxs(DropdownMenuContent, { align: "end", children: [
          /* @__PURE__ */ jsx(DropdownMenuItem, { asChild: true, children: /* @__PURE__ */ jsxs(Link, { to: "/tenants/$id", params: {
            id: tenant.id ?? ""
          }, children: [
            /* @__PURE__ */ jsx(FileText, { className: "mr-2 h-4 w-4" }),
            "View Details"
          ] }) }),
          /* @__PURE__ */ jsx(DropdownMenuItem, { asChild: true, children: /* @__PURE__ */ jsxs(Link, { to: "/tenants/$id", params: {
            id: tenant.id ?? ""
          }, children: [
            /* @__PURE__ */ jsx(Edit, { className: "mr-2 h-4 w-4" }),
            "Edit"
          ] }) }),
          tenant.status === "active" ? /* @__PURE__ */ jsxs(DropdownMenuItem, { onClick: () => {
            setSelectedTenant(tenant);
            setDialogState("suspend");
          }, children: [
            /* @__PURE__ */ jsx(Pause, { className: "mr-2 h-4 w-4" }),
            "Suspend"
          ] }) : /* @__PURE__ */ jsxs(DropdownMenuItem, { onClick: () => {
            setSelectedTenant(tenant);
            setDialogState("activate");
          }, children: [
            /* @__PURE__ */ jsx(Play, { className: "mr-2 h-4 w-4" }),
            "Activate"
          ] }),
          /* @__PURE__ */ jsxs(DropdownMenuItem, { className: "text-destructive focus:text-destructive", onClick: () => {
            setSelectedTenant(tenant);
            setDialogState("delete");
          }, children: [
            /* @__PURE__ */ jsx(Trash2, { className: "mr-2 h-4 w-4" }),
            "Delete"
          ] })
        ] })
      ] });
    }
  }];
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "Tenants", description: "Manage your platform tenants and their subscriptions", breadcrumbs: [{
      label: "Tenants"
    }], actions: /* @__PURE__ */ jsx(Button, { asChild: true, leftIcon: /* @__PURE__ */ jsx(Plus, { className: "h-4 w-4" }), children: /* @__PURE__ */ jsx(Link, { to: "/tenants/create", children: "Create Tenant" }) }) }),
    /* @__PURE__ */ jsx("div", { className: "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4", children: [{
      label: "Total Tenants",
      value: tenants.length,
      color: "blue"
    }, {
      label: "Active",
      value: tenants.filter((t) => t.status === "active").length,
      color: "green"
    }, {
      label: "Suspended",
      value: tenants.filter((t) => t.status === "suspended").length,
      color: "amber"
    }, {
      label: "Enterprise",
      value: tenants.filter((t) => t.plan === "enterprise").length,
      color: "purple"
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
    }, children: /* @__PURE__ */ jsxs(Card, { className: "p-6 card-hover", children: [
      /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: stat.label }),
      /* @__PURE__ */ jsx("p", { className: "text-3xl font-bold mt-1", children: stat.value })
    ] }) }, stat.label)) }),
    /* @__PURE__ */ jsx(Card, { children: /* @__PURE__ */ jsx(DataTable, { columns, data: tenants, isLoading, searchable: true, searchPlaceholder: "Search tenants by name or slug…", pagination: true, pageSize: 10, onRowClick: (row) => {
      navigate({
        to: `/tenants/${row.id}`
      });
    }, exportable: true, exportFileName: "tenants" }) }),
    /* @__PURE__ */ jsx(ConfirmDialog, { isOpen: dialogState === "suspend", onClose: () => setDialogState(null), onConfirm: handleAction, title: "Suspend Tenant", description: `Are you sure you want to suspend "${selectedTenant?.name}"? This will prevent users from accessing the tenant.`, confirmText: "Suspend", variant: "destructive", isLoading: isSubmitting }),
    /* @__PURE__ */ jsx(ConfirmDialog, { isOpen: dialogState === "activate", onClose: () => setDialogState(null), onConfirm: handleAction, title: "Activate Tenant", description: `Are you sure you want to activate "${selectedTenant?.name}"?`, confirmText: "Activate", isLoading: isSubmitting }),
    /* @__PURE__ */ jsx(ConfirmDialog, { isOpen: dialogState === "delete", onClose: () => setDialogState(null), onConfirm: handleAction, title: "Delete Tenant", description: `Are you sure you want to delete "${selectedTenant?.name}"? This action cannot be undone.`, confirmText: "Delete", variant: "destructive", isLoading: isSubmitting })
  ] });
}
export {
  TenantsPage as component
};
