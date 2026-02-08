import { jsx, jsxs, Fragment } from "react/jsx-runtime";
import * as React from "react";
import { useState, useMemo, useEffect } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { AlertTriangle, Building2, ArrowRightLeft, ChevronDown, Check, ChevronUp, User, AlertCircle, MoreHorizontal, Mail, Trash2, Shield } from "lucide-react";
import { d as deleteUser, e as env, r as requestOwnershipTransfer, g as getOwnershipStatus, c as canDeleteUser, D as Dialog, a as DialogContent, b as DialogHeader, f as DialogTitle, h as DialogDescription, i as DialogFooter, B as Button, j as cn, s as searchUsers, u as useServerFn, P as PageHeader, k as formatNumber, t as toast } from "./router-BDwxh4pl.js";
import { D as DataTable, c as createSelectColumn } from "./DataTable-B04i1moJ.js";
import { B as Badge } from "./Badge-DmGWtXSM.js";
import { C as Card } from "./Card-Brxgy2gk.js";
import { D as DropdownMenu, a as DropdownMenuTrigger, b as DropdownMenuContent, c as DropdownMenuItem } from "./DropdownMenu-CUcXj7WN.js";
import { A as Alert, a as AlertDescription } from "./Alert-BGdSf0_L.js";
import { useQueryClient, useMutation, useQuery } from "@tanstack/react-query";
import * as SelectPrimitive from "@radix-ui/react-select";
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
import "./Input-C7MrN6IE.js";
import "./Skeleton-CdKpSX4m.js";
import "./Checkbox-Dbk2YhaG.js";
import "@radix-ui/react-checkbox";
import "@radix-ui/react-dropdown-menu";
const UI_TOKEN$1 = env.VITE_INTERNAL_UI_TOKEN || "";
function useOwnershipStatus(userId) {
  return useQuery({
    queryKey: ["ownership", "status", userId],
    queryFn: async () => {
      return getOwnershipStatus({ data: { userId, uiToken: UI_TOKEN$1 } });
    },
    enabled: Boolean(userId)
  });
}
function useCanDeleteUser(userId) {
  return useQuery({
    queryKey: ["ownership", "canDelete", userId],
    queryFn: async () => {
      return canDeleteUser({ data: { userId, uiToken: UI_TOKEN$1 } });
    },
    enabled: Boolean(userId)
  });
}
function useDeleteUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ userId, tenantId }) => {
      return deleteUser({ data: { userId, tenantId, uiToken: UI_TOKEN$1 } });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      queryClient.invalidateQueries({ queryKey: ["ownership"] });
    }
  });
}
function useRequestOwnershipTransfer() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      tenantId,
      fromUserId,
      toUserId
    }) => {
      return requestOwnershipTransfer({
        data: { tenantId, fromUserId, toUserId, uiToken: UI_TOKEN$1 }
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ownership", "transfers"] });
    }
  });
}
function useOwnershipGuards(userId) {
  const { data: status, isLoading: statusLoading } = useOwnershipStatus(userId);
  const { data: canDelete, isLoading: canDeleteLoading } = useCanDeleteUser(userId);
  return {
    isLoading: statusLoading || canDeleteLoading,
    status,
    canDelete: canDelete?.canDelete ?? false,
    deleteBlockReason: canDelete?.reason ?? null,
    deleteBlockMessage: canDelete?.message ?? null,
    ownedTenants: canDelete?.ownedTenants ?? []
  };
}
function DeleteUserDialog({
  user,
  isOpen,
  onClose,
  onSuccess,
  onTransferOwnership
}) {
  const [confirmText, setConfirmText] = useState("");
  const userId = user?.id ?? "";
  const { isLoading, canDelete, deleteBlockReason, deleteBlockMessage, ownedTenants } = useOwnershipGuards(userId);
  const deleteUser2 = useDeleteUser();
  const isBlocked = deleteBlockReason === "PRIMARY_OWNER";
  const canProceed = !isLoading && canDelete && confirmText === "DELETE";
  const handleDelete = async () => {
    if (!canProceed || !user) return;
    try {
      await deleteUser2.mutateAsync({ userId: user.id });
      setConfirmText("");
      onSuccess?.();
      onClose();
    } catch (error) {
    }
  };
  const handleTransferClick = () => {
    if (user && onTransferOwnership) {
      onTransferOwnership(user.id);
      onClose();
    }
  };
  return /* @__PURE__ */ jsx(Dialog, { open: isOpen, onOpenChange: onClose, children: /* @__PURE__ */ jsxs(DialogContent, { className: "sm:max-w-md", children: [
    /* @__PURE__ */ jsxs(DialogHeader, { children: [
      /* @__PURE__ */ jsxs(DialogTitle, { className: "flex items-center gap-2 text-destructive", children: [
        /* @__PURE__ */ jsx(AlertTriangle, { className: "h-5 w-5" }),
        "Delete User"
      ] }),
      /* @__PURE__ */ jsxs(DialogDescription, { children: [
        "This action cannot be undone. This will permanently delete",
        " ",
        /* @__PURE__ */ jsx("strong", { children: user?.email }),
        " and remove their data from our servers."
      ] })
    ] }),
    isBlocked && /* @__PURE__ */ jsxs(Alert, { variant: "destructive", className: "mt-4", children: [
      /* @__PURE__ */ jsx(Building2, { className: "h-4 w-4" }),
      /* @__PURE__ */ jsxs(AlertDescription, { className: "mt-2", children: [
        /* @__PURE__ */ jsx("p", { className: "font-medium", children: "Cannot Delete Account" }),
        /* @__PURE__ */ jsx("p", { className: "mt-1 text-sm", children: deleteBlockMessage }),
        ownedTenants.length > 0 && /* @__PURE__ */ jsxs("div", { className: "mt-2", children: [
          /* @__PURE__ */ jsx("p", { className: "text-sm font-medium", children: "Owned Tenants:" }),
          /* @__PURE__ */ jsx("ul", { className: "mt-1 list-inside list-disc text-sm", children: ownedTenants.map((tenantId) => /* @__PURE__ */ jsx("li", { children: tenantId }, tenantId)) })
        ] })
      ] })
    ] }),
    !isBlocked && /* @__PURE__ */ jsxs("div", { className: "space-y-4 py-4", children: [
      /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground", children: [
        "To confirm deletion, type ",
        /* @__PURE__ */ jsx("strong", { children: "DELETE" }),
        " below:"
      ] }),
      /* @__PURE__ */ jsx(
        "input",
        {
          type: "text",
          value: confirmText,
          onChange: (e) => setConfirmText(e.target.value),
          placeholder: "Type DELETE to confirm",
          className: "w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        }
      )
    ] }),
    /* @__PURE__ */ jsx(DialogFooter, { className: "gap-2 sm:gap-0", children: isBlocked ? /* @__PURE__ */ jsxs(Fragment, { children: [
      /* @__PURE__ */ jsx(Button, { variant: "outline", onClick: onClose, children: "Cancel" }),
      /* @__PURE__ */ jsxs(
        Button,
        {
          variant: "outline",
          onClick: handleTransferClick,
          className: "gap-2",
          children: [
            /* @__PURE__ */ jsx(ArrowRightLeft, { className: "h-4 w-4" }),
            "Transfer Ownership"
          ]
        }
      )
    ] }) : /* @__PURE__ */ jsxs(Fragment, { children: [
      /* @__PURE__ */ jsx(Button, { variant: "outline", onClick: onClose, children: "Cancel" }),
      /* @__PURE__ */ jsx(
        Button,
        {
          variant: "destructive",
          onClick: handleDelete,
          disabled: !canProceed || deleteUser2.isPending,
          children: deleteUser2.isPending ? "Deleting…" : "Delete User"
        }
      )
    ] }) })
  ] }) });
}
const Select = SelectPrimitive.Root;
const SelectValue = SelectPrimitive.Value;
const SelectTrigger = React.forwardRef(({ className, children, ...props }, ref) => /* @__PURE__ */ jsxs(
  SelectPrimitive.Trigger,
  {
    ref,
    className: cn(
      "flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 [&>span]:line-clamp-1",
      className
    ),
    ...props,
    children: [
      children,
      /* @__PURE__ */ jsx(SelectPrimitive.Icon, { asChild: true, children: /* @__PURE__ */ jsx(ChevronDown, { className: "h-4 w-4 opacity-50" }) })
    ]
  }
));
SelectTrigger.displayName = SelectPrimitive.Trigger.displayName;
const SelectScrollUpButton = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  SelectPrimitive.ScrollUpButton,
  {
    ref,
    className: cn(
      "flex cursor-default items-center justify-center py-1",
      className
    ),
    ...props,
    children: /* @__PURE__ */ jsx(ChevronUp, { className: "h-4 w-4" })
  }
));
SelectScrollUpButton.displayName = SelectPrimitive.ScrollUpButton.displayName;
const SelectScrollDownButton = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  SelectPrimitive.ScrollDownButton,
  {
    ref,
    className: cn(
      "flex cursor-default items-center justify-center py-1",
      className
    ),
    ...props,
    children: /* @__PURE__ */ jsx(ChevronDown, { className: "h-4 w-4" })
  }
));
SelectScrollDownButton.displayName = SelectPrimitive.ScrollDownButton.displayName;
const SelectContent = React.forwardRef(({ className, children, position = "popper", ...props }, ref) => /* @__PURE__ */ jsx(SelectPrimitive.Portal, { children: /* @__PURE__ */ jsxs(
  SelectPrimitive.Content,
  {
    ref,
    className: cn(
      "relative z-50 max-h-96 min-w-[8rem] overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-md data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2",
      position === "popper" && "data-[side=bottom]:translate-y-1 data-[side=left]:-translate-x-1 data-[side=right]:translate-x-1 data-[side=top]:-translate-y-1",
      className
    ),
    position,
    ...props,
    children: [
      /* @__PURE__ */ jsx(SelectScrollUpButton, {}),
      /* @__PURE__ */ jsx(
        SelectPrimitive.Viewport,
        {
          className: cn(
            "p-1",
            position === "popper" && "h-[var(--radix-select-trigger-height)] w-full min-w-[var(--radix-select-trigger-width)]"
          ),
          children
        }
      ),
      /* @__PURE__ */ jsx(SelectScrollDownButton, {})
    ]
  }
) }));
SelectContent.displayName = SelectPrimitive.Content.displayName;
const SelectLabel = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  SelectPrimitive.Label,
  {
    ref,
    className: cn("py-1.5 pl-8 pr-2 text-sm font-semibold", className),
    ...props
  }
));
SelectLabel.displayName = SelectPrimitive.Label.displayName;
const SelectItem = React.forwardRef(({ className, children, ...props }, ref) => /* @__PURE__ */ jsxs(
  SelectPrimitive.Item,
  {
    ref,
    className: cn(
      "relative flex w-full cursor-default select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm outline-none focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
      className
    ),
    ...props,
    children: [
      /* @__PURE__ */ jsx("span", { className: "absolute left-2 flex h-3.5 w-3.5 items-center justify-center", children: /* @__PURE__ */ jsx(SelectPrimitive.ItemIndicator, { children: /* @__PURE__ */ jsx(Check, { className: "h-4 w-4" }) }) }),
      /* @__PURE__ */ jsx(SelectPrimitive.ItemText, { children })
    ]
  }
));
SelectItem.displayName = SelectPrimitive.Item.displayName;
const SelectSeparator = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  SelectPrimitive.Separator,
  {
    ref,
    className: cn("-mx-1 my-1 h-px bg-muted", className),
    ...props
  }
));
SelectSeparator.displayName = SelectPrimitive.Separator.displayName;
const UI_TOKEN = env.VITE_INTERNAL_UI_TOKEN || "";
function useUsers({
  tenantId,
  email,
  page
} = {}) {
  return useQuery({
    queryKey: ["users", { tenantId, email, page }],
    queryFn: async () => {
      const result = await searchUsers({
        data: { tenantId, email, page, uiToken: UI_TOKEN }
      });
      return {
        data: result.data ?? [],
        pagination: result.pagination
      };
    }
  });
}
function TransferOwnershipDialog({
  user,
  tenantId,
  isOpen,
  onClose,
  onSuccess
}) {
  const [selectedUserId, setSelectedUserId] = useState("");
  const [step, setStep] = useState("select");
  const { data: usersData, isLoading: usersLoading } = useUsers({ tenantId });
  const requestTransfer = useRequestOwnershipTransfer();
  const eligibleUsers = useMemo(() => {
    const users = usersData?.data;
    if (!users) return [];
    return users.filter((u) => u.id !== user?.id);
  }, [usersData, user]);
  const selectedUser = useMemo(() => {
    return eligibleUsers.find((u) => u.id === selectedUserId);
  }, [eligibleUsers, selectedUserId]);
  const handleNext = () => {
    if (selectedUserId) {
      setStep("confirm");
    }
  };
  const handleBack = () => {
    setStep("select");
  };
  const handleTransfer = async () => {
    if (!user || !selectedUserId) return;
    try {
      await requestTransfer.mutateAsync({
        tenantId,
        fromUserId: user.id,
        toUserId: selectedUserId
      });
      setSelectedUserId("");
      setStep("select");
      onSuccess?.();
      onClose();
    } catch (error) {
    }
  };
  const handleClose = () => {
    setSelectedUserId("");
    setStep("select");
    onClose();
  };
  return /* @__PURE__ */ jsx(Dialog, { open: isOpen, onOpenChange: handleClose, children: /* @__PURE__ */ jsxs(DialogContent, { className: "sm:max-w-md", children: [
    /* @__PURE__ */ jsxs(DialogHeader, { children: [
      /* @__PURE__ */ jsxs(DialogTitle, { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsx(ArrowRightLeft, { className: "h-5 w-5" }),
        "Transfer Ownership"
      ] }),
      /* @__PURE__ */ jsx(DialogDescription, { children: step === "select" ? "Select a new primary owner for this tenant." : "Review and confirm the ownership transfer." })
    ] }),
    step === "select" ? /* @__PURE__ */ jsxs("div", { className: "space-y-4 py-4", children: [
      /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
        /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", children: "Current Owner" }),
        /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3 rounded-md border bg-muted/50 px-3 py-2", children: [
          /* @__PURE__ */ jsx("div", { className: "flex h-8 w-8 items-center justify-center rounded-full bg-primary/10", children: /* @__PURE__ */ jsx(User, { className: "h-4 w-4 text-primary" }) }),
          /* @__PURE__ */ jsxs("div", { className: "flex-1 min-w-0", children: [
            /* @__PURE__ */ jsx("p", { className: "text-sm font-medium truncate", children: user?.name }),
            /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground truncate", children: user?.email })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
        /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", children: "New Owner" }),
        /* @__PURE__ */ jsxs(
          Select,
          {
            value: selectedUserId,
            onValueChange: setSelectedUserId,
            disabled: usersLoading,
            children: [
              /* @__PURE__ */ jsx(SelectTrigger, { children: /* @__PURE__ */ jsx(SelectValue, { placeholder: "Select a user…" }) }),
              /* @__PURE__ */ jsx(SelectContent, { children: eligibleUsers.map((u) => /* @__PURE__ */ jsx(SelectItem, { value: u.id, children: /* @__PURE__ */ jsxs("div", { className: "flex flex-col items-start", children: [
                /* @__PURE__ */ jsx("span", { className: "font-medium", children: u.name }),
                /* @__PURE__ */ jsx("span", { className: "text-xs text-muted-foreground", children: u.email })
              ] }) }, u.id)) })
            ]
          }
        ),
        eligibleUsers.length === 0 && !usersLoading && /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: "No eligible users found. Add more users to this tenant first." })
      ] }),
      /* @__PURE__ */ jsxs(Alert, { variant: "info", className: "bg-blue-500/10 border-blue-500/20", children: [
        /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4 text-blue-500" }),
        /* @__PURE__ */ jsx(AlertDescription, { className: "text-sm text-blue-700 dark:text-blue-300", children: "The selected user will receive an invitation to accept ownership. They must accept within 7 days." })
      ] })
    ] }) : /* @__PURE__ */ jsxs("div", { className: "space-y-4 py-4", children: [
      /* @__PURE__ */ jsx("div", { className: "rounded-lg border p-4 space-y-4", children: /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
        /* @__PURE__ */ jsxs("div", { children: [
          /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: "From" }),
          /* @__PURE__ */ jsx("p", { className: "font-medium", children: user?.name }),
          /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: user?.email })
        ] }),
        /* @__PURE__ */ jsx(ArrowRightLeft, { className: "h-5 w-5 text-muted-foreground" }),
        /* @__PURE__ */ jsxs("div", { className: "text-right", children: [
          /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: "To" }),
          /* @__PURE__ */ jsx("p", { className: "font-medium", children: selectedUser?.name }),
          /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: selectedUser?.email })
        ] })
      ] }) }),
      /* @__PURE__ */ jsxs(Alert, { variant: "warning", children: [
        /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4" }),
        /* @__PURE__ */ jsx(AlertDescription, { children: "After transfer, you will lose primary owner privileges for this tenant. This action requires the recipient's acceptance." })
      ] })
    ] }),
    /* @__PURE__ */ jsx(DialogFooter, { className: "gap-2 sm:gap-0", children: step === "select" ? /* @__PURE__ */ jsxs(Fragment, { children: [
      /* @__PURE__ */ jsx(Button, { variant: "outline", onClick: handleClose, children: "Cancel" }),
      /* @__PURE__ */ jsx(Button, { onClick: handleNext, disabled: !selectedUserId, children: "Next" })
    ] }) : /* @__PURE__ */ jsxs(Fragment, { children: [
      /* @__PURE__ */ jsx(Button, { variant: "outline", onClick: handleBack, children: "Back" }),
      /* @__PURE__ */ jsx(
        Button,
        {
          onClick: handleTransfer,
          disabled: requestTransfer.isPending,
          className: "gap-2",
          children: requestTransfer.isPending ? "Sending…" : /* @__PURE__ */ jsxs(Fragment, { children: [
            /* @__PURE__ */ jsx(Check, { className: "h-4 w-4" }),
            "Send Invitation"
          ] })
        }
      )
    ] }) })
  ] }) });
}
const statusConfig = {
  active: {
    label: "Active",
    variant: "success"
  },
  pending: {
    label: "Pending",
    variant: "warning"
  },
  suspended: {
    label: "Suspended",
    variant: "destructive"
  }
};
function UsersPage() {
  const [users, setUsers] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [userToDelete, setUserToDelete] = useState(null);
  const [userToTransfer, setUserToTransfer] = useState(null);
  const [transferTenantId, setTransferTenantId] = useState("");
  const prefersReducedMotion = useReducedMotion();
  const searchUsersFn = useServerFn(searchUsers);
  useEffect(() => {
    const fetchUsers = async () => {
      setIsLoading(true);
      try {
        const result = await searchUsersFn({
          data: {
            page: 1
          }
        });
        setUsers(result.data || []);
      } catch (error) {
        toast.error("Failed to load users");
      } finally {
        setIsLoading(false);
      }
    };
    fetchUsers();
  }, []);
  const columns = [createSelectColumn(), {
    accessorKey: "name",
    header: "User",
    cell: ({
      row
    }) => {
      const user = row.original;
      return /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
        /* @__PURE__ */ jsx("div", { className: "h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center", children: /* @__PURE__ */ jsx("span", { className: "text-sm font-medium text-primary", children: user.name?.[0] || (user.email ? user.email[0].toUpperCase() : "?") }) }),
        /* @__PURE__ */ jsxs("div", { children: [
          /* @__PURE__ */ jsx("p", { className: "font-medium", children: user.name || "Unnamed User" }),
          /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: user.email ?? "unknown" })
        ] })
      ] });
    }
  }, {
    accessorKey: "status",
    header: "Status",
    cell: ({
      getValue
    }) => {
      const status = getValue();
      const config = statusConfig[status] || {
        label: status,
        variant: "default"
      };
      return /* @__PURE__ */ jsx(Badge, { variant: config.variant, children: config.label });
    }
  }, {
    id: "actions",
    header: "",
    cell: ({
      row
    }) => {
      const user = row.original;
      return /* @__PURE__ */ jsxs(DropdownMenu, { children: [
        /* @__PURE__ */ jsx(DropdownMenuTrigger, { asChild: true, children: /* @__PURE__ */ jsx(Button, { variant: "ghost", size: "icon-sm", "aria-label": "Open user actions", children: /* @__PURE__ */ jsx(MoreHorizontal, { className: "h-4 w-4" }) }) }),
        /* @__PURE__ */ jsxs(DropdownMenuContent, { align: "end", children: [
          /* @__PURE__ */ jsxs(DropdownMenuItem, { children: [
            /* @__PURE__ */ jsx(Mail, { className: "mr-2 h-4 w-4" }),
            "Send Email"
          ] }),
          /* @__PURE__ */ jsxs(DropdownMenuItem, { className: "text-destructive", onClick: () => setUserToDelete({
            id: user.id ?? "",
            email: user.email ?? "unknown",
            name: user.name || void 0
          }), children: [
            /* @__PURE__ */ jsx(Trash2, { className: "mr-2 h-4 w-4" }),
            "Delete"
          ] }),
          /* @__PURE__ */ jsxs(DropdownMenuItem, { onClick: () => {
            setUserToTransfer({
              id: user.id ?? "",
              email: user.email ?? "unknown",
              name: user.name || void 0
            });
            setTransferTenantId("tenant-1");
          }, children: [
            /* @__PURE__ */ jsx(Shield, { className: "mr-2 h-4 w-4" }),
            "Transfer Ownership"
          ] })
        ] })
      ] });
    }
  }];
  const stats = {
    total: users.length || 2480,
    active: users.filter((u) => u.status === "active").length || 2100,
    pending: users.filter((u) => u.status === "pending").length || 180,
    suspended: users.filter((u) => u.status === "suspended").length || 45
  };
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "Users", description: "Manage platform users across all tenants", breadcrumbs: [{
      label: "Users"
    }] }),
    /* @__PURE__ */ jsx("div", { className: "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4", children: [{
      label: "Total Users",
      value: stats.total,
      color: "blue"
    }, {
      label: "Active",
      value: stats.active,
      color: "green"
    }, {
      label: "Pending",
      value: stats.pending,
      color: "amber"
    }, {
      label: "Suspended",
      value: stats.suspended,
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
    }, children: /* @__PURE__ */ jsxs(Card, { className: "p-6 card-hover", children: [
      /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: stat.label }),
      /* @__PURE__ */ jsx("p", { className: "text-3xl font-bold mt-1", children: formatNumber(stat.value) })
    ] }) }, stat.label)) }),
    /* @__PURE__ */ jsx(Card, { children: /* @__PURE__ */ jsx(DataTable, { columns, data: users, isLoading, searchable: true, searchPlaceholder: "Search users by name or email…", pagination: true, pageSize: 10, exportable: true, exportFileName: "users" }) }),
    /* @__PURE__ */ jsx(DeleteUserDialog, { user: userToDelete, isOpen: !!userToDelete, onClose: () => setUserToDelete(null), onSuccess: () => {
      toast.success("User deleted successfully");
      searchUsersFn({
        data: {
          page: 1
        }
      }).then((result) => {
        setUsers(result.data || []);
      });
    }, onTransferOwnership: (userId) => {
      const user = users.find((u) => u.id === userId);
      if (user) {
        setUserToTransfer({
          id: user.id ?? "",
          email: user.email ?? "unknown",
          name: user.name || void 0
        });
        setTransferTenantId("tenant-1");
      }
    } }),
    /* @__PURE__ */ jsx(TransferOwnershipDialog, { user: userToTransfer, tenantId: transferTenantId, isOpen: !!userToTransfer, onClose: () => {
      setUserToTransfer(null);
      setTransferTenantId("");
    }, onSuccess: () => {
      toast.success("Ownership transfer request sent");
    } })
  ] });
}
export {
  UsersPage as component
};
