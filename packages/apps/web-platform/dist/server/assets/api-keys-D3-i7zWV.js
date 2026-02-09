import { jsxs, jsx, Fragment } from "react/jsx-runtime";
import { t as toast, B as Button, a as Badge, D as Dialog, n as DialogContent, o as DialogHeader, p as DialogTitle, q as DialogDescription, r as DialogFooter, C as ConfirmDialog, P as PageHeader } from "./router-BqFKwE1w.js";
import { C as Card, d as CardContent } from "./Card-DiqECnNB.js";
import { useState, useMemo } from "react";
import { I as Input } from "./Input-D8nMsmC2.js";
import "./Switch-DnK4UYa_.js";
import "./Tabs-Dlqc7sYx.js";
import "clsx";
import { motion, AnimatePresence } from "framer-motion";
import { Plus, Key, Clock, Trash2, Shield, EyeOff, Eye, Copy } from "lucide-react";
import { useQueryClient, useQuery, useMutation } from "@tanstack/react-query";
import { u as useServerFn } from "../server.js";
import { m as listApiKeys, n as createApiKey, o as deleteApiKey } from "./internal-api-DaRn9LSO.js";
import "@tanstack/react-router";
import "@t3-oss/env-core";
import "zod";
import "sonner";
import "tailwind-merge";
import "@radix-ui/react-slot";
import "class-variance-authority";
import "@radix-ui/react-dialog";
import "cmdk";
import "@radix-ui/react-checkbox";
import "@radix-ui/react-label";
import "@sentry/react";
import "@radix-ui/react-switch";
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
const availableScopes = [
  { id: "read:users", label: "Read Users", description: "View user data" },
  { id: "write:users", label: "Write Users", description: "Create and modify users" },
  { id: "read:tenants", label: "Read Tenants", description: "View tenant data" },
  { id: "write:tenants", label: "Write Tenants", description: "Manage tenants" },
  { id: "read:audit", label: "Read Audit", description: "View audit logs" },
  { id: "admin", label: "Admin", description: "Full admin access" }
];
function ApiKeyManager() {
  const queryClient = useQueryClient();
  const listApiKeysFn = useServerFn(listApiKeys);
  const createApiKeyFn = useServerFn(createApiKey);
  const deleteApiKeyFn = useServerFn(deleteApiKey);
  const { data: apiKeys = [], isLoading } = useQuery({
    queryKey: ["api-keys"],
    queryFn: () => listApiKeysFn()
  });
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [isRevokeOpen, setIsRevokeOpen] = useState(false);
  const [selectedKey, setSelectedKey] = useState(null);
  const [newKey, setNewKey] = useState(null);
  const [showNewKey, setShowNewKey] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyExpiry, setNewKeyExpiry] = useState("never");
  const [selectedScopes, setSelectedScopes] = useState(["read:users"]);
  const sortedKeys = useMemo(() => {
    return [...apiKeys].sort(
      (a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime()
    );
  }, [apiKeys]);
  const createMutation = useMutation({
    mutationFn: async () => createApiKeyFn({
      data: {
        name: newKeyName,
        scopes: selectedScopes,
        expiresInDays: newKeyExpiry === "never" ? void 0 : Number(newKeyExpiry)
      }
    }),
    onSuccess: (data) => {
      setNewKey(data);
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
      toast.success("API key created");
    },
    onError: () => toast.error("Failed to create API key"),
    onSettled: () => setIsCreating(false)
  });
  const handleCreate = async () => {
    setIsCreating(true);
    createMutation.mutate();
  };
  const revokeMutation = useMutation({
    mutationFn: async (keyId) => deleteApiKeyFn({ data: { keyId } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
      toast.success("API key revoked");
    },
    onError: () => toast.error("Failed to revoke API key")
  });
  const handleRevoke = async () => {
    if (!selectedKey?.id) return;
    await revokeMutation.mutateAsync(selectedKey.id);
    setIsRevokeOpen(false);
    setSelectedKey(null);
  };
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };
  const closeCreateDialog = () => {
    setIsCreateOpen(false);
    setNewKey(null);
    setNewKeyName("");
    setNewKeyExpiry("never");
    setSelectedScopes(["read:users"]);
    setShowNewKey(false);
  };
  const formatDate = (date) => {
    if (!date) return "Never";
    return new Date(date).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric"
    });
  };
  const toggleScope = (scope) => {
    setSelectedScopes(
      (prev) => prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]
    );
  };
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsx("h2", { className: "text-2xl font-bold tracking-tight", children: "API Keys" }),
        /* @__PURE__ */ jsx("p", { className: "text-muted-foreground", children: "Manage API keys for programmatic access to the Vault API" })
      ] }),
      /* @__PURE__ */ jsxs(Button, { onClick: () => setIsCreateOpen(true), children: [
        /* @__PURE__ */ jsx(Plus, { className: "mr-2 h-4 w-4" }),
        "Create API Key"
      ] })
    ] }),
    /* @__PURE__ */ jsxs("div", { className: "space-y-4", children: [
      isLoading && /* @__PURE__ */ jsx(Card, { children: /* @__PURE__ */ jsx(CardContent, { className: "p-6 text-sm text-muted-foreground", children: "Loading API keys…" }) }),
      sortedKeys.map((key) => /* @__PURE__ */ jsx(
        motion.div,
        {
          layout: true,
          initial: { opacity: 0, y: 20 },
          animate: { opacity: 1, y: 0 },
          exit: { opacity: 0, y: -20 },
          children: /* @__PURE__ */ jsx(Card, { children: /* @__PURE__ */ jsxs(CardContent, { className: "flex items-center justify-between p-6", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-start gap-4", children: [
              /* @__PURE__ */ jsx("div", { className: "flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10", children: /* @__PURE__ */ jsx(Key, { className: "h-5 w-5 text-primary" }) }),
              /* @__PURE__ */ jsxs("div", { className: "space-y-1", children: [
                /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
                  /* @__PURE__ */ jsx("h3", { className: "font-semibold", children: key.name }),
                  /* @__PURE__ */ jsxs(Badge, { variant: "outline", className: "font-mono text-xs", children: [
                    key.prefix,
                    "..."
                  ] })
                ] }),
                /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-4 text-sm text-muted-foreground", children: [
                  /* @__PURE__ */ jsxs("span", { className: "flex items-center gap-1", children: [
                    /* @__PURE__ */ jsx(Clock, { className: "h-3 w-3" }),
                    "Created ",
                    formatDate(key.createdAt)
                  ] }),
                  key.expiresAt && /* @__PURE__ */ jsxs("span", { className: "flex items-center gap-1 text-amber-600", children: [
                    /* @__PURE__ */ jsx(Clock, { className: "h-3 w-3" }),
                    "Expires ",
                    formatDate(key.expiresAt)
                  ] }),
                  key.lastUsedAt && /* @__PURE__ */ jsxs("span", { children: [
                    "Last used ",
                    formatDate(key.lastUsedAt)
                  ] })
                ] }),
                /* @__PURE__ */ jsx("div", { className: "flex flex-wrap gap-1 pt-1", children: (key.scopes ?? []).map((scope) => /* @__PURE__ */ jsx(Badge, { variant: "secondary", className: "text-xs", children: scope }, scope)) })
              ] })
            ] }),
            /* @__PURE__ */ jsx(
              Button,
              {
                variant: "ghost",
                size: "sm",
                className: "text-destructive hover:text-destructive",
                onClick: () => {
                  setSelectedKey(key);
                  setIsRevokeOpen(true);
                },
                children: /* @__PURE__ */ jsx(Trash2, { className: "h-4 w-4" })
              }
            )
          ] }) })
        },
        key.id
      )),
      apiKeys.length === 0 && /* @__PURE__ */ jsx(Card, { className: "border-dashed", children: /* @__PURE__ */ jsxs(CardContent, { className: "flex flex-col items-center justify-center py-12", children: [
        /* @__PURE__ */ jsx(Key, { className: "h-12 w-12 text-muted-foreground/50" }),
        /* @__PURE__ */ jsx("h3", { className: "mt-4 text-lg font-semibold", children: "No API keys" }),
        /* @__PURE__ */ jsx("p", { className: "text-muted-foreground", children: "Create an API key to get started with the Vault API" }),
        /* @__PURE__ */ jsxs(Button, { className: "mt-4", onClick: () => setIsCreateOpen(true), children: [
          /* @__PURE__ */ jsx(Plus, { className: "mr-2 h-4 w-4" }),
          "Create API Key"
        ] })
      ] }) })
    ] }),
    /* @__PURE__ */ jsx(Dialog, { open: isCreateOpen, onOpenChange: closeCreateDialog, children: /* @__PURE__ */ jsxs(DialogContent, { className: "max-w-lg", children: [
      /* @__PURE__ */ jsxs(DialogHeader, { children: [
        /* @__PURE__ */ jsx(DialogTitle, { children: "Create API Key" }),
        /* @__PURE__ */ jsx(DialogDescription, { children: "Create a new API key for programmatic access" })
      ] }),
      /* @__PURE__ */ jsx(AnimatePresence, { mode: "wait", children: !newKey ? /* @__PURE__ */ jsxs(
        motion.div,
        {
          initial: { opacity: 0 },
          animate: { opacity: 1 },
          exit: { opacity: 0 },
          className: "space-y-4",
          children: [
            /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
              /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", htmlFor: "key-name", children: "Key Name" }),
              /* @__PURE__ */ jsx(
                Input,
                {
                  id: "key-name",
                  placeholder: "e.g., Production API, Testing Key",
                  value: newKeyName,
                  onChange: (e) => setNewKeyName(e.target.value)
                }
              )
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
              /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", htmlFor: "key-expiry", children: "Expiration" }),
              /* @__PURE__ */ jsxs(
                "select",
                {
                  id: "key-expiry",
                  className: "w-full rounded-md border border-input bg-background px-3 py-2 text-sm",
                  value: newKeyExpiry,
                  onChange: (e) => setNewKeyExpiry(e.target.value),
                  children: [
                    /* @__PURE__ */ jsx("option", { value: "never", children: "Never" }),
                    /* @__PURE__ */ jsx("option", { value: "30", children: "30 days" }),
                    /* @__PURE__ */ jsx("option", { value: "90", children: "90 days" }),
                    /* @__PURE__ */ jsx("option", { value: "365", children: "1 year" })
                  ]
                }
              )
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
              /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", children: "Scopes" }),
              /* @__PURE__ */ jsx("div", { className: "space-y-2 rounded-lg border p-3", children: availableScopes.map((scope) => /* @__PURE__ */ jsxs(
                "label",
                {
                  className: "flex cursor-pointer items-center gap-3 rounded-md p-2 hover:bg-muted",
                  children: [
                    /* @__PURE__ */ jsx(
                      "input",
                      {
                        type: "checkbox",
                        checked: selectedScopes.includes(scope.id),
                        onChange: () => toggleScope(scope.id),
                        className: "h-4 w-4 rounded border-primary"
                      }
                    ),
                    /* @__PURE__ */ jsxs("div", { className: "flex-1", children: [
                      /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
                        /* @__PURE__ */ jsx("span", { className: "font-medium", children: scope.label }),
                        /* @__PURE__ */ jsx("code", { className: "text-xs text-muted-foreground", children: scope.id })
                      ] }),
                      /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: scope.description })
                    ] })
                  ]
                },
                scope.id
              )) })
            ] }),
            /* @__PURE__ */ jsxs(DialogFooter, { children: [
              /* @__PURE__ */ jsx(Button, { variant: "outline", onClick: closeCreateDialog, children: "Cancel" }),
              /* @__PURE__ */ jsx(
                Button,
                {
                  onClick: handleCreate,
                  disabled: !newKeyName || selectedScopes.length === 0 || isCreating,
                  children: isCreating ? /* @__PURE__ */ jsxs(Fragment, { children: [
                    /* @__PURE__ */ jsx(
                      motion.div,
                      {
                        className: "mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
                      }
                    ),
                    "Creating…"
                  ] }) : "Create Key"
                }
              )
            ] })
          ]
        },
        "form"
      ) : /* @__PURE__ */ jsxs(
        motion.div,
        {
          initial: { opacity: 0 },
          animate: { opacity: 1 },
          exit: { opacity: 0 },
          className: "space-y-4",
          children: [
            /* @__PURE__ */ jsxs("div", { className: "rounded-lg bg-green-50 p-4 text-green-800 dark:bg-green-900/20 dark:text-green-400", children: [
              /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
                /* @__PURE__ */ jsx(Shield, { className: "h-5 w-5" }),
                /* @__PURE__ */ jsx("span", { className: "font-medium", children: "API Key Created Successfully" })
              ] }),
              /* @__PURE__ */ jsx("p", { className: "mt-1 text-sm", children: "Copy this key now. You won't be able to see it again!" })
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
              /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", children: "Your API Key" }),
              (() => {
                const keyValue = newKey.key ?? "";
                return /* @__PURE__ */ jsxs("div", { className: "flex gap-2", children: [
                  /* @__PURE__ */ jsx("code", { className: "flex-1 overflow-hidden rounded bg-muted px-3 py-2 text-sm", children: showNewKey ? keyValue : "•".repeat(keyValue.length) }),
                  /* @__PURE__ */ jsx(
                    Button,
                    {
                      variant: "outline",
                      size: "icon",
                      onClick: () => setShowNewKey(!showNewKey),
                      "aria-label": showNewKey ? "Hide API key" : "Show API key",
                      children: showNewKey ? /* @__PURE__ */ jsx(EyeOff, { className: "h-4 w-4" }) : /* @__PURE__ */ jsx(Eye, { className: "h-4 w-4" })
                    }
                  ),
                  /* @__PURE__ */ jsx(
                    Button,
                    {
                      variant: "outline",
                      size: "icon",
                      onClick: () => copyToClipboard(keyValue),
                      "aria-label": "Copy API key",
                      children: /* @__PURE__ */ jsx(Copy, { className: "h-4 w-4" })
                    }
                  )
                ] });
              })()
            ] }),
            /* @__PURE__ */ jsx(DialogFooter, { children: /* @__PURE__ */ jsx(Button, { onClick: closeCreateDialog, children: "I've Copied My Key" }) })
          ]
        },
        "success"
      ) })
    ] }) }),
    /* @__PURE__ */ jsx(
      ConfirmDialog,
      {
        isOpen: isRevokeOpen,
        onClose: () => {
          setIsRevokeOpen(false);
          setSelectedKey(null);
        },
        onConfirm: handleRevoke,
        title: "Revoke API Key",
        description: `Are you sure you want to revoke the API key "${selectedKey?.name}"? This action cannot be undone and any applications using this key will immediately stop working.`,
        confirmText: "Revoke Key",
        variant: "destructive"
      }
    )
  ] });
}
function ApiKeysSettingsPage() {
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "API Keys", description: "Manage API access tokens", breadcrumbs: [{
      label: "Settings",
      href: "/settings"
    }, {
      label: "API Keys"
    }] }),
    /* @__PURE__ */ jsx(Card, { className: "p-6", children: /* @__PURE__ */ jsx(ApiKeyManager, {}) })
  ] });
}
export {
  ApiKeysSettingsPage as component
};
