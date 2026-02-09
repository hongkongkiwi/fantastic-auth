import { jsx, jsxs } from "react/jsx-runtime";
import { useState } from "react";
import { useQueryClient, useQuery, useMutation } from "@tanstack/react-query";
import { Loader2, Plus, Webhook, CheckCircle, XCircle, Edit2, Trash2 } from "lucide-react";
import { t as toast, B as Button, D as Dialog, n as DialogContent, o as DialogHeader, p as DialogTitle, q as DialogDescription, r as DialogFooter } from "./router-BqFKwE1w.js";
import { I as Input } from "./Input-D8nMsmC2.js";
import "@tanstack/react-router";
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
const EVENT_OPTIONS = [
  { value: "user.created", label: "User Created" },
  { value: "user.updated", label: "User Updated" },
  { value: "user.deleted", label: "User Deleted" },
  { value: "user.login", label: "User Login" },
  { value: "user.login_failed", label: "Login Failed" },
  { value: "session.created", label: "Session Created" },
  { value: "session.revoked", label: "Session Revoked" },
  { value: "mfa.enabled", label: "MFA Enabled" },
  { value: "mfa.disabled", label: "MFA Disabled" },
  { value: "*", label: "All Events" }
];
function WebhookManager() {
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [editingWebhook, setEditingWebhook] = useState(null);
  const queryClient = useQueryClient();
  const { data: webhooks, isLoading } = useQuery({
    queryKey: ["webhooks"],
    queryFn: async () => {
      const res = await fetch("/api/v1/admin/webhooks");
      if (!res.ok) throw new Error("Failed to load webhooks");
      return res.json();
    }
  });
  const toggleMutation = useMutation({
    mutationFn: async ({ id, active }) => {
      await fetch(`/api/v1/admin/webhooks/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ active })
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhooks"] });
    }
  });
  const deleteMutation = useMutation({
    mutationFn: async (id) => {
      await fetch(`/api/v1/admin/webhooks/${id}`, { method: "DELETE" });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhooks"] });
      toast.success("Webhook deleted");
    }
  });
  if (isLoading) {
    return /* @__PURE__ */ jsx("div", { className: "flex items-center justify-center py-12", children: /* @__PURE__ */ jsx(Loader2, { className: "h-6 w-6 animate-spin" }) });
  }
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsx("h3", { className: "text-lg font-medium", children: "Webhook Endpoints" }),
        /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Configure endpoints to receive event notifications" })
      ] }),
      /* @__PURE__ */ jsxs(Button, { onClick: () => setIsCreateOpen(true), children: [
        /* @__PURE__ */ jsx(Plus, { className: "mr-2 h-4 w-4" }),
        "Add Webhook"
      ] })
    ] }),
    webhooks?.length === 0 ? /* @__PURE__ */ jsxs("div", { className: "text-center py-12 border rounded-lg", children: [
      /* @__PURE__ */ jsx(Webhook, { className: "h-12 w-12 mx-auto text-muted-foreground/50 mb-4" }),
      /* @__PURE__ */ jsx("p", { className: "text-muted-foreground", children: "No webhooks configured" }),
      /* @__PURE__ */ jsx(
        Button,
        {
          variant: "outline",
          className: "mt-4",
          onClick: () => setIsCreateOpen(true),
          children: "Create your first webhook"
        }
      )
    ] }) : /* @__PURE__ */ jsx("div", { className: "space-y-3", children: webhooks?.map((webhook) => /* @__PURE__ */ jsxs(
      "div",
      {
        className: "p-4 border rounded-lg flex items-center justify-between",
        children: [
          /* @__PURE__ */ jsxs("div", { className: "flex items-start gap-3", children: [
            /* @__PURE__ */ jsx("div", { className: `p-2 rounded-full ${webhook.active ? "bg-green-100 text-green-600" : "bg-gray-100 text-gray-600"}`, children: /* @__PURE__ */ jsx(Webhook, { className: "h-4 w-4" }) }),
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx("p", { className: "font-medium", children: webhook.name }),
              /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: webhook.url }),
              /* @__PURE__ */ jsx("div", { className: "flex items-center gap-2 mt-1", children: webhook.events.includes("*") ? /* @__PURE__ */ jsx("span", { className: "text-xs px-2 py-0.5 bg-primary/10 rounded", children: "All events" }) : /* @__PURE__ */ jsxs("span", { className: "text-xs text-muted-foreground", children: [
                webhook.events.length,
                " event",
                webhook.events.length !== 1 ? "s" : ""
              ] }) })
            ] })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsx(
              Button,
              {
                variant: "ghost",
                size: "sm",
                onClick: () => toggleMutation.mutate({ id: webhook.id, active: !webhook.active }),
                children: webhook.active ? /* @__PURE__ */ jsx(CheckCircle, { className: "h-4 w-4 text-green-500" }) : /* @__PURE__ */ jsx(XCircle, { className: "h-4 w-4 text-gray-400" })
              }
            ),
            /* @__PURE__ */ jsx(
              Button,
              {
                variant: "ghost",
                size: "sm",
                onClick: () => setEditingWebhook(webhook),
                children: /* @__PURE__ */ jsx(Edit2, { className: "h-4 w-4" })
              }
            ),
            /* @__PURE__ */ jsx(
              Button,
              {
                variant: "ghost",
                size: "sm",
                onClick: () => deleteMutation.mutate(webhook.id),
                disabled: deleteMutation.isPending,
                children: /* @__PURE__ */ jsx(Trash2, { className: "h-4 w-4 text-destructive" })
              }
            )
          ] })
        ]
      },
      webhook.id
    )) }),
    /* @__PURE__ */ jsx(
      CreateWebhookDialog,
      {
        open: isCreateOpen,
        onClose: () => setIsCreateOpen(false)
      }
    ),
    editingWebhook && /* @__PURE__ */ jsx(
      EditWebhookDialog,
      {
        webhook: editingWebhook,
        open: true,
        onClose: () => setEditingWebhook(null)
      }
    )
  ] });
}
function CreateWebhookDialog({ open, onClose }) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [selectedEvents, setSelectedEvents] = useState([]);
  const queryClient = useQueryClient();
  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch("/api/v1/admin/webhooks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          url,
          events: selectedEvents
        })
      });
      if (!res.ok) throw new Error("Failed to create webhook");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhooks"] });
      toast.success("Webhook created");
      onClose();
      setName("");
      setUrl("");
      setSelectedEvents([]);
    },
    onError: () => toast.error("Failed to create webhook")
  });
  const toggleEvent = (event) => {
    if (event === "*") {
      setSelectedEvents(["*"]);
    } else {
      setSelectedEvents((prev) => {
        const withoutAll = prev.filter((e) => e !== "*");
        if (prev.includes(event)) {
          return withoutAll.filter((e) => e !== event);
        }
        return [...withoutAll, event];
      });
    }
  };
  return /* @__PURE__ */ jsx(Dialog, { open, onOpenChange: onClose, children: /* @__PURE__ */ jsxs(DialogContent, { className: "max-w-lg", children: [
    /* @__PURE__ */ jsxs(DialogHeader, { children: [
      /* @__PURE__ */ jsx(DialogTitle, { children: "Add Webhook Endpoint" }),
      /* @__PURE__ */ jsx(DialogDescription, { children: "Configure a URL to receive event notifications" })
    ] }),
    /* @__PURE__ */ jsxs("div", { className: "space-y-4 py-4", children: [
      /* @__PURE__ */ jsx("div", { className: "space-y-2", children: /* @__PURE__ */ jsx(
        Input,
        {
          label: "Name",
          value: name,
          onChange: (e) => setName(e.target.value),
          placeholder: "My Webhook",
          name: "webhookName",
          autoComplete: "off"
        }
      ) }),
      /* @__PURE__ */ jsx("div", { className: "space-y-2", children: /* @__PURE__ */ jsx(
        Input,
        {
          label: "URL",
          value: url,
          onChange: (e) => setUrl(e.target.value),
          placeholder: "https://example.com/webhook",
          type: "url",
          name: "webhookUrl",
          autoComplete: "url"
        }
      ) }),
      /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
        /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", children: "Events" }),
        /* @__PURE__ */ jsx("div", { className: "flex flex-wrap gap-2", children: EVENT_OPTIONS.map((event) => /* @__PURE__ */ jsx(
          "button",
          {
            type: "button",
            onClick: () => toggleEvent(event.value),
            className: `px-3 py-1 text-xs rounded-full border transition-colors ${selectedEvents.includes(event.value) ? "bg-primary text-primary-foreground border-primary" : "bg-background hover:bg-muted"}`,
            children: event.label
          },
          event.value
        )) })
      ] })
    ] }),
    /* @__PURE__ */ jsxs(DialogFooter, { children: [
      /* @__PURE__ */ jsx(Button, { variant: "outline", onClick: onClose, children: "Cancel" }),
      /* @__PURE__ */ jsx(
        Button,
        {
          onClick: () => createMutation.mutate(),
          disabled: !name || !url || selectedEvents.length === 0 || createMutation.isPending,
          isLoading: createMutation.isPending,
          children: "Create Webhook"
        }
      )
    ] })
  ] }) });
}
function EditWebhookDialog({
  webhook,
  open,
  onClose
}) {
  return /* @__PURE__ */ jsx(Dialog, { open, onOpenChange: onClose, children: /* @__PURE__ */ jsxs(DialogContent, { children: [
    /* @__PURE__ */ jsx(DialogHeader, { children: /* @__PURE__ */ jsx(DialogTitle, { children: "Edit Webhook" }) }),
    /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground", children: [
      'Editing webhook "',
      webhook.name,
      '" is not yet implemented'
    ] }),
    /* @__PURE__ */ jsx(DialogFooter, { children: /* @__PURE__ */ jsx(Button, { onClick: onClose, children: "Close" }) })
  ] }) });
}
export {
  WebhookManager
};
