import { jsx, jsxs } from "react/jsx-runtime";
import { useQueryClient, useQuery, useMutation } from "@tanstack/react-query";
import { Loader2, LogOut, ShieldCheck, Tablet, Smartphone, Laptop, Monitor, MapPin, Clock } from "lucide-react";
import { t as toast, B as Button, h as formatRelativeTime } from "./router-BqFKwE1w.js";
import "@tanstack/react-router";
import "react";
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
function SessionManager({ userId }) {
  const queryClient = useQueryClient();
  const isAdminView = !!userId;
  const { data: sessions, isLoading } = useQuery({
    queryKey: ["sessions", userId || "me"],
    queryFn: async () => {
      const endpoint = isAdminView ? `/api/v1/admin/users/${userId}/sessions` : "/api/v1/auth/sessions";
      const res = await fetch(endpoint);
      if (!res.ok) throw new Error("Failed to load sessions");
      return res.json();
    }
  });
  const revokeMutation = useMutation({
    mutationFn: async (sessionId) => {
      const endpoint = isAdminView ? `/api/v1/admin/users/${userId}/sessions/${sessionId}` : `/api/v1/auth/sessions/${sessionId}`;
      await fetch(endpoint, { method: "DELETE" });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sessions", userId || "me"] });
      toast.success("Session revoked");
    },
    onError: () => toast.error("Failed to revoke session")
  });
  const revokeAllMutation = useMutation({
    mutationFn: async () => {
      const endpoint = isAdminView ? `/api/v1/admin/users/${userId}/sessions/revoke-all` : "/api/v1/auth/sessions/revoke-all";
      await fetch(endpoint, { method: "POST" });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sessions", userId || "me"] });
      toast.success("All other sessions revoked");
    },
    onError: () => toast.error("Failed to revoke sessions")
  });
  if (isLoading) {
    return /* @__PURE__ */ jsx("div", { className: "flex items-center justify-center py-8", children: /* @__PURE__ */ jsx(Loader2, { className: "h-6 w-6 animate-spin text-muted-foreground" }) });
  }
  const currentSession = sessions?.find((s) => s.is_current);
  const otherSessions = sessions?.filter((s) => !s.is_current) || [];
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    currentSession && /* @__PURE__ */ jsxs("div", { className: "space-y-3", children: [
      /* @__PURE__ */ jsx("h4", { className: "text-sm font-medium text-muted-foreground uppercase tracking-wider", children: "Current Session" }),
      /* @__PURE__ */ jsx(SessionCard, { session: currentSession })
    ] }),
    /* @__PURE__ */ jsxs("div", { className: "space-y-3", children: [
      /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
        /* @__PURE__ */ jsx("h4", { className: "text-sm font-medium text-muted-foreground uppercase tracking-wider", children: "Other Sessions" }),
        otherSessions.length > 0 && /* @__PURE__ */ jsxs(
          Button,
          {
            variant: "ghost",
            size: "sm",
            onClick: () => revokeAllMutation.mutate(),
            disabled: revokeAllMutation.isPending,
            children: [
              /* @__PURE__ */ jsx(LogOut, { className: "mr-2 h-4 w-4" }),
              "Revoke All"
            ]
          }
        )
      ] }),
      otherSessions.length === 0 ? /* @__PURE__ */ jsxs("div", { className: "text-center py-8 text-muted-foreground", children: [
        /* @__PURE__ */ jsx(ShieldCheck, { className: "h-12 w-12 mx-auto mb-2 opacity-50" }),
        /* @__PURE__ */ jsx("p", { children: "No other active sessions" })
      ] }) : /* @__PURE__ */ jsx("div", { className: "space-y-2", children: otherSessions.map((session) => /* @__PURE__ */ jsx(
        SessionCard,
        {
          session,
          onRevoke: () => revokeMutation.mutate(session.id),
          isRevoking: revokeMutation.isPending
        },
        session.id
      )) })
    ] })
  ] });
}
function SessionCard({
  session,
  onRevoke,
  isRevoking
}) {
  const DeviceIcon = {
    desktop: Laptop,
    mobile: Smartphone,
    tablet: Tablet
  }[session.device_info.device_type] || Monitor;
  return /* @__PURE__ */ jsx("div", { className: `p-4 rounded-lg border ${session.is_current ? "border-primary bg-primary/5" : "border-border"}`, children: /* @__PURE__ */ jsxs("div", { className: "flex items-start justify-between", children: [
    /* @__PURE__ */ jsxs("div", { className: "flex items-start gap-3", children: [
      /* @__PURE__ */ jsx("div", { className: "p-2 rounded-full bg-muted", children: /* @__PURE__ */ jsx(DeviceIcon, { className: "h-5 w-5" }) }),
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsx("span", { className: "font-medium", children: session.device_info.name }),
          session.is_current && /* @__PURE__ */ jsx("span", { className: "px-2 py-0.5 text-xs bg-primary text-primary-foreground rounded-full", children: "Current" })
        ] }),
        /* @__PURE__ */ jsxs("div", { className: "mt-1 text-sm text-muted-foreground space-y-1", children: [
          /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsx("span", { children: session.device_info.browser }),
            /* @__PURE__ */ jsx("span", { children: "•" }),
            /* @__PURE__ */ jsx("span", { children: session.device_info.os })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3 text-xs", children: [
            session.location && /* @__PURE__ */ jsxs("span", { className: "flex items-center gap-1", children: [
              /* @__PURE__ */ jsx(MapPin, { className: "h-3 w-3" }),
              session.location
            ] }),
            /* @__PURE__ */ jsxs("span", { className: "flex items-center gap-1", children: [
              /* @__PURE__ */ jsx(Clock, { className: "h-3 w-3" }),
              "Active ",
              formatRelativeTime(new Date(session.last_active_at))
            ] })
          ] }),
          /* @__PURE__ */ jsx("span", { className: "font-mono text-xs text-muted-foreground/60", children: session.ip_address })
        ] })
      ] })
    ] }),
    !session.is_current && onRevoke && /* @__PURE__ */ jsx(
      Button,
      {
        variant: "ghost",
        size: "sm",
        onClick: onRevoke,
        disabled: isRevoking,
        children: isRevoking ? /* @__PURE__ */ jsx(Loader2, { className: "h-4 w-4 animate-spin" }) : /* @__PURE__ */ jsx(LogOut, { className: "h-4 w-4" })
      }
    )
  ] }) });
}
export {
  SessionManager
};
