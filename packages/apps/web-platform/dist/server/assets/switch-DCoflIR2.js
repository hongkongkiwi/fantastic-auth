import { jsx, jsxs } from "react/jsx-runtime";
import { useNavigate } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { useReducedMotion, motion, AnimatePresence } from "framer-motion";
import { Building2, AlertCircle, Plus, Crown, Check, ArrowRight, Users } from "lucide-react";
import { b as Alert, f as AlertDescription, B as Button } from "./router-BqFKwE1w.js";
import { C as Card, a as CardHeader, b as CardTitle, c as CardDescription, d as CardContent } from "./Card-DiqECnNB.js";
import { H as HostedLayout, u as useHostedConfig, g as hostedListOrganizations, i as hostedSwitchOrganization } from "./HostedLayout-BdDuyvHy.js";
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
function HostedOrganizationSwitchPage() {
  return /* @__PURE__ */ jsx(HostedLayout, { searchParams: new URLSearchParams(window.location.search), children: /* @__PURE__ */ jsx(OrganizationSwitchContent, {}) });
}
function OrganizationSwitchContent() {
  const navigate = useNavigate();
  const {
    config,
    tenantId,
    redirectUrl,
    organizationId
  } = useHostedConfig();
  const prefersReducedMotion = useReducedMotion();
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [organizations, setOrganizations] = useState([]);
  const [switchingOrgId, setSwitchingOrgId] = useState(null);
  const getSessionToken = () => {
    return sessionStorage.getItem("hosted_session_token") || "";
  };
  useEffect(() => {
    if (!tenantId) return;
    const fetchOrganizations = async () => {
      const sessionToken = getSessionToken();
      if (!sessionToken) {
        setError("You must be signed in to view organizations");
        setIsLoading(false);
        return;
      }
      try {
        const result = await hostedListOrganizations({
          data: {
            tenantId,
            sessionToken
          }
        });
        setOrganizations(result.organizations);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load organizations");
      } finally {
        setIsLoading(false);
      }
    };
    void fetchOrganizations();
  }, [tenantId]);
  if (!config || !tenantId) {
    return null;
  }
  const handleSwitch = async (orgId) => {
    const sessionToken = getSessionToken();
    if (!sessionToken) {
      setError("Session expired. Please sign in again.");
      return;
    }
    setSwitchingOrgId(orgId);
    setError(null);
    try {
      const result = await hostedSwitchOrganization({
        data: {
          organizationId: orgId,
          tenantId,
          sessionToken
        }
      });
      window.location.href = redirectUrl || result.redirectUrl;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to switch organization");
      setSwitchingOrgId(null);
    }
  };
  const handleCreateNew = () => {
    navigate({
      to: "/hosted/organization/create",
      search: {
        tenant_id: tenantId,
        redirect_url: redirectUrl || void 0
      }
    });
  };
  return /* @__PURE__ */ jsxs(Card, { className: "shadow-elevated", children: [
    /* @__PURE__ */ jsxs(CardHeader, { className: "space-y-1", children: [
      /* @__PURE__ */ jsx("div", { className: "mx-auto w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mb-2", children: /* @__PURE__ */ jsx(Building2, { className: "h-6 w-6 text-primary" }) }),
      /* @__PURE__ */ jsx(CardTitle, { className: "text-2xl text-center", children: "Switch Organization" }),
      /* @__PURE__ */ jsx(CardDescription, { className: "text-center", children: "Select an organization to continue" })
    ] }),
    /* @__PURE__ */ jsxs(CardContent, { className: "space-y-4", children: [
      error && /* @__PURE__ */ jsxs(Alert, { variant: "destructive", children: [
        /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4" }),
        /* @__PURE__ */ jsx(AlertDescription, { children: error })
      ] }),
      isLoading ? /* @__PURE__ */ jsxs("div", { className: "py-8 text-center", children: [
        /* @__PURE__ */ jsx("div", { className: "w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4" }),
        /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Loading organizations..." })
      ] }) : organizations.length === 0 ? (
        /* Empty State */
        /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
          opacity: 0
        }, animate: {
          opacity: 1
        }, className: "text-center py-8 space-y-4", children: [
          /* @__PURE__ */ jsx("div", { className: "w-16 h-16 bg-muted rounded-full flex items-center justify-center mx-auto", children: /* @__PURE__ */ jsx(Building2, { className: "h-8 w-8 text-muted-foreground" }) }),
          /* @__PURE__ */ jsxs("div", { children: [
            /* @__PURE__ */ jsx("p", { className: "text-muted-foreground", children: "You don't have any organizations yet." }),
            /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Create one to get started." })
          ] }),
          /* @__PURE__ */ jsxs(Button, { onClick: handleCreateNew, className: "gap-2", children: [
            /* @__PURE__ */ jsx(Plus, { className: "h-4 w-4" }),
            "Create Organization"
          ] })
        ] })
      ) : (
        /* Organization List */
        /* @__PURE__ */ jsx("div", { className: "space-y-2", children: /* @__PURE__ */ jsx(AnimatePresence, { mode: "popLayout", children: organizations.map((org, index) => /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
          opacity: 0,
          y: 10
        }, animate: {
          opacity: 1,
          y: 0
        }, exit: {
          opacity: 0,
          scale: 0.95
        }, transition: {
          delay: prefersReducedMotion ? 0 : index * 0.05
        }, children: /* @__PURE__ */ jsxs("button", { type: "button", onClick: () => handleSwitch(org.id), disabled: switchingOrgId === org.id, className: `w-full flex items-center gap-4 p-4 rounded-lg border transition-all text-left ${organizationId === org.id ? "border-primary bg-primary/5" : "border-border hover:border-primary/50 hover:bg-muted/50"}`, children: [
          /* @__PURE__ */ jsx("div", { className: "flex-shrink-0", children: org.logoUrl ? /* @__PURE__ */ jsx("img", { src: org.logoUrl, alt: org.name, className: "w-12 h-12 rounded-lg object-cover" }) : /* @__PURE__ */ jsx("div", { className: "w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center", children: /* @__PURE__ */ jsx(Building2, { className: "h-6 w-6 text-primary" }) }) }),
          /* @__PURE__ */ jsxs("div", { className: "flex-1 min-w-0", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
              /* @__PURE__ */ jsx("h4", { className: "font-semibold truncate", children: org.name }),
              org.role === "owner" && /* @__PURE__ */ jsx(Crown, { className: "h-4 w-4 text-amber-500 flex-shrink-0" })
            ] }),
            /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground", children: [
              "/",
              org.slug
            ] })
          ] }),
          /* @__PURE__ */ jsx("div", { className: "flex-shrink-0", children: switchingOrgId === org.id ? /* @__PURE__ */ jsx("div", { className: "w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" }) : organizationId === org.id ? /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-1 text-primary text-sm", children: [
            /* @__PURE__ */ jsx(Check, { className: "h-4 w-4" }),
            /* @__PURE__ */ jsx("span", { className: "hidden sm:inline", children: "Current" })
          ] }) : /* @__PURE__ */ jsx(ArrowRight, { className: "h-5 w-5 text-muted-foreground" }) })
        ] }) }, org.id)) }) })
      ),
      !isLoading && organizations.length > 0 && /* @__PURE__ */ jsx("div", { className: "pt-4 border-t", children: /* @__PURE__ */ jsxs(Button, { variant: "outline", fullWidth: true, onClick: handleCreateNew, className: "gap-2", children: [
        /* @__PURE__ */ jsx(Plus, { className: "h-4 w-4" }),
        "Create New Organization"
      ] }) }),
      !isLoading && organizations.length > 0 && /* @__PURE__ */ jsx("div", { className: "text-center", children: /* @__PURE__ */ jsxs("button", { type: "button", onClick: () => handleSwitch("personal"), disabled: switchingOrgId === "personal", className: "inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors", children: [
        /* @__PURE__ */ jsx(Users, { className: "h-4 w-4" }),
        "Continue with personal account",
        switchingOrgId === "personal" && /* @__PURE__ */ jsx("div", { className: "w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" })
      ] }) })
    ] })
  ] });
}
export {
  HostedOrganizationSwitchPage as component
};
