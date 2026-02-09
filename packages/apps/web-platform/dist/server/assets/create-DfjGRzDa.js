import { jsx, jsxs } from "react/jsx-runtime";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { CheckCircle, ArrowRight, Building2, AlertCircle, ArrowLeft } from "lucide-react";
import { B as Button, b as Alert, f as AlertDescription } from "./router-BqFKwE1w.js";
import { I as Input } from "./Input-D8nMsmC2.js";
import { C as Card, d as CardContent, a as CardHeader, b as CardTitle, c as CardDescription } from "./Card-DiqECnNB.js";
import { useForm } from "@tanstack/react-form";
import { H as HostedLayout, u as useHostedConfig, j as hostedCreateOrganization } from "./HostedLayout-BdDuyvHy.js";
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
function HostedOrganizationCreatePage() {
  return /* @__PURE__ */ jsx(HostedLayout, { searchParams: new URLSearchParams(window.location.search), children: /* @__PURE__ */ jsx(OrganizationCreateContent, {}) });
}
function OrganizationCreateContent() {
  const {
    config,
    tenantId,
    redirectUrl
  } = useHostedConfig();
  const prefersReducedMotion = useReducedMotion();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isSuccess, setIsSuccess] = useState(false);
  const [createdOrg, setCreatedOrg] = useState(null);
  const getSessionToken = () => {
    return sessionStorage.getItem("hosted_session_token") || "";
  };
  const form = useForm({
    defaultValues: {
      name: "",
      slug: ""
    },
    onSubmit: async ({
      value
    }) => {
      if (!tenantId) return;
      const sessionToken = getSessionToken();
      if (!sessionToken) {
        setError("You must be signed in to create an organization");
        return;
      }
      setIsLoading(true);
      setError(null);
      try {
        const result = await hostedCreateOrganization({
          data: {
            name: value.name,
            slug: value.slug,
            tenantId,
            sessionToken
          }
        });
        setCreatedOrg({
          name: result.name,
          slug: result.slug
        });
        setIsSuccess(true);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to create organization");
      } finally {
        setIsLoading(false);
      }
    }
  });
  const handleNameChange = (name) => {
    form.setFieldValue("name", name);
    const currentSlug = form.getFieldValue("slug");
    const autoSlug = name.toLowerCase().replace(/[^a-z0-9\s-]/g, "").replace(/\s+/g, "-").slice(0, 50);
    if (!currentSlug || currentSlug === form.getFieldValue("name").toLowerCase().replace(/[^a-z0-9\s-]/g, "").replace(/\s+/g, "-").slice(0, 50)) {
      form.setFieldValue("slug", autoSlug);
    }
  };
  if (!config || !tenantId) {
    return null;
  }
  const handleContinue = () => {
    const targetUrl = redirectUrl || config.afterSignInUrl || "/dashboard";
    window.location.href = targetUrl;
  };
  if (isSuccess && createdOrg) {
    return /* @__PURE__ */ jsx(Card, { className: "shadow-elevated", children: /* @__PURE__ */ jsx(CardContent, { className: "pt-6", children: /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
      opacity: 0,
      scale: 0.95
    }, animate: {
      opacity: 1,
      scale: 1
    }, className: "text-center space-y-6 py-8", children: [
      /* @__PURE__ */ jsx("div", { className: "w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto", children: /* @__PURE__ */ jsx(CheckCircle, { className: "w-8 h-8 text-green-600 dark:text-green-400" }) }),
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsx("h3", { className: "text-xl font-semibold", children: "Organization created!" }),
        /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground mt-2", children: [
          /* @__PURE__ */ jsx("strong", { children: createdOrg.name }),
          " has been created successfully."
        ] }),
        /* @__PURE__ */ jsxs("p", { className: "text-xs text-muted-foreground mt-1", children: [
          "Organization slug: ",
          createdOrg.slug
        ] })
      ] }),
      /* @__PURE__ */ jsx(Button, { onClick: handleContinue, fullWidth: true, rightIcon: /* @__PURE__ */ jsx(ArrowRight, { className: "h-4 w-4" }), children: "Continue" })
    ] }) }) });
  }
  return /* @__PURE__ */ jsxs(Card, { className: "shadow-elevated", children: [
    /* @__PURE__ */ jsxs(CardHeader, { className: "space-y-1", children: [
      /* @__PURE__ */ jsx("div", { className: "mx-auto w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mb-2", children: /* @__PURE__ */ jsx(Building2, { className: "h-6 w-6 text-primary" }) }),
      /* @__PURE__ */ jsx(CardTitle, { className: "text-2xl text-center", children: "Create Organization" }),
      /* @__PURE__ */ jsx(CardDescription, { className: "text-center", children: "Set up a new organization for your team" })
    ] }),
    /* @__PURE__ */ jsxs(CardContent, { className: "space-y-4", children: [
      error && /* @__PURE__ */ jsxs(Alert, { variant: "destructive", children: [
        /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4" }),
        /* @__PURE__ */ jsx(AlertDescription, { children: error })
      ] }),
      /* @__PURE__ */ jsxs("form", { onSubmit: (e) => {
        e.preventDefault();
        e.stopPropagation();
        void form.handleSubmit();
      }, className: "space-y-4", children: [
        /* @__PURE__ */ jsx(form.Field, { name: "name", validators: {
          onChange: ({
            value
          }) => {
            if (!value.trim()) return "Organization name is required";
            if (value.trim().length < 2) return "Name must be at least 2 characters";
            if (value.trim().length > 50) return "Name must be less than 50 characters";
            return void 0;
          }
        }, children: (field) => /* @__PURE__ */ jsx(Input, { label: "Organization Name", type: "text", placeholder: "Acme Inc.", value: field.state.value, onChange: (e) => handleNameChange(e.target.value), onBlur: field.handleBlur, error: field.state.meta.isTouched ? field.state.meta.errors[0] : void 0, leftIcon: /* @__PURE__ */ jsx(Building2, { className: "h-4 w-4 text-muted-foreground" }), autoComplete: "organization", required: true, disabled: isLoading }) }),
        /* @__PURE__ */ jsx(form.Field, { name: "slug", validators: {
          onChange: ({
            value
          }) => {
            if (!value.trim()) return "Organization slug is required";
            if (!/^[a-z0-9-]+$/.test(value)) {
              return "Slug can only contain lowercase letters, numbers, and hyphens";
            }
            if (value.length < 2) return "Slug must be at least 2 characters";
            if (value.length > 50) return "Slug must be less than 50 characters";
            return void 0;
          }
        }, children: (field) => /* @__PURE__ */ jsxs("div", { className: "space-y-1.5", children: [
          /* @__PURE__ */ jsxs("label", { className: "text-sm font-medium text-foreground", children: [
            "Organization Slug",
            /* @__PURE__ */ jsx("span", { className: "text-destructive ml-1", children: "*" })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "relative", children: [
            /* @__PURE__ */ jsx("span", { className: "absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-sm", children: "/" }),
            /* @__PURE__ */ jsx("input", { type: "text", value: field.state.value, onChange: (e) => field.handleChange(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "")), onBlur: field.handleBlur, placeholder: "acme-inc", className: `flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 pl-6 text-sm ring-offset-background transition-colors transition-shadow duration-200 placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 hover:border-muted-foreground/30 ${field.state.meta.isTouched && field.state.meta.errors[0] ? "border-destructive focus-visible:ring-destructive" : ""}`, required: true, disabled: isLoading })
          ] }),
          field.state.meta.isTouched && field.state.meta.errors[0] && /* @__PURE__ */ jsx("p", { className: "text-sm text-destructive animate-fade-in", children: field.state.meta.errors[0] }),
          /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: "This will be used in URLs and cannot be changed later" })
        ] }) }),
        /* @__PURE__ */ jsx(Button, { type: "submit", fullWidth: true, size: "lg", isLoading, rightIcon: /* @__PURE__ */ jsx(ArrowRight, { className: "h-4 w-4" }), children: "Create Organization" })
      ] }),
      /* @__PURE__ */ jsx("div", { className: "text-center pt-4 border-t", children: /* @__PURE__ */ jsxs(Link, { to: "/hosted/organization/switch", search: {
        tenant_id: tenantId,
        redirect_url: redirectUrl || void 0
      }, className: "inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors", children: [
        /* @__PURE__ */ jsx(ArrowLeft, { className: "h-4 w-4" }),
        "Back to Organizations"
      ] }) })
    ] })
  ] });
}
export {
  HostedOrganizationCreatePage as component
};
