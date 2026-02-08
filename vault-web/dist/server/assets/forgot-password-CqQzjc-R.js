import { jsx, jsxs } from "react/jsx-runtime";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { CheckCircle, ArrowLeft, KeyRound, AlertCircle, Mail } from "lucide-react";
import { B as Button } from "./router-BDwxh4pl.js";
import { I as Input } from "./Input-C7MrN6IE.js";
import { C as Card, d as CardContent, a as CardHeader, b as CardTitle, c as CardDescription } from "./Card-Brxgy2gk.js";
import { A as Alert, a as AlertDescription } from "./Alert-BGdSf0_L.js";
import { useForm } from "@tanstack/react-form";
import { u as useHostedSearchParams, H as HostedLayout, a as useHostedConfig, i as hostedRequestPasswordReset } from "./HostedLayout-Dne6B-Jo.js";
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
function HostedForgotPasswordPage() {
  const searchParams = useHostedSearchParams();
  return /* @__PURE__ */ jsx(HostedLayout, { searchParams: new URLSearchParams(window.location.search), children: /* @__PURE__ */ jsx(ForgotPasswordContent, { searchParams }) });
}
function ForgotPasswordContent({
  searchParams
}) {
  const {
    config,
    tenantId
  } = useHostedConfig();
  const prefersReducedMotion = useReducedMotion();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isSuccess, setIsSuccess] = useState(false);
  const form = useForm({
    defaultValues: {
      email: ""
    },
    onSubmit: async ({
      value
    }) => {
      if (!tenantId) return;
      setIsLoading(true);
      setError(null);
      try {
        await hostedRequestPasswordReset({
          data: {
            email: value.email,
            tenantId
          }
        });
        setIsSuccess(true);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to send reset email");
      } finally {
        setIsLoading(false);
      }
    }
  });
  if (!config || !tenantId) {
    return null;
  }
  if (isSuccess) {
    return /* @__PURE__ */ jsx(Card, { className: "shadow-elevated", children: /* @__PURE__ */ jsx(CardContent, { className: "pt-6", children: /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
      opacity: 0,
      scale: 0.95
    }, animate: {
      opacity: 1,
      scale: 1
    }, className: "text-center space-y-6 py-8", children: [
      /* @__PURE__ */ jsx("div", { className: "w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto", children: /* @__PURE__ */ jsx(CheckCircle, { className: "w-8 h-8 text-green-600 dark:text-green-400" }) }),
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsx("h3", { className: "text-xl font-semibold", children: "Check your email" }),
        /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground mt-2", children: [
          "We've sent password reset instructions to ",
          /* @__PURE__ */ jsx("strong", { children: form.getFieldValue("email") })
        ] }),
        /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground mt-2", children: "The link will expire in 1 hour." })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "space-y-3", children: [
        /* @__PURE__ */ jsx(Button, { variant: "outline", fullWidth: true, onClick: () => setIsSuccess(false), children: "Use a different email" }),
        /* @__PURE__ */ jsx(Link, { to: "/hosted/sign-in", search: {
          tenant_id: tenantId
        }, className: "block", children: /* @__PURE__ */ jsxs(Button, { variant: "ghost", fullWidth: true, className: "gap-2", children: [
          /* @__PURE__ */ jsx(ArrowLeft, { className: "h-4 w-4" }),
          "Back to Sign In"
        ] }) })
      ] })
    ] }) }) });
  }
  return /* @__PURE__ */ jsxs(Card, { className: "shadow-elevated", children: [
    /* @__PURE__ */ jsxs(CardHeader, { className: "space-y-1", children: [
      /* @__PURE__ */ jsx("div", { className: "mx-auto w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mb-2", children: /* @__PURE__ */ jsx(KeyRound, { className: "h-6 w-6 text-primary" }) }),
      /* @__PURE__ */ jsx(CardTitle, { className: "text-2xl text-center", children: "Forgot password?" }),
      /* @__PURE__ */ jsx(CardDescription, { className: "text-center", children: "Enter your email and we'll send you reset instructions" })
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
        /* @__PURE__ */ jsx(form.Field, { name: "email", validators: {
          onChange: ({
            value
          }) => {
            if (!value.trim()) return "Email is required";
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
              return "Please enter a valid email";
            }
            return void 0;
          }
        }, children: (field) => /* @__PURE__ */ jsx(Input, { label: "Email", type: "email", placeholder: "you@example.com", value: field.state.value, onChange: (e) => field.handleChange(e.target.value), onBlur: field.handleBlur, error: field.state.meta.isTouched ? field.state.meta.errors[0] : void 0, leftIcon: /* @__PURE__ */ jsx(Mail, { className: "h-4 w-4 text-muted-foreground" }), autoComplete: "email", autoCapitalize: "none", spellCheck: false, required: true, disabled: isLoading }) }),
        /* @__PURE__ */ jsx(Button, { type: "submit", fullWidth: true, size: "lg", isLoading, children: "Send Reset Instructions" })
      ] }),
      /* @__PURE__ */ jsx("div", { className: "text-center pt-4 border-t", children: /* @__PURE__ */ jsxs(Link, { to: "/hosted/sign-in", search: {
        tenant_id: tenantId
      }, className: "inline-flex items-center gap-2 text-sm text-primary hover:underline", children: [
        /* @__PURE__ */ jsx(ArrowLeft, { className: "h-4 w-4" }),
        "Back to Sign In"
      ] }) })
    ] })
  ] });
}
export {
  HostedForgotPasswordPage as component
};
