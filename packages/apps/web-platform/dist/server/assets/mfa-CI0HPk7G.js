import { jsx, jsxs } from "react/jsx-runtime";
import { useNavigate, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { Lock, AlertCircle, Shield, Mail, Smartphone, ArrowRight, ArrowLeft } from "lucide-react";
import { b as Alert, f as AlertDescription, B as Button } from "./router-BqFKwE1w.js";
import { I as Input } from "./Input-D8nMsmC2.js";
import { C as Card, a as CardHeader, b as CardTitle, c as CardDescription, d as CardContent } from "./Card-DiqECnNB.js";
import { T as Tabs, a as TabsList, b as TabsTrigger, c as TabsContent } from "./Tabs-Dlqc7sYx.js";
import { H as HostedLayout, u as useHostedConfig } from "./HostedLayout-BdDuyvHy.js";
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
import "@radix-ui/react-tabs";
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
const methodConfig = {
  totp: {
    icon: Shield,
    title: "Authenticator App",
    description: "Enter the 6-digit code from your authenticator app",
    showResend: false
  },
  email: {
    icon: Mail,
    title: "Email Code",
    description: "Enter the 6-digit code sent to your email",
    showResend: true
  },
  sms: {
    icon: Smartphone,
    title: "SMS Code",
    description: "Enter the 6-digit code sent to your phone",
    showResend: true
  }
};
function HostedMfaPage() {
  return /* @__PURE__ */ jsx(HostedLayout, { searchParams: new URLSearchParams(window.location.search), children: /* @__PURE__ */ jsx(MfaContent, {}) });
}
function MfaContent() {
  const navigate = useNavigate();
  const {
    config,
    tenantId,
    redirectUrl
  } = useHostedConfig();
  const prefersReducedMotion = useReducedMotion();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [code, setCode] = useState("");
  const [method, setMethod] = useState("totp");
  const [resendTimer, setResendTimer] = useState(30);
  const [canResend, setCanResend] = useState(false);
  const urlParams = new URLSearchParams(window.location.search);
  const mfaToken = urlParams.get("mfa_token");
  useEffect(() => {
    if (resendTimer > 0 && !canResend) {
      const timer = setTimeout(() => setResendTimer(resendTimer - 1), 1e3);
      return () => clearTimeout(timer);
    } else if (resendTimer === 0) {
      setCanResend(true);
    }
  }, [resendTimer, canResend]);
  if (!config || !tenantId) {
    return null;
  }
  if (!mfaToken) {
    navigate({
      to: "/hosted/sign-in",
      search: {
        tenant_id: tenantId,
        redirect_url: redirectUrl || void 0
      }
    });
    return null;
  }
  const handleVerify = async () => {
    if (code.length !== 6) {
      setError("Please enter a 6-digit code");
      return;
    }
    setError("Hosted MFA challenge continuation is not available in this build. Return to sign-in and enter MFA code there.");
  };
  const handleResend = async () => {
    if (!canResend) return;
    setIsLoading(true);
    setError(null);
    try {
      setError("Code resend is not available in this build. Return to sign-in to request a new challenge.");
      setResendTimer(30);
      setCanResend(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to resend code");
    } finally {
      setIsLoading(false);
    }
  };
  return /* @__PURE__ */ jsxs(Card, { className: "shadow-elevated", children: [
    /* @__PURE__ */ jsxs(CardHeader, { className: "space-y-1", children: [
      /* @__PURE__ */ jsx("div", { className: "mx-auto w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mb-2", children: /* @__PURE__ */ jsx(Lock, { className: "h-6 w-6 text-primary" }) }),
      /* @__PURE__ */ jsx(CardTitle, { className: "text-2xl text-center", children: "Two-Factor Authentication" }),
      /* @__PURE__ */ jsx(CardDescription, { className: "text-center", children: "Choose a verification method to continue" })
    ] }),
    /* @__PURE__ */ jsxs(CardContent, { className: "space-y-4", children: [
      error && /* @__PURE__ */ jsxs(Alert, { variant: "destructive", children: [
        /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4" }),
        /* @__PURE__ */ jsx(AlertDescription, { children: error })
      ] }),
      /* @__PURE__ */ jsxs(Tabs, { value: method, onValueChange: (v) => setMethod(v), children: [
        /* @__PURE__ */ jsxs(TabsList, { className: "grid w-full grid-cols-3", children: [
          /* @__PURE__ */ jsxs(TabsTrigger, { value: "totp", className: "gap-2", children: [
            /* @__PURE__ */ jsx(Shield, { className: "h-4 w-4" }),
            /* @__PURE__ */ jsx("span", { className: "hidden sm:inline", children: "App" })
          ] }),
          /* @__PURE__ */ jsxs(TabsTrigger, { value: "email", className: "gap-2", children: [
            /* @__PURE__ */ jsx(Mail, { className: "h-4 w-4" }),
            /* @__PURE__ */ jsx("span", { className: "hidden sm:inline", children: "Email" })
          ] }),
          /* @__PURE__ */ jsxs(TabsTrigger, { value: "sms", className: "gap-2", children: [
            /* @__PURE__ */ jsx(Smartphone, { className: "h-4 w-4" }),
            /* @__PURE__ */ jsx("span", { className: "hidden sm:inline", children: "SMS" })
          ] })
        ] }),
        Object.keys(methodConfig).map((m) => {
          const Icon = methodConfig[m].icon;
          return /* @__PURE__ */ jsx(TabsContent, { value: m, className: "mt-4 space-y-4", children: /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
            opacity: 0,
            y: 10
          }, animate: {
            opacity: 1,
            y: 0
          }, className: "space-y-4", children: [
            /* @__PURE__ */ jsxs("div", { className: "text-center", children: [
              /* @__PURE__ */ jsx("div", { className: "w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-3", children: /* @__PURE__ */ jsx(Icon, { className: "h-6 w-6 text-primary" }) }),
              /* @__PURE__ */ jsx("h3", { className: "font-semibold", children: methodConfig[m].title }),
              /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: methodConfig[m].description })
            ] }),
            /* @__PURE__ */ jsx("div", { className: "space-y-2", children: /* @__PURE__ */ jsx(Input, { type: "text", placeholder: "000000", value: code, onChange: (e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6)), className: "text-center text-2xl tracking-widest font-mono", maxLength: 6, inputMode: "numeric", autoComplete: "one-time-code", autoFocus: true, disabled: isLoading, onKeyDown: (e) => {
              if (e.key === "Enter" && code.length === 6) {
                void handleVerify();
              }
            } }) }),
            /* @__PURE__ */ jsx(Button, { fullWidth: true, size: "lg", isLoading, disabled: code.length !== 6, onClick: handleVerify, rightIcon: /* @__PURE__ */ jsx(ArrowRight, { className: "h-4 w-4" }), children: "Verify" }),
            methodConfig[m].showResend && /* @__PURE__ */ jsx("div", { className: "text-center", children: /* @__PURE__ */ jsx("button", { type: "button", onClick: handleResend, disabled: !canResend || isLoading, className: "text-sm text-primary hover:underline disabled:text-muted-foreground disabled:no-underline disabled:cursor-not-allowed", children: canResend ? "Resend code" : `Resend code in ${resendTimer}s` }) })
          ] }) }, m);
        })
      ] }),
      /* @__PURE__ */ jsx("div", { className: "text-center pt-4 border-t", children: /* @__PURE__ */ jsxs(Link, { to: "/hosted/sign-in", search: {
        tenant_id: tenantId,
        redirect_url: redirectUrl || void 0
      }, className: "inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors", children: [
        /* @__PURE__ */ jsx(ArrowLeft, { className: "h-4 w-4" }),
        "Use a different sign-in method"
      ] }) })
    ] })
  ] });
}
export {
  HostedMfaPage as component
};
