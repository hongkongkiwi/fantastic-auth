import { jsx, jsxs } from "react/jsx-runtime";
import { useNavigate, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { Loader2, CheckCircle, ArrowRight, XCircle, Mail } from "lucide-react";
import { B as Button } from "./router-BDwxh4pl.js";
import { C as Card, d as CardContent } from "./Card-Brxgy2gk.js";
import { A as Alert, a as AlertDescription } from "./Alert-BGdSf0_L.js";
import { u as useHostedSearchParams, H as HostedLayout, a as useHostedConfig, h as hostedVerifyEmail } from "./HostedLayout-Dne6B-Jo.js";
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
function HostedVerifyEmailPage() {
  const searchParams = useHostedSearchParams();
  return /* @__PURE__ */ jsx(HostedLayout, { searchParams: new URLSearchParams(window.location.search), children: /* @__PURE__ */ jsx(VerifyEmailContent, { searchParams }) });
}
function VerifyEmailContent({
  searchParams
}) {
  const navigate = useNavigate();
  const {
    config,
    tenantId
  } = useHostedConfig();
  const prefersReducedMotion = useReducedMotion();
  const [state, setState] = useState("loading");
  const [error, setError] = useState(null);
  const token = new URLSearchParams(window.location.search).get("token");
  useEffect(() => {
    if (!tenantId || !token) {
      setState("error");
      setError(!token ? "Missing verification token" : "Missing tenant ID");
      return;
    }
    const verifyEmail = async () => {
      try {
        const result = await hostedVerifyEmail({
          data: {
            token,
            tenantId
          }
        });
        if (result.success) {
          setState("success");
        } else {
          setState("error");
          setError("Verification failed");
        }
      } catch (err) {
        setState("error");
        setError(err instanceof Error ? err.message : "Invalid or expired verification link");
      }
    };
    void verifyEmail();
  }, [tenantId, token]);
  if (!config || !tenantId) {
    return null;
  }
  const handleContinue = () => {
    const redirectUrl = config.afterSignInUrl || "/hosted/sign-in";
    navigate({
      to: redirectUrl,
      search: {
        tenant_id: tenantId
      }
    });
  };
  return /* @__PURE__ */ jsx(Card, { className: "shadow-elevated", children: /* @__PURE__ */ jsxs(CardContent, { className: "pt-6", children: [
    state === "loading" && /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
      opacity: 0
    }, animate: {
      opacity: 1
    }, className: "text-center space-y-6 py-12", children: [
      /* @__PURE__ */ jsx("div", { className: "w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center mx-auto", children: /* @__PURE__ */ jsx(Loader2, { className: "w-8 h-8 text-primary animate-spin" }) }),
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsx("h3", { className: "text-xl font-semibold", children: "Verifying your email..." }),
        /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground mt-2", children: "Please wait while we verify your email address" })
      ] })
    ] }),
    state === "success" && /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
      opacity: 0,
      scale: 0.95
    }, animate: {
      opacity: 1,
      scale: 1
    }, className: "text-center space-y-6 py-8", children: [
      /* @__PURE__ */ jsx("div", { className: "w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto", children: /* @__PURE__ */ jsx(CheckCircle, { className: "w-8 h-8 text-green-600 dark:text-green-400" }) }),
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsx("h3", { className: "text-xl font-semibold", children: "Email verified!" }),
        /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground mt-2", children: "Your email has been successfully verified. You can now sign in to your account." })
      ] }),
      /* @__PURE__ */ jsx(Button, { onClick: handleContinue, fullWidth: true, rightIcon: /* @__PURE__ */ jsx(ArrowRight, { className: "h-4 w-4" }), children: "Continue to Sign In" })
    ] }),
    state === "error" && /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
      opacity: 0,
      scale: 0.95
    }, animate: {
      opacity: 1,
      scale: 1
    }, className: "text-center space-y-6 py-8", children: [
      /* @__PURE__ */ jsx("div", { className: "w-16 h-16 bg-destructive/10 rounded-full flex items-center justify-center mx-auto", children: /* @__PURE__ */ jsx(XCircle, { className: "w-8 h-8 text-destructive" }) }),
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsx("h3", { className: "text-xl font-semibold", children: "Verification failed" }),
        /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground mt-2", children: error || "The verification link is invalid or has expired." })
      ] }),
      /* @__PURE__ */ jsxs(Alert, { children: [
        /* @__PURE__ */ jsx(Mail, { className: "h-4 w-4" }),
        /* @__PURE__ */ jsx(AlertDescription, { children: "Please request a new verification email or contact support if the problem persists." })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "space-y-3", children: [
        /* @__PURE__ */ jsx(Link, { to: "/hosted/sign-in", search: {
          tenant_id: tenantId
        }, className: "block", children: /* @__PURE__ */ jsx(Button, { fullWidth: true, children: "Go to Sign In" }) }),
        config.allowSignUp && /* @__PURE__ */ jsx(Link, { to: "/hosted/sign-up", search: {
          tenant_id: tenantId
        }, className: "block", children: /* @__PURE__ */ jsx(Button, { variant: "outline", fullWidth: true, children: "Create New Account" }) })
      ] })
    ] })
  ] }) });
}
export {
  HostedVerifyEmailPage as component
};
