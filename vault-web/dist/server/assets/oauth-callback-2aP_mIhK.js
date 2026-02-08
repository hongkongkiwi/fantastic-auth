import { jsx, jsxs, Fragment } from "react/jsx-runtime";
import { useNavigate, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { Loader2, CheckCircle, ArrowRight, XCircle } from "lucide-react";
import { B as Button } from "./router-BDwxh4pl.js";
import { C as Card, a as CardHeader, b as CardTitle, c as CardDescription, d as CardContent } from "./Card-Brxgy2gk.js";
import { u as useHostedSearchParams, H as HostedLayout, a as useHostedConfig, f as hostedOAuthCallback } from "./HostedLayout-Dne6B-Jo.js";
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
import "./Alert-BGdSf0_L.js";
function HostedOAuthCallbackPage() {
  const searchParams = useHostedSearchParams();
  return /* @__PURE__ */ jsx(HostedLayout, { searchParams: new URLSearchParams(window.location.search), children: /* @__PURE__ */ jsx(OAuthCallbackContent, { searchParams }) });
}
function OAuthCallbackContent({
  searchParams
}) {
  const navigate = useNavigate();
  const {
    config,
    tenantId,
    redirectUrl
  } = useHostedConfig();
  const prefersReducedMotion = useReducedMotion();
  const [state, setState] = useState("processing");
  const [error, setError] = useState(null);
  const [requiresMfa, setRequiresMfa] = useState(false);
  const [mfaToken, setMfaToken] = useState(null);
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get("code");
    const state2 = urlParams.get("state");
    const errorParam = urlParams.get("error");
    const errorDescription = urlParams.get("error_description");
    if (errorParam) {
      setState("error");
      setError(errorDescription || `OAuth error: ${errorParam}`);
      return;
    }
    if (!tenantId) {
      setState("error");
      setError("Missing tenant_id parameter");
      return;
    }
    if (!code || !state2) {
      setState("error");
      setError("Invalid OAuth callback: missing code or state");
      return;
    }
    const storedState = sessionStorage.getItem("hosted_oauth_state");
    if (storedState && storedState !== state2) {
      setState("error");
      setError("Invalid state parameter. Possible CSRF attack.");
      return;
    }
    sessionStorage.removeItem("hosted_oauth_state");
    const exchangeCode = async () => {
      try {
        const result = await hostedOAuthCallback({
          data: {
            code,
            state: state2,
            tenantId,
            redirectUrl: redirectUrl || void 0
          }
        });
        if (result.requiresMfa && result.mfaToken) {
          setRequiresMfa(true);
          setMfaToken(result.mfaToken);
          setState("success");
          return;
        }
        setState("success");
        setTimeout(() => {
          window.location.href = result.redirectUrl;
        }, 1500);
      } catch (err) {
        setState("error");
        setError(err instanceof Error ? err.message : "OAuth authentication failed");
      }
    };
    void exchangeCode();
  }, [tenantId, redirectUrl]);
  if (!config || !tenantId) {
    return null;
  }
  const handleContinue = () => {
    if (requiresMfa && mfaToken) {
      navigate({
        to: "/hosted/mfa",
        search: {
          tenant_id: tenantId,
          mfa_token: mfaToken,
          redirect_url: redirectUrl || void 0
        }
      });
    } else {
      const targetUrl = redirectUrl || config.afterSignInUrl || "/hosted/sign-in";
      window.location.href = targetUrl;
    }
  };
  return /* @__PURE__ */ jsxs(Card, { className: "shadow-elevated", children: [
    /* @__PURE__ */ jsxs(CardHeader, { className: "space-y-1", children: [
      /* @__PURE__ */ jsxs(CardTitle, { className: "text-2xl text-center", children: [
        state === "processing" && "Completing Sign In...",
        state === "success" && requiresMfa && "Additional Verification Required",
        state === "success" && !requiresMfa && "Sign In Successful!",
        state === "error" && "Sign In Failed"
      ] }),
      /* @__PURE__ */ jsxs(CardDescription, { className: "text-center", children: [
        state === "processing" && "Please wait while we complete the authentication...",
        state === "success" && requiresMfa && "Please verify your identity to continue.",
        state === "success" && !requiresMfa && "Redirecting you to your account...",
        state === "error" && "We couldn't complete the sign in process."
      ] })
    ] }),
    /* @__PURE__ */ jsxs(CardContent, { className: "space-y-6", children: [
      state === "processing" && /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
        opacity: 0
      }, animate: {
        opacity: 1
      }, className: "flex flex-col items-center py-8", children: [
        /* @__PURE__ */ jsx("div", { className: "w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center mb-4", children: /* @__PURE__ */ jsx(Loader2, { className: "w-8 h-8 text-primary animate-spin" }) }),
        /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Exchanging authorization code..." })
      ] }),
      state === "success" && /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
        opacity: 0,
        scale: 0.95
      }, animate: {
        opacity: 1,
        scale: 1
      }, className: "text-center space-y-6 py-4", children: [
        /* @__PURE__ */ jsx("div", { className: "w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto", children: /* @__PURE__ */ jsx(CheckCircle, { className: "w-8 h-8 text-green-600 dark:text-green-400" }) }),
        requiresMfa ? /* @__PURE__ */ jsxs(Fragment, { children: [
          /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "For added security, we need to verify your identity with multi-factor authentication." }),
          /* @__PURE__ */ jsx(Button, { onClick: handleContinue, fullWidth: true, rightIcon: /* @__PURE__ */ jsx(ArrowRight, { className: "h-4 w-4" }), children: "Continue to Verification" })
        ] }) : /* @__PURE__ */ jsxs(Fragment, { children: [
          /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "You're being redirected to your account..." }),
          /* @__PURE__ */ jsx("div", { className: "w-full bg-muted rounded-full h-2 overflow-hidden", children: /* @__PURE__ */ jsx(motion.div, { initial: {
            width: "0%"
          }, animate: {
            width: "100%"
          }, transition: {
            duration: 1.5,
            ease: "easeInOut"
          }, className: "h-full bg-primary" }) })
        ] })
      ] }),
      state === "error" && /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
        opacity: 0,
        scale: 0.95
      }, animate: {
        opacity: 1,
        scale: 1
      }, className: "text-center space-y-6 py-4", children: [
        /* @__PURE__ */ jsx("div", { className: "w-16 h-16 bg-destructive/10 rounded-full flex items-center justify-center mx-auto", children: /* @__PURE__ */ jsx(XCircle, { className: "w-8 h-8 text-destructive" }) }),
        /* @__PURE__ */ jsx("div", { className: "bg-destructive/5 border border-destructive/20 rounded-lg p-4", children: /* @__PURE__ */ jsx("p", { className: "text-sm text-destructive", children: error || "An unexpected error occurred" }) }),
        /* @__PURE__ */ jsxs("div", { className: "space-y-3", children: [
          /* @__PURE__ */ jsx(Link, { to: "/hosted/sign-in", search: {
            tenant_id: tenantId,
            redirect_url: redirectUrl || void 0
          }, className: "block", children: /* @__PURE__ */ jsx(Button, { fullWidth: true, children: "Try Again" }) }),
          config.allowSignUp && /* @__PURE__ */ jsx(Link, { to: "/hosted/sign-up", search: {
            tenant_id: tenantId,
            redirect_url: redirectUrl || void 0
          }, className: "block", children: /* @__PURE__ */ jsx(Button, { variant: "outline", fullWidth: true, children: "Create Account" }) })
        ] })
      ] })
    ] })
  ] });
}
export {
  HostedOAuthCallbackPage as component
};
