import { jsx, jsxs } from "react/jsx-runtime";
import { useNavigate, Link } from "@tanstack/react-router";
import { useState } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { AlertCircle, Lock, Zap, Fingerprint, Mail, EyeOff, Eye, ArrowRight } from "lucide-react";
import { b as Alert, f as AlertDescription, B as Button } from "./router-BqFKwE1w.js";
import { I as Input } from "./Input-D8nMsmC2.js";
import { C as Card, a as CardHeader, b as CardTitle, c as CardDescription, d as CardContent } from "./Card-DiqECnNB.js";
import { T as Tabs, a as TabsList, b as TabsTrigger, c as TabsContent } from "./Tabs-Dlqc7sYx.js";
import { useForm } from "@tanstack/react-form";
import { H as HostedLayout, u as useHostedConfig, c as hostedSignIn, d as hostedSendMagicLink, b as hostedOAuthStart } from "./HostedLayout-BdDuyvHy.js";
import { S as SocialLoginButtons } from "./SocialLoginButtons-CWQt5HeN.js";
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
function HostedSignInPage() {
  return /* @__PURE__ */ jsx(HostedLayout, { searchParams: new URLSearchParams(window.location.search), children: /* @__PURE__ */ jsx(SignInContent, {}) });
}
function SignInContent() {
  const navigate = useNavigate();
  const {
    config,
    tenantId,
    redirectUrl,
    error: configError
  } = useHostedConfig();
  const prefersReducedMotion = useReducedMotion();
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [loginMethod, setLoginMethod] = useState("password");
  const [oauthLoading, setOauthLoading] = useState(null);
  const [magicLinkSent, setMagicLinkSent] = useState(false);
  const [requiresMfaStep, setRequiresMfaStep] = useState(false);
  const passwordForm = useForm({
    defaultValues: {
      email: "",
      password: "",
      mfaCode: ""
    },
    onSubmit: async ({
      value
    }) => {
      if (!tenantId) return;
      setIsLoading(true);
      setError(null);
      try {
        const result = await hostedSignIn({
          data: {
            email: value.email,
            password: value.password,
            mfaCode: requiresMfaStep ? value.mfaCode : void 0,
            tenantId,
            redirectUrl: redirectUrl || void 0
          }
        });
        if (result.requiresMfa && result.mfaToken) {
          sessionStorage.removeItem("hosted_session_token");
          navigate({
            to: "/hosted/mfa",
            search: {
              tenant_id: tenantId,
              mfa_token: result.mfaToken,
              redirect_url: redirectUrl || void 0
            }
          });
          return;
        }
        if (result.requiresMfa) {
          sessionStorage.removeItem("hosted_session_token");
          setRequiresMfaStep(true);
          setError("Enter your MFA code to continue");
          return;
        }
        if (result.sessionToken) {
          sessionStorage.setItem("hosted_session_token", result.sessionToken);
        }
        window.location.href = result.redirectUrl;
      } catch (err) {
        setError(err instanceof Error ? err.message : "Sign in failed");
      } finally {
        setIsLoading(false);
      }
    }
  });
  const magicLinkForm = useForm({
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
        await hostedSendMagicLink({
          data: {
            email: value.email,
            tenantId,
            redirectUrl: redirectUrl || void 0
          }
        });
        setMagicLinkSent(true);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to send magic link");
      } finally {
        setIsLoading(false);
      }
    }
  });
  const handleOAuthLogin = async (provider) => {
    if (!tenantId) return;
    setOauthLoading(provider);
    setError(null);
    try {
      const result = await hostedOAuthStart({
        data: {
          provider,
          tenantId,
          redirectUrl: redirectUrl || void 0
        }
      });
      sessionStorage.setItem("hosted_oauth_state", result.state);
      window.location.href = result.authUrl;
    } catch (err) {
      setError(err instanceof Error ? err.message : "OAuth failed");
      setOauthLoading(null);
    }
  };
  const handleWebAuthn = async () => {
    setError("WebAuthn coming soon");
  };
  if (!config || !tenantId) {
    return null;
  }
  const availableOAuthProviders = config.oauthProviders.filter((p) => ["google", "github", "apple", "slack", "discord"].includes(p));
  return /* @__PURE__ */ jsxs(Card, { className: "shadow-elevated", children: [
    /* @__PURE__ */ jsxs(CardHeader, { className: "space-y-1", children: [
      /* @__PURE__ */ jsx(CardTitle, { className: "text-2xl text-center", children: config.signInTitle || `Sign in to ${config.companyName}` }),
      /* @__PURE__ */ jsx(CardDescription, { className: "text-center", children: "Enter your credentials to access your account" })
    ] }),
    /* @__PURE__ */ jsxs(CardContent, { className: "space-y-4", children: [
      error && /* @__PURE__ */ jsxs(Alert, { variant: "destructive", children: [
        /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4" }),
        /* @__PURE__ */ jsx(AlertDescription, { children: error })
      ] }),
      configError && /* @__PURE__ */ jsxs(Alert, { variant: "destructive", children: [
        /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4" }),
        /* @__PURE__ */ jsx(AlertDescription, { children: configError })
      ] }),
      availableOAuthProviders.length > 0 && /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
        opacity: 0
      }, animate: {
        opacity: 1
      }, transition: prefersReducedMotion ? {
        duration: 0
      } : {
        delay: 0.1
      }, children: /* @__PURE__ */ jsx(SocialLoginButtons, { onGoogleClick: availableOAuthProviders.includes("google") ? () => handleOAuthLogin("google") : void 0, onGitHubClick: availableOAuthProviders.includes("github") ? () => handleOAuthLogin("github") : void 0, onAppleClick: availableOAuthProviders.includes("apple") ? () => handleOAuthLogin("apple") : void 0, onSlackClick: availableOAuthProviders.includes("slack") ? () => handleOAuthLogin("slack") : void 0, onDiscordClick: availableOAuthProviders.includes("discord") ? () => handleOAuthLogin("discord") : void 0, isLoading: !!oauthLoading }) }),
      config.showMagicLink || config.showWebAuthn ? /* @__PURE__ */ jsxs(Tabs, { value: loginMethod, onValueChange: (v) => setLoginMethod(v), children: [
        /* @__PURE__ */ jsxs(TabsList, { className: "grid w-full grid-cols-2", children: [
          /* @__PURE__ */ jsxs(TabsTrigger, { value: "password", className: "gap-2", children: [
            /* @__PURE__ */ jsx(Lock, { className: "h-4 w-4" }),
            "Password"
          ] }),
          config.showMagicLink && /* @__PURE__ */ jsxs(TabsTrigger, { value: "magic-link", className: "gap-2", children: [
            /* @__PURE__ */ jsx(Zap, { className: "h-4 w-4" }),
            "Magic Link"
          ] })
        ] }),
        /* @__PURE__ */ jsx(TabsContent, { value: "password", className: "mt-4 space-y-4", children: /* @__PURE__ */ jsx(PasswordForm, { form: passwordForm, showPassword, setShowPassword, isLoading, config, requiresMfaStep }) }),
        config.showMagicLink && /* @__PURE__ */ jsx(TabsContent, { value: "magic-link", className: "mt-4", children: magicLinkSent ? /* @__PURE__ */ jsx(MagicLinkSuccess, { email: magicLinkForm.getFieldValue("email") }) : /* @__PURE__ */ jsx(MagicLinkForm, { form: magicLinkForm, isLoading }) })
      ] }) : /* @__PURE__ */ jsx(PasswordForm, { form: passwordForm, showPassword, setShowPassword, isLoading, config, requiresMfaStep }),
      config.showWebAuthn && /* @__PURE__ */ jsxs(Button, { variant: "outline", fullWidth: true, onClick: handleWebAuthn, disabled: isLoading, className: "gap-2", children: [
        /* @__PURE__ */ jsx(Fingerprint, { className: "h-4 w-4" }),
        "Sign in with Passkey"
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between text-sm pt-4 border-t", children: [
        config.allowSignUp ? /* @__PURE__ */ jsx(Link, { to: "/hosted/sign-up", search: {
          tenant_id: tenantId,
          redirect_url: redirectUrl || void 0
        }, className: "text-primary hover:underline", children: "Create account" }) : /* @__PURE__ */ jsx("span", {}),
        /* @__PURE__ */ jsx(Link, { to: "/hosted/forgot-password", search: {
          tenant_id: tenantId
        }, className: "text-primary hover:underline", children: "Forgot password?" })
      ] })
    ] })
  ] });
}
function PasswordForm({
  form,
  showPassword,
  setShowPassword,
  isLoading,
  config,
  requiresMfaStep
}) {
  return /* @__PURE__ */ jsxs("form", { onSubmit: (e) => {
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
    }, children: (field) => /* @__PURE__ */ jsx(Input, { label: "Email", type: "email", placeholder: `you@${config.companyName.toLowerCase().replace(/\s+/g, "")}.com`, value: field.state.value, onChange: (e) => field.handleChange(e.target.value), onBlur: field.handleBlur, error: field.state.meta.isTouched ? field.state.meta.errors[0] : void 0, leftIcon: /* @__PURE__ */ jsx(Mail, { className: "h-4 w-4 text-muted-foreground" }), autoComplete: "email", autoCapitalize: "none", spellCheck: false, required: true, disabled: isLoading }) }),
    requiresMfaStep && /* @__PURE__ */ jsx(form.Field, { name: "mfaCode", validators: {
      onChange: ({
        value
      }) => {
        if (!value || value.trim().length < 6) return "MFA code is required";
        return void 0;
      }
    }, children: (field) => /* @__PURE__ */ jsx(Input, { label: "MFA Code", type: "text", placeholder: "123456", value: field.state.value, onChange: (e) => field.handleChange(e.target.value.replace(/\D/g, "").slice(0, 8)), onBlur: field.handleBlur, error: field.state.meta.isTouched ? field.state.meta.errors[0] : void 0, leftIcon: /* @__PURE__ */ jsx(Fingerprint, { className: "h-4 w-4 text-muted-foreground" }), inputMode: "numeric", autoComplete: "one-time-code", required: true, disabled: isLoading }) }),
    /* @__PURE__ */ jsx(form.Field, { name: "password", validators: {
      onChange: ({
        value
      }) => {
        if (!value) return "Password is required";
        return void 0;
      }
    }, children: (field) => /* @__PURE__ */ jsx(Input, { label: "Password", type: showPassword ? "text" : "password", placeholder: "••••••••", value: field.state.value, onChange: (e) => field.handleChange(e.target.value), onBlur: field.handleBlur, error: field.state.meta.isTouched ? field.state.meta.errors[0] : void 0, leftIcon: /* @__PURE__ */ jsx(Lock, { className: "h-4 w-4 text-muted-foreground" }), autoComplete: "current-password", rightIcon: /* @__PURE__ */ jsx("button", { type: "button", onClick: () => setShowPassword(!showPassword), className: "text-muted-foreground hover:text-foreground transition-colors", "aria-label": showPassword ? "Hide password" : "Show password", children: showPassword ? /* @__PURE__ */ jsx(EyeOff, { className: "h-4 w-4" }) : /* @__PURE__ */ jsx(Eye, { className: "h-4 w-4" }) }), required: true, disabled: isLoading }) }),
    /* @__PURE__ */ jsx(Button, { type: "submit", fullWidth: true, size: "lg", isLoading, rightIcon: /* @__PURE__ */ jsx(ArrowRight, { className: "h-4 w-4" }), children: requiresMfaStep ? "Verify MFA" : "Sign In" })
  ] });
}
function MagicLinkForm({
  form,
  isLoading
}) {
  return /* @__PURE__ */ jsxs("form", { onSubmit: (e) => {
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
    }, children: (field) => /* @__PURE__ */ jsx(Input, { label: "Email", type: "email", placeholder: "you@example.com", value: field.state.value, onChange: (e) => field.handleChange(e.target.value), onBlur: field.handleBlur, error: field.state.meta.isTouched ? field.state.meta.errors[0] : void 0, leftIcon: /* @__PURE__ */ jsx(Mail, { className: "h-4 w-4 text-muted-foreground" }), autoComplete: "email", required: true, disabled: isLoading }) }),
    /* @__PURE__ */ jsx(Button, { type: "submit", fullWidth: true, isLoading, rightIcon: /* @__PURE__ */ jsx(Zap, { className: "h-4 w-4" }), children: "Send Magic Link" }),
    /* @__PURE__ */ jsx("p", { className: "text-xs text-center text-muted-foreground", children: "You'll receive an email with a secure link to sign in instantly" })
  ] });
}
function MagicLinkSuccess({
  email
}) {
  return /* @__PURE__ */ jsxs("div", { className: "text-center space-y-4 py-8", children: [
    /* @__PURE__ */ jsx("div", { className: "w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto", children: /* @__PURE__ */ jsx(Mail, { className: "w-8 h-8 text-green-600 dark:text-green-400" }) }),
    /* @__PURE__ */ jsxs("div", { children: [
      /* @__PURE__ */ jsx("h3", { className: "text-lg font-semibold", children: "Check your email" }),
      /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground mt-1", children: [
        "We've sent a magic link to ",
        /* @__PURE__ */ jsx("strong", { children: email })
      ] }),
      /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground mt-2", children: "Link expires in 15 minutes" })
    ] })
  ] });
}
export {
  HostedSignInPage as component
};
