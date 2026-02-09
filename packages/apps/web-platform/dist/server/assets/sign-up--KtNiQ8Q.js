import { jsx, jsxs } from "react/jsx-runtime";
import { useNavigate, Link } from "@tanstack/react-router";
import { useState } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { CheckCircle, AlertCircle, User, Mail, EyeOff, Eye, Lock, ArrowRight } from "lucide-react";
import { B as Button, b as Alert, f as AlertDescription, s as Checkbox } from "./router-BqFKwE1w.js";
import { I as Input } from "./Input-D8nMsmC2.js";
import { C as Card, d as CardContent, a as CardHeader, b as CardTitle, c as CardDescription } from "./Card-DiqECnNB.js";
import { useForm } from "@tanstack/react-form";
import { H as HostedLayout, u as useHostedConfig, a as hostedSignUp, b as hostedOAuthStart } from "./HostedLayout-BdDuyvHy.js";
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
function HostedSignUpPage() {
  return /* @__PURE__ */ jsx(HostedLayout, { searchParams: new URLSearchParams(window.location.search), children: /* @__PURE__ */ jsx(SignUpContent, {}) });
}
function SignUpContent() {
  const navigate = useNavigate();
  const {
    config,
    tenantId,
    redirectUrl
  } = useHostedConfig();
  const prefersReducedMotion = useReducedMotion();
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [oauthLoading, setOauthLoading] = useState(null);
  const [isSuccess, setIsSuccess] = useState(false);
  const form = useForm({
    defaultValues: {
      name: "",
      email: "",
      password: "",
      agreeToTerms: false
    },
    onSubmit: async ({
      value
    }) => {
      if (!tenantId) return;
      setIsLoading(true);
      setError(null);
      try {
        const result = await hostedSignUp({
          data: {
            name: value.name,
            email: value.email,
            password: value.password,
            tenantId,
            redirectUrl: redirectUrl || void 0
          }
        });
        if (config?.requireEmailVerification) {
          sessionStorage.removeItem("hosted_session_token");
          setIsSuccess(true);
        } else {
          if (result.sessionToken) {
            sessionStorage.setItem("hosted_session_token", result.sessionToken);
          }
          window.location.href = result.redirectUrl;
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Sign up failed");
      } finally {
        setIsLoading(false);
      }
    }
  });
  const handleOAuthSignUp = async (provider) => {
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
  if (!config || !tenantId) {
    return null;
  }
  if (!config.allowSignUp) {
    navigate({
      to: "/hosted/sign-in",
      search: {
        tenant_id: tenantId,
        redirect_url: redirectUrl || void 0
      }
    });
    return null;
  }
  const availableOAuthProviders = config.oauthProviders.filter((p) => ["google", "github", "apple", "slack", "discord"].includes(p));
  if (isSuccess) {
    return /* @__PURE__ */ jsx(Card, { className: "shadow-elevated", children: /* @__PURE__ */ jsx(CardContent, { className: "pt-6", children: /* @__PURE__ */ jsxs("div", { className: "text-center space-y-4 py-8", children: [
      /* @__PURE__ */ jsx("div", { className: "w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto", children: /* @__PURE__ */ jsx(CheckCircle, { className: "w-8 h-8 text-green-600 dark:text-green-400" }) }),
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsx("h3", { className: "text-xl font-semibold", children: "Verify your email" }),
        /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground mt-2", children: [
          "We've sent a verification link to ",
          /* @__PURE__ */ jsx("strong", { children: form.getFieldValue("email") })
        ] }),
        /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground mt-2", children: "Click the link in your email to complete your registration." })
      ] }),
      /* @__PURE__ */ jsx(Button, { variant: "outline", fullWidth: true, onClick: () => navigate({
        to: "/hosted/sign-in",
        search: {
          tenant_id: tenantId
        }
      }), children: "Back to Sign In" })
    ] }) }) });
  }
  return /* @__PURE__ */ jsxs(Card, { className: "shadow-elevated", children: [
    /* @__PURE__ */ jsxs(CardHeader, { className: "space-y-1", children: [
      /* @__PURE__ */ jsx(CardTitle, { className: "text-2xl text-center", children: config.signUpTitle || `Create your ${config.companyName} account` }),
      /* @__PURE__ */ jsx(CardDescription, { className: "text-center", children: "Enter your details to get started" })
    ] }),
    /* @__PURE__ */ jsxs(CardContent, { className: "space-y-4", children: [
      error && /* @__PURE__ */ jsxs(Alert, { variant: "destructive", children: [
        /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4" }),
        /* @__PURE__ */ jsx(AlertDescription, { children: error })
      ] }),
      availableOAuthProviders.length > 0 && /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
        opacity: 0
      }, animate: {
        opacity: 1
      }, transition: prefersReducedMotion ? {
        duration: 0
      } : {
        delay: 0.1
      }, children: /* @__PURE__ */ jsx(SocialLoginButtons, { onGoogleClick: availableOAuthProviders.includes("google") ? () => handleOAuthSignUp("google") : void 0, onGitHubClick: availableOAuthProviders.includes("github") ? () => handleOAuthSignUp("github") : void 0, onAppleClick: availableOAuthProviders.includes("apple") ? () => handleOAuthSignUp("apple") : void 0, onSlackClick: availableOAuthProviders.includes("slack") ? () => handleOAuthSignUp("slack") : void 0, onDiscordClick: availableOAuthProviders.includes("discord") ? () => handleOAuthSignUp("discord") : void 0, isLoading: !!oauthLoading }) }),
      /* @__PURE__ */ jsxs("form", { onSubmit: (e) => {
        e.preventDefault();
        e.stopPropagation();
        void form.handleSubmit();
      }, className: "space-y-4", children: [
        /* @__PURE__ */ jsx(form.Field, { name: "name", validators: {
          onChange: ({
            value
          }) => {
            if (!value.trim()) return "Name is required";
            if (value.trim().length < 2) return "Name must be at least 2 characters";
            return void 0;
          }
        }, children: (field) => /* @__PURE__ */ jsx(Input, { label: "Full Name", type: "text", placeholder: "John Doe", value: field.state.value, onChange: (e) => field.handleChange(e.target.value), onBlur: field.handleBlur, error: field.state.meta.isTouched ? field.state.meta.errors[0] : void 0, leftIcon: /* @__PURE__ */ jsx(User, { className: "h-4 w-4 text-muted-foreground" }), autoComplete: "name", required: true, disabled: isLoading }) }),
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
        /* @__PURE__ */ jsx(form.Field, { name: "password", validators: {
          onChange: ({
            value
          }) => {
            if (!value) return "Password is required";
            if (value.length < 8) return "Password must be at least 8 characters";
            if (!/[A-Z]/.test(value)) return "Password must contain an uppercase letter";
            if (!/[a-z]/.test(value)) return "Password must contain a lowercase letter";
            if (!/[0-9]/.test(value)) return "Password must contain a number";
            return void 0;
          }
        }, children: (field) => /* @__PURE__ */ jsx(Input, { label: "Password", type: showPassword ? "text" : "password", placeholder: "••••••••", value: field.state.value, onChange: (e) => field.handleChange(e.target.value), onBlur: field.handleBlur, error: field.state.meta.isTouched ? field.state.meta.errors[0] : void 0, leftIcon: /* @__PURE__ */ jsx(Lock, { className: "h-4 w-4 text-muted-foreground" }), autoComplete: "new-password", rightIcon: /* @__PURE__ */ jsx("button", { type: "button", onClick: () => setShowPassword(!showPassword), className: "text-muted-foreground hover:text-foreground transition-colors", "aria-label": showPassword ? "Hide password" : "Show password", children: showPassword ? /* @__PURE__ */ jsx(EyeOff, { className: "h-4 w-4" }) : /* @__PURE__ */ jsx(Eye, { className: "h-4 w-4" }) }), required: true, disabled: isLoading }) }),
        (config.termsUrl || config.privacyUrl) && /* @__PURE__ */ jsx(form.Field, { name: "agreeToTerms", validators: {
          onChange: ({
            value
          }) => {
            if (!value) return "You must agree to continue";
            return void 0;
          }
        }, children: (field) => /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
          /* @__PURE__ */ jsxs("div", { className: "flex items-start gap-2", children: [
            /* @__PURE__ */ jsx(Checkbox, { id: "agreeToTerms", checked: field.state.value, onCheckedChange: (checked) => field.handleChange(checked), disabled: isLoading }),
            /* @__PURE__ */ jsxs("label", { htmlFor: "agreeToTerms", className: "text-sm text-muted-foreground leading-relaxed cursor-pointer", children: [
              "I agree to the",
              " ",
              config.termsUrl ? /* @__PURE__ */ jsx("a", { href: config.termsUrl, target: "_blank", rel: "noopener noreferrer", className: "text-primary hover:underline", onClick: (e) => e.stopPropagation(), children: "Terms of Service" }) : "Terms of Service",
              config.termsUrl && config.privacyUrl && " and ",
              config.privacyUrl ? /* @__PURE__ */ jsx("a", { href: config.privacyUrl, target: "_blank", rel: "noopener noreferrer", className: "text-primary hover:underline", onClick: (e) => e.stopPropagation(), children: "Privacy Policy" }) : config.termsUrl ? "Privacy Policy" : null
            ] })
          ] }),
          field.state.meta.isTouched && field.state.meta.errors[0] && /* @__PURE__ */ jsx("p", { className: "text-sm text-destructive", children: field.state.meta.errors[0] })
        ] }) }),
        /* @__PURE__ */ jsx(Button, { type: "submit", fullWidth: true, size: "lg", isLoading, rightIcon: /* @__PURE__ */ jsx(ArrowRight, { className: "h-4 w-4" }), children: "Create Account" })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "text-center text-sm pt-4 border-t", children: [
        /* @__PURE__ */ jsxs("span", { className: "text-muted-foreground", children: [
          "Already have an account?",
          " "
        ] }),
        /* @__PURE__ */ jsx(Link, { to: "/hosted/sign-in", search: {
          tenant_id: tenantId,
          redirect_url: redirectUrl || void 0
        }, className: "text-primary hover:underline", children: "Sign in" })
      ] })
    ] })
  ] });
}
export {
  HostedSignUpPage as component
};
