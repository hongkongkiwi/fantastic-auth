import { jsxs, jsx } from "react/jsx-runtime";
import { useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { CheckCircle, Mail, ArrowRight, Shield, Lock, Zap, EyeOff, Eye } from "lucide-react";
import { B as Button, u as useAuth, A as AuthMfaRequiredError, e as env } from "./router-BqFKwE1w.js";
import { I as Input } from "./Input-D8nMsmC2.js";
import { C as Card, a as CardHeader, b as CardTitle, c as CardDescription, d as CardContent } from "./Card-DiqECnNB.js";
import { T as Tabs, a as TabsList, b as TabsTrigger, c as TabsContent } from "./Tabs-Dlqc7sYx.js";
import { useForm } from "@tanstack/react-form";
import { S as SocialLoginButtons } from "./SocialLoginButtons-CWQt5HeN.js";
import { c as clientLogger } from "./client-logger-DdKNJYmy.js";
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
import "./logger-D87hn870.js";
import "loglayer";
function MagicLinkForm({ onSuccess }) {
  const [isLoading, setIsLoading] = useState(false);
  const [isSent, setIsSent] = useState(false);
  const [error, setError] = useState("");
  const [sentEmail, setSentEmail] = useState("");
  const form = useForm({
    defaultValues: {
      email: ""
    },
    onSubmit: async ({ value }) => {
      setError("");
      setIsLoading(true);
      try {
        const response = await fetch("/api/v1/auth/magic-link", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: value.email })
        });
        if (!response.ok) {
          const data = await response.json();
          throw new Error(data.error?.message || "Failed to send magic link");
        }
        setSentEmail(value.email);
        setIsSent(true);
        onSuccess?.();
      } catch (err) {
        setError(err instanceof Error ? err.message : "An error occurred");
      } finally {
        setIsLoading(false);
      }
    }
  });
  if (isSent) {
    return /* @__PURE__ */ jsxs(
      motion.div,
      {
        initial: { opacity: 0, scale: 0.95 },
        animate: { opacity: 1, scale: 1 },
        className: "text-center space-y-4 py-8",
        children: [
          /* @__PURE__ */ jsx("div", { className: "w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto", children: /* @__PURE__ */ jsx(CheckCircle, { className: "w-8 h-8 text-green-600 dark:text-green-400" }) }),
          /* @__PURE__ */ jsxs("div", { children: [
            /* @__PURE__ */ jsx("h3", { className: "text-lg font-semibold", children: "Check your email" }),
            /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground mt-1", children: [
              "We've sent a magic link to ",
              /* @__PURE__ */ jsx("strong", { children: sentEmail })
            ] }),
            /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground mt-2", children: "Link expires in 15 minutes" })
          ] }),
          /* @__PURE__ */ jsx(
            Button,
            {
              variant: "ghost",
              size: "sm",
              onClick: () => {
                setIsSent(false);
                setSentEmail("");
                form.reset();
              },
              children: "Use a different email"
            }
          )
        ]
      }
    );
  }
  return /* @__PURE__ */ jsxs(
    "form",
    {
      onSubmit: (event) => {
        event.preventDefault();
        event.stopPropagation();
        void form.handleSubmit();
      },
      className: "space-y-4",
      children: [
        /* @__PURE__ */ jsx("div", { className: "space-y-2", children: /* @__PURE__ */ jsx(
          form.Field,
          {
            name: "email",
            validators: {
              onChange: ({ value }) => {
                if (!value.trim()) return "Email is required";
                if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
                  return "Please enter a valid email";
                }
                return void 0;
              }
            },
            children: (field) => /* @__PURE__ */ jsx(
              Input,
              {
                label: "Email",
                type: "email",
                placeholder: "you@example.com",
                value: field.state.value,
                onChange: (e) => field.handleChange(e.target.value),
                onBlur: field.handleBlur,
                leftIcon: /* @__PURE__ */ jsx(Mail, { className: "h-4 w-4 text-muted-foreground" }),
                name: "email",
                autoComplete: "email",
                autoCapitalize: "none",
                spellCheck: false,
                required: true,
                disabled: isLoading,
                error: error || (field.state.meta.isTouched ? field.state.meta.errors[0] : void 0)
              }
            )
          }
        ) }),
        /* @__PURE__ */ jsx(
          Button,
          {
            type: "submit",
            fullWidth: true,
            isLoading,
            rightIcon: /* @__PURE__ */ jsx(ArrowRight, { className: "h-4 w-4" }),
            children: isLoading ? "Sending…" : "Send Magic Link"
          }
        ),
        /* @__PURE__ */ jsx("p", { className: "text-xs text-center text-muted-foreground", children: "You'll receive an email with a secure link to sign in instantly" })
      ]
    }
  );
}
function LoginPage() {
  const navigate = useNavigate();
  const {
    login,
    isAuthenticated
  } = useAuth();
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [loginMethod, setLoginMethod] = useState("password");
  const [oauthLoading, setOauthLoading] = useState(null);
  const [requiresMfaStep, setRequiresMfaStep] = useState(false);
  const [mfaToken, setMfaToken] = useState(void 0);
  const prefersReducedMotion = useReducedMotion();
  const form = useForm({
    defaultValues: {
      email: "",
      password: "",
      mfaCode: ""
    },
    onSubmit: async ({
      value
    }) => {
      setIsLoading(true);
      try {
        await login(value.email, value.password, requiresMfaStep ? value.mfaCode || void 0 : void 0, mfaToken);
      } catch (error) {
        if (error instanceof AuthMfaRequiredError) {
          setRequiresMfaStep(true);
          setMfaToken(error.mfaToken);
          return;
        }
        throw error;
      } finally {
        setIsLoading(false);
      }
    }
  });
  if (isAuthenticated) {
    navigate({
      to: "/"
    });
    return null;
  }
  const handleOAuthLogin = async (provider) => {
    setOauthLoading(provider);
    try {
      const response = await fetch(`/api/v1/auth/oauth/${provider}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          redirectUri: window.location.origin + "/oauth/callback"
        })
      });
      if (!response.ok) throw new Error("Failed to initiate OAuth");
      const {
        authUrl
      } = await response.json();
      window.location.href = authUrl;
    } catch (error) {
      clientLogger.error("OAuth error", error);
    } finally {
      setOauthLoading(null);
    }
  };
  return /* @__PURE__ */ jsxs("div", { className: "min-h-screen flex items-center justify-center p-4 bg-gradient-to-br from-background via-background to-muted", children: [
    /* @__PURE__ */ jsxs("div", { className: "fixed inset-0 overflow-hidden pointer-events-none", children: [
      /* @__PURE__ */ jsx("div", { className: "absolute -top-1/2 -right-1/2 w-full h-full bg-primary/5 rounded-full blur-3xl" }),
      /* @__PURE__ */ jsx("div", { className: "absolute -bottom-1/2 -left-1/2 w-full h-full bg-secondary/5 rounded-full blur-3xl" })
    ] }),
    /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
      opacity: 0,
      y: 20
    }, animate: {
      opacity: 1,
      y: 0
    }, transition: prefersReducedMotion ? {
      duration: 0
    } : {
      duration: 0.5
    }, className: "w-full max-w-md relative z-10", children: [
      /* @__PURE__ */ jsx("div", { className: "flex justify-center mb-8", children: /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
        scale: 0.8
      }, animate: {
        scale: 1
      }, transition: prefersReducedMotion ? {
        duration: 0
      } : {
        delay: 0.2,
        type: "spring"
      }, className: "flex items-center gap-3", children: [
        /* @__PURE__ */ jsx("div", { className: "h-12 w-12 rounded-xl bg-primary flex items-center justify-center shadow-glow", children: /* @__PURE__ */ jsx(Shield, { className: "h-7 w-7 text-primary-foreground" }) }),
        /* @__PURE__ */ jsxs("div", { children: [
          /* @__PURE__ */ jsx("h1", { className: "text-2xl font-bold", children: "Vault" }),
          /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Admin Console" })
        ] })
      ] }) }),
      /* @__PURE__ */ jsxs(Card, { className: "shadow-elevated", children: [
        /* @__PURE__ */ jsxs(CardHeader, { className: "space-y-1", children: [
          /* @__PURE__ */ jsx(CardTitle, { className: "text-2xl text-center", children: "Welcome back" }),
          /* @__PURE__ */ jsx(CardDescription, { className: "text-center", children: "Sign in to access your admin panel" })
        ] }),
        /* @__PURE__ */ jsx(CardContent, { children: /* @__PURE__ */ jsxs(Tabs, { value: loginMethod, onValueChange: (v) => setLoginMethod(v), className: "mb-6", children: [
          /* @__PURE__ */ jsxs(TabsList, { className: "grid w-full grid-cols-2", children: [
            /* @__PURE__ */ jsxs(TabsTrigger, { value: "password", className: "gap-2", children: [
              /* @__PURE__ */ jsx(Lock, { className: "h-4 w-4" }),
              "Password"
            ] }),
            /* @__PURE__ */ jsxs(TabsTrigger, { value: "magic-link", className: "gap-2", children: [
              /* @__PURE__ */ jsx(Zap, { className: "h-4 w-4" }),
              "Magic Link"
            ] })
          ] }),
          /* @__PURE__ */ jsxs(TabsContent, { value: "password", className: "mt-4", children: [
            /* @__PURE__ */ jsxs("form", { onSubmit: (event) => {
              event.preventDefault();
              event.stopPropagation();
              void form.handleSubmit();
            }, className: "space-y-4", children: [
              /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
                opacity: 0,
                x: -20
              }, animate: {
                opacity: 1,
                x: 0
              }, transition: prefersReducedMotion ? {
                duration: 0
              } : {
                delay: 0.3
              }, children: /* @__PURE__ */ jsx(form.Field, { name: "email", validators: {
                onChange: ({
                  value
                }) => {
                  if (!value.trim()) return "Email is required";
                  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
                    return "Please enter a valid email";
                  }
                  return void 0;
                }
              }, children: (field) => /* @__PURE__ */ jsx(Input, { label: "Email", type: "email", placeholder: "admin@vault.local", value: field.state.value, onChange: (e) => field.handleChange(e.target.value), onBlur: field.handleBlur, error: field.state.meta.isTouched ? field.state.meta.errors[0] : void 0, leftIcon: /* @__PURE__ */ jsx(Mail, { className: "h-4 w-4 text-muted-foreground" }), autoComplete: "email", autoCapitalize: "none", spellCheck: false, required: true }) }) }),
              /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
                opacity: 0,
                x: -20
              }, animate: {
                opacity: 1,
                x: 0
              }, transition: prefersReducedMotion ? {
                duration: 0
              } : {
                delay: 0.4
              }, children: /* @__PURE__ */ jsx("div", { className: "relative", children: /* @__PURE__ */ jsx(form.Field, { name: "password", validators: {
                onChange: ({
                  value
                }) => {
                  if (loginMethod === "password" && !value) {
                    return "Password is required";
                  }
                  return void 0;
                }
              }, children: (field) => /* @__PURE__ */ jsx(Input, { label: "Password", type: showPassword ? "text" : "password", placeholder: "••••••••", value: field.state.value, onChange: (e) => field.handleChange(e.target.value), onBlur: field.handleBlur, error: field.state.meta.isTouched ? field.state.meta.errors[0] : void 0, leftIcon: /* @__PURE__ */ jsx(Lock, { className: "h-4 w-4 text-muted-foreground" }), autoComplete: "current-password", rightIcon: /* @__PURE__ */ jsx("button", { type: "button", onClick: () => setShowPassword(!showPassword), className: "text-muted-foreground hover:text-foreground transition-colors", "aria-label": showPassword ? "Hide password" : "Show password", children: showPassword ? /* @__PURE__ */ jsx(EyeOff, { className: "h-4 w-4" }) : /* @__PURE__ */ jsx(Eye, { className: "h-4 w-4" }) }), required: true }) }) }) }),
              requiresMfaStep && /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Multi-factor authentication is required. Enter your verification code to continue." }),
              requiresMfaStep && /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
                opacity: 0,
                y: 20
              }, animate: {
                opacity: 1,
                y: 0
              }, transition: prefersReducedMotion ? {
                duration: 0
              } : {
                delay: 0.5
              }, children: /* @__PURE__ */ jsx(form.Field, { name: "mfaCode", children: (field) => /* @__PURE__ */ jsx(Input, { label: "2FA Code", type: "text", placeholder: "123456", value: field.state.value, onChange: (e) => field.handleChange(e.target.value), onBlur: field.handleBlur, autoComplete: "one-time-code", inputMode: "numeric", required: requiresMfaStep }) }) }),
              /* @__PURE__ */ jsxs(motion.div, { initial: prefersReducedMotion ? false : {
                opacity: 0,
                y: 20
              }, animate: {
                opacity: 1,
                y: 0
              }, transition: prefersReducedMotion ? {
                duration: 0
              } : {
                delay: 0.55
              }, className: "flex items-center justify-between text-sm", children: [
                /* @__PURE__ */ jsxs("label", { className: "flex items-center gap-2 cursor-pointer", children: [
                  /* @__PURE__ */ jsx("input", { type: "checkbox", className: "rounded border-input" }),
                  /* @__PURE__ */ jsx("span", { className: "text-muted-foreground", children: "Remember me" })
                ] }),
                /* @__PURE__ */ jsx("a", { href: "#", className: "text-primary hover:underline", children: "Forgot password?" })
              ] }),
              /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
                opacity: 0,
                y: 20
              }, animate: {
                opacity: 1,
                y: 0
              }, transition: prefersReducedMotion ? {
                duration: 0
              } : {
                delay: 0.6
              }, children: /* @__PURE__ */ jsx(Button, { type: "submit", fullWidth: true, size: "lg", isLoading, rightIcon: /* @__PURE__ */ jsx(ArrowRight, { className: "h-4 w-4" }), children: "Sign In" }) })
            ] }),
            /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
              opacity: 0
            }, animate: {
              opacity: 1
            }, transition: prefersReducedMotion ? {
              duration: 0
            } : {
              delay: 0.7
            }, className: "mt-6", children: /* @__PURE__ */ jsx(SocialLoginButtons, { onGoogleClick: env.VITE_OAUTH_GOOGLE_ENABLED === "true" ? () => handleOAuthLogin("google") : void 0, onGitHubClick: env.VITE_OAUTH_GITHUB_ENABLED === "true" ? () => handleOAuthLogin("github") : void 0, onMicrosoftClick: env.VITE_OAUTH_MICROSOFT_ENABLED === "true" ? () => handleOAuthLogin("microsoft") : void 0, onAppleClick: env.VITE_OAUTH_APPLE_ENABLED === "true" ? () => handleOAuthLogin("apple") : void 0, isLoading: !!oauthLoading }) })
          ] }),
          /* @__PURE__ */ jsx(TabsContent, { value: "magic-link", className: "mt-4", children: /* @__PURE__ */ jsx(MagicLinkForm, {}) })
        ] }) })
      ] }),
      /* @__PURE__ */ jsx(motion.p, { initial: prefersReducedMotion ? false : {
        opacity: 0
      }, animate: {
        opacity: 1
      }, transition: prefersReducedMotion ? {
        duration: 0
      } : {
        delay: 0.9
      }, className: "text-center text-sm text-muted-foreground mt-6", children: "Protected by industry-standard encryption" })
    ] })
  ] });
}
export {
  LoginPage as component
};
