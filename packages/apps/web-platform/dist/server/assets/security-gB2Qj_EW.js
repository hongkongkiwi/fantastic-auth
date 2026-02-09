import { jsxs, jsx, Fragment } from "react/jsx-runtime";
import { useState, useEffect, Suspense, lazy } from "react";
import { Shield, Key, Mail, Smartphone, CheckCircle, Trash2, AlertCircle } from "lucide-react";
import { motion } from "framer-motion";
import { P as PageHeader, a as Badge, B as Button, D as Dialog, n as DialogContent, o as DialogHeader, p as DialogTitle, q as DialogDescription } from "./router-BqFKwE1w.js";
import { C as Card } from "./Card-DiqECnNB.js";
import { T as Tabs, a as TabsList, b as TabsTrigger, c as TabsContent } from "./Tabs-Dlqc7sYx.js";
import { a as Skeleton } from "./Skeleton-RwodY-mL.js";
import { I as Input } from "./Input-D8nMsmC2.js";
import { useForm } from "@tanstack/react-form";
import "@tanstack/react-router";
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
const MfaEnroll = lazy(() => import("./MfaEnroll-COFjPnVZ.js").then((mod) => ({
  default: mod.MfaEnroll
})));
const SessionManager = lazy(() => import("./SessionManager-ChR0cMnE.js").then((mod) => ({
  default: mod.SessionManager
})));
function SecuritySettingsPage() {
  const [activeTab, setActiveTab] = useState("mfa");
  const [isEnrollOpen, setIsEnrollOpen] = useState(false);
  const [enrollMethod, setEnrollMethod] = useState("totp");
  const [isUpdatingPassword, setIsUpdatingPassword] = useState(false);
  const [passwordMessage, setPasswordMessage] = useState(null);
  const [passwordError, setPasswordError] = useState(null);
  const [providers, setProviders] = useState(null);
  const [providerStatus, setProviderStatus] = useState(null);
  const [providersError, setProvidersError] = useState(null);
  const passwordForm = useForm({
    defaultValues: {
      currentPassword: "",
      newPassword: "",
      confirmPassword: ""
    },
    onSubmit: async ({
      value
    }) => {
      if (value.newPassword !== value.confirmPassword) {
        setPasswordError("Passwords do not match");
        return;
      }
      setIsUpdatingPassword(true);
      setPasswordError(null);
      setPasswordMessage(null);
      try {
        const response = await fetch("/api/v1/users/me/password", {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          credentials: "include",
          body: JSON.stringify({
            current_password: value.currentPassword,
            new_password: value.newPassword
          })
        });
        if (!response.ok) {
          throw new Error("Failed to update password. Step-up authentication may be required.");
        }
        setPasswordMessage("Password updated successfully");
      } catch (err) {
        setPasswordError(err instanceof Error ? err.message : "Failed to update password");
      } finally {
        setIsUpdatingPassword(false);
      }
    }
  });
  const mfaMethods = [{
    type: "totp",
    name: "Authenticator App",
    enabled: true,
    created_at: "2024-01-15"
  }];
  useEffect(() => {
    let cancelled = false;
    async function loadProviders() {
      try {
        const [providersRes, statusRes] = await Promise.all([fetch("/api/v1/admin/security/data-encryption/providers"), fetch("/api/v1/admin/security/data-encryption")]);
        if (!providersRes.ok || !statusRes.ok) {
          throw new Error("Failed to load providers");
        }
        const providersData = await providersRes.json();
        const statusData = await statusRes.json();
        if (!cancelled) {
          setProviders(providersData);
          setProviderStatus(statusData);
        }
      } catch (err) {
        if (!cancelled) {
          setProvidersError("Unable to load data encryption providers");
        }
      }
    }
    void loadProviders();
    return () => {
      cancelled = true;
    };
  }, []);
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "Security Settings", description: "Manage your account security and authentication methods", breadcrumbs: [{
      label: "Settings",
      href: "/settings"
    }, {
      label: "Security"
    }] }),
    /* @__PURE__ */ jsxs(Tabs, { value: activeTab, onValueChange: setActiveTab, children: [
      /* @__PURE__ */ jsxs(TabsList, { className: "grid w-full grid-cols-3 lg:w-auto", children: [
        /* @__PURE__ */ jsxs(TabsTrigger, { value: "mfa", className: "gap-2", children: [
          /* @__PURE__ */ jsx(Shield, { className: "h-4 w-4" }),
          /* @__PURE__ */ jsx("span", { className: "hidden sm:inline", children: "MFA" })
        ] }),
        /* @__PURE__ */ jsxs(TabsTrigger, { value: "sessions", className: "gap-2", children: [
          /* @__PURE__ */ jsx(Key, { className: "h-4 w-4" }),
          /* @__PURE__ */ jsx("span", { className: "hidden sm:inline", children: "Sessions" })
        ] }),
        /* @__PURE__ */ jsxs(TabsTrigger, { value: "password", className: "gap-2", children: [
          /* @__PURE__ */ jsx(Shield, { className: "h-4 w-4" }),
          /* @__PURE__ */ jsx("span", { className: "hidden sm:inline", children: "Password" })
        ] })
      ] }),
      /* @__PURE__ */ jsxs(TabsContent, { value: "mfa", className: "space-y-6", children: [
        /* @__PURE__ */ jsxs(Card, { className: "p-6", children: [
          /* @__PURE__ */ jsxs("div", { className: "flex items-start justify-between", children: [
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx("h3", { className: "text-lg font-medium", children: "Multi-Factor Authentication" }),
              /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground mt-1", children: "Add an extra layer of security to your account" })
            ] }),
            /* @__PURE__ */ jsx(Badge, { variant: "success", children: "Enabled" })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "mt-6 space-y-3", children: [
            mfaMethods.map((method) => /* @__PURE__ */ jsxs(motion.div, { initial: {
              opacity: 0,
              y: 10
            }, animate: {
              opacity: 1,
              y: 0
            }, className: "flex items-center justify-between p-4 border rounded-lg", children: [
              /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
                /* @__PURE__ */ jsxs("div", { className: "p-2 bg-primary/10 rounded-lg", children: [
                  method.type === "totp" && /* @__PURE__ */ jsx(Shield, { className: "h-5 w-5 text-primary" }),
                  method.type === "email" && /* @__PURE__ */ jsx(Mail, { className: "h-5 w-5 text-primary" }),
                  method.type === "sms" && /* @__PURE__ */ jsx(Smartphone, { className: "h-5 w-5 text-primary" })
                ] }),
                /* @__PURE__ */ jsxs("div", { children: [
                  /* @__PURE__ */ jsx("p", { className: "font-medium", children: method.name }),
                  /* @__PURE__ */ jsxs("p", { className: "text-xs text-muted-foreground", children: [
                    "Added ",
                    new Date(method.created_at).toLocaleDateString()
                  ] })
                ] })
              ] }),
              /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
                /* @__PURE__ */ jsxs(Badge, { variant: "success", className: "gap-1", children: [
                  /* @__PURE__ */ jsx(CheckCircle, { className: "h-3 w-3" }),
                  "Active"
                ] }),
                /* @__PURE__ */ jsx(Button, { variant: "ghost", size: "icon", "aria-label": "Remove MFA method", children: /* @__PURE__ */ jsx(Trash2, { className: "h-4 w-4 text-destructive" }) })
              ] })
            ] }, method.type)),
            /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-1 sm:grid-cols-3 gap-3 mt-4", children: [
              /* @__PURE__ */ jsxs(Button, { variant: "outline", className: "h-auto py-4 flex-col items-center gap-2", onClick: () => {
                setEnrollMethod("totp");
                setIsEnrollOpen(true);
              }, children: [
                /* @__PURE__ */ jsx(Shield, { className: "h-6 w-6" }),
                /* @__PURE__ */ jsx("span", { className: "text-sm", children: "Authenticator App" })
              ] }),
              /* @__PURE__ */ jsxs(Button, { variant: "outline", className: "h-auto py-4 flex-col items-center gap-2", onClick: () => {
                setEnrollMethod("email");
                setIsEnrollOpen(true);
              }, children: [
                /* @__PURE__ */ jsx(Mail, { className: "h-6 w-6" }),
                /* @__PURE__ */ jsx("span", { className: "text-sm", children: "Email OTP" })
              ] }),
              /* @__PURE__ */ jsxs(Button, { variant: "outline", className: "h-auto py-4 flex-col items-center gap-2", onClick: () => {
                setEnrollMethod("sms");
                setIsEnrollOpen(true);
              }, children: [
                /* @__PURE__ */ jsx(Smartphone, { className: "h-6 w-6" }),
                /* @__PURE__ */ jsx("span", { className: "text-sm", children: "SMS OTP" })
              ] })
            ] })
          ] })
        ] }),
        /* @__PURE__ */ jsx(Card, { className: "p-6", children: /* @__PURE__ */ jsxs("div", { className: "flex items-start gap-4", children: [
          /* @__PURE__ */ jsx("div", { className: "p-3 bg-amber-100 dark:bg-amber-900/20 rounded-lg", children: /* @__PURE__ */ jsx(AlertCircle, { className: "h-6 w-6 text-amber-600 dark:text-amber-400" }) }),
          /* @__PURE__ */ jsxs("div", { className: "flex-1", children: [
            /* @__PURE__ */ jsx("h3", { className: "text-lg font-medium", children: "Backup Codes" }),
            /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground mt-1", children: "Generate backup codes to access your account if you lose your MFA device" }),
            /* @__PURE__ */ jsx(Button, { variant: "outline", className: "mt-4", children: "Generate New Codes" })
          ] })
        ] }) })
      ] }),
      /* @__PURE__ */ jsx(TabsContent, { value: "sessions", children: /* @__PURE__ */ jsx(Card, { className: "p-6", children: /* @__PURE__ */ jsx(Suspense, { fallback: /* @__PURE__ */ jsx(Skeleton, { className: "h-64 w-full" }), children: /* @__PURE__ */ jsx(SessionManager, {}) }) }) }),
      /* @__PURE__ */ jsx(TabsContent, { value: "password", children: /* @__PURE__ */ jsxs(Card, { className: "p-6", children: [
        /* @__PURE__ */ jsx("h3", { className: "text-lg font-medium mb-4", children: "Change Password" }),
        passwordError && /* @__PURE__ */ jsx("p", { className: "mb-3 text-sm text-destructive", children: passwordError }),
        passwordMessage && /* @__PURE__ */ jsx("p", { className: "mb-3 text-sm text-green-600", children: passwordMessage }),
        /* @__PURE__ */ jsxs("form", { onSubmit: (event) => {
          event.preventDefault();
          event.stopPropagation();
          void passwordForm.handleSubmit();
        }, className: "space-y-4 max-w-md", children: [
          /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
            /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", children: "Current Password" }),
            /* @__PURE__ */ jsx(passwordForm.Field, { name: "currentPassword", validators: {
              onChange: ({
                value
              }) => {
                if (!value) return "Current password is required";
                return void 0;
              }
            }, children: (field) => /* @__PURE__ */ jsx(Input, { type: "password", placeholder: "Enter current password", value: field.state.value, onChange: (e) => field.handleChange(e.target.value), onBlur: field.handleBlur, error: field.state.meta.isTouched ? field.state.meta.errors[0] : void 0 }) })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
            /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", children: "New Password" }),
            /* @__PURE__ */ jsx(passwordForm.Field, { name: "newPassword", validators: {
              onChange: ({
                value
              }) => {
                if (!value) return "New password is required";
                if (value.length < 8) return "Password must be at least 8 characters";
                return void 0;
              }
            }, children: (field) => /* @__PURE__ */ jsx(Input, { type: "password", placeholder: "Enter new password", value: field.state.value, onChange: (e) => field.handleChange(e.target.value), onBlur: field.handleBlur, error: field.state.meta.isTouched ? field.state.meta.errors[0] : void 0 }) })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
            /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", children: "Confirm New Password" }),
            /* @__PURE__ */ jsx(passwordForm.Field, { name: "confirmPassword", validators: {
              onChange: ({
                value
              }) => {
                if (!value) return "Please confirm your new password";
                return void 0;
              }
            }, children: (field) => /* @__PURE__ */ jsx(Input, { type: "password", placeholder: "Confirm new password", value: field.state.value, onChange: (e) => field.handleChange(e.target.value), onBlur: field.handleBlur, error: field.state.meta.isTouched ? field.state.meta.errors[0] : void 0 }) }),
            /* @__PURE__ */ jsx(passwordForm.Subscribe, { selector: (state) => ({
              newPassword: state.values.newPassword,
              confirmPassword: state.values.confirmPassword
            }), children: ({
              newPassword,
              confirmPassword
            }) => confirmPassword && newPassword && confirmPassword !== newPassword ? /* @__PURE__ */ jsx("p", { className: "text-sm text-destructive", children: "Passwords do not match" }) : null })
          ] }),
          /* @__PURE__ */ jsx(Button, { type: "submit", isLoading: isUpdatingPassword, children: "Update Password" })
        ] })
      ] }) })
    ] }),
    /* @__PURE__ */ jsxs(Card, { className: "p-6", children: [
      /* @__PURE__ */ jsxs("div", { className: "flex items-start justify-between", children: [
        /* @__PURE__ */ jsxs("div", { children: [
          /* @__PURE__ */ jsx("h3", { className: "text-lg font-medium", children: "Data Encryption Providers" }),
          /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground mt-1", children: "Available KMS backends are determined by the current build" })
        ] }),
        providerStatus?.initialized ? /* @__PURE__ */ jsx(Badge, { variant: "success", children: "Initialized" }) : /* @__PURE__ */ jsx(Badge, { variant: "warning", children: "Not Initialized" })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "mt-4 space-y-2", children: [
        providersError && /* @__PURE__ */ jsx("p", { className: "text-sm text-destructive", children: providersError }),
        !providers && !providersError && /* @__PURE__ */ jsx(Skeleton, { className: "h-20 w-full" }),
        providers && /* @__PURE__ */ jsxs(Fragment, { children: [
          /* @__PURE__ */ jsx("div", { className: "flex flex-wrap gap-2", children: providers.supported.map((provider) => /* @__PURE__ */ jsx(Badge, { variant: "outline", children: provider.replace("_", " ").toUpperCase() }, provider)) }),
          /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground", children: [
            "Default provider: ",
            /* @__PURE__ */ jsx("span", { className: "font-medium", children: providers.default })
          ] }),
          providerStatus && /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground", children: [
            "Active provider: ",
            /* @__PURE__ */ jsx("span", { className: "font-medium", children: providerStatus.provider })
          ] })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsx(Dialog, { open: isEnrollOpen, onOpenChange: setIsEnrollOpen, children: /* @__PURE__ */ jsxs(DialogContent, { className: "max-w-md", children: [
      /* @__PURE__ */ jsxs(DialogHeader, { children: [
        /* @__PURE__ */ jsxs(DialogTitle, { children: [
          "Set Up ",
          enrollMethod === "totp" ? "Authenticator App" : enrollMethod === "email" ? "Email OTP" : "SMS OTP"
        ] }),
        /* @__PURE__ */ jsx(DialogDescription, { children: "Add an extra layer of security to your account" })
      ] }),
      /* @__PURE__ */ jsx(Suspense, { fallback: /* @__PURE__ */ jsx(Skeleton, { className: "h-72 w-full" }), children: /* @__PURE__ */ jsx(MfaEnroll, { method: enrollMethod, onEnroll: async (_code) => {
        await new Promise((resolve) => setTimeout(resolve, 1e3));
      }, onCancel: () => setIsEnrollOpen(false) }) })
    ] }) })
  ] });
}
export {
  SecuritySettingsPage as component
};
