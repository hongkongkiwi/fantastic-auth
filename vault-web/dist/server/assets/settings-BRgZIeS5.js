import { jsx, jsxs } from "react/jsx-runtime";
import * as React from "react";
import { useState, useMemo } from "react";
import { useReducedMotion, motion, AnimatePresence } from "framer-motion";
import { Settings, Shield, Mail, CreditCard, Bell, Webhook, Lock, BarChart3, Server, Search, X, ChevronRight, Key, AlertTriangle, CheckCircle } from "lucide-react";
import { j as cn$1, l as getUiConfig, P as PageHeader, B as Button, t as toast } from "./router-BDwxh4pl.js";
import { C as Card, a as CardHeader, b as CardTitle, c as CardDescription, d as CardContent } from "./Card-Brxgy2gk.js";
import { B as Badge } from "./Badge-DmGWtXSM.js";
import * as SwitchPrimitives from "@radix-ui/react-switch";
import { I as Input } from "./Input-C7MrN6IE.js";
import * as SliderPrimitive from "@radix-ui/react-slider";
import { useQuery } from "@tanstack/react-query";
import "@tanstack/react-router";
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
const Switch = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  SwitchPrimitives.Root,
  {
    className: cn$1(
      "peer inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:bg-primary data-[state=unchecked]:bg-input",
      className
    ),
    ...props,
    ref,
    children: /* @__PURE__ */ jsx(
      SwitchPrimitives.Thumb,
      {
        className: cn$1(
          "pointer-events-none block h-5 w-5 rounded-full bg-background shadow-lg ring-0 transition-transform data-[state=checked]:translate-x-5 data-[state=unchecked]:translate-x-0"
        )
      }
    )
  }
));
Switch.displayName = SwitchPrimitives.Root.displayName;
const Slider = React.forwardRef(
  ({
    className,
    label,
    description,
    showValue = true,
    valueFormatter = (v) => String(v),
    min = 0,
    max = 100,
    step = 1,
    value,
    defaultValue,
    ...props
  }, ref) => {
    const currentValue = value ?? defaultValue ?? [min];
    const displayValue = Array.isArray(currentValue) ? currentValue[0] : currentValue;
    return /* @__PURE__ */ jsxs("div", { className: cn$1("w-full space-y-3", className), children: [
      (label || showValue) && /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
        label && /* @__PURE__ */ jsx("label", { className: "text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70", children: label }),
        showValue && /* @__PURE__ */ jsx("span", { className: "text-sm text-muted-foreground font-mono", children: valueFormatter(displayValue) })
      ] }),
      /* @__PURE__ */ jsxs(
        SliderPrimitive.Root,
        {
          ref,
          min,
          max,
          step,
          value,
          defaultValue,
          className: cn$1(
            "relative flex w-full touch-none select-none items-center",
            className
          ),
          ...props,
          children: [
            /* @__PURE__ */ jsx(SliderPrimitive.Track, { className: "relative h-2 w-full grow overflow-hidden rounded-full bg-secondary", children: /* @__PURE__ */ jsx(SliderPrimitive.Range, { className: "absolute h-full bg-primary" }) }),
            /* @__PURE__ */ jsx(
              SliderPrimitive.Thumb,
              {
                className: cn$1(
                  "block h-5 w-5 rounded-full border-2 border-primary bg-background",
                  "ring-offset-background transition-colors",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
                  "disabled:pointer-events-none disabled:opacity-50",
                  "active:scale-110 transition-transform"
                )
              }
            )
          ]
        }
      ),
      description && /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: description }),
      /* @__PURE__ */ jsxs("div", { className: "flex justify-between text-xs text-muted-foreground", children: [
        /* @__PURE__ */ jsx("span", { children: valueFormatter(min) }),
        /* @__PURE__ */ jsx("span", { children: valueFormatter(max) })
      ] })
    ] });
  }
);
Slider.displayName = SliderPrimitive.Root.displayName;
const RangeSlider = React.forwardRef(
  ({
    className,
    label,
    description,
    showValue = true,
    valueFormatter = (v) => String(v),
    min = 0,
    max = 100,
    step = 1,
    value,
    defaultValue,
    onValueChange,
    ...props
  }, ref) => {
    const currentValue = value ?? defaultValue ?? [min, max];
    return /* @__PURE__ */ jsxs("div", { className: cn$1("w-full space-y-3", className), children: [
      (label || showValue) && /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
        label && /* @__PURE__ */ jsx("label", { className: "text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70", children: label }),
        showValue && /* @__PURE__ */ jsxs("span", { className: "text-sm text-muted-foreground font-mono", children: [
          valueFormatter(currentValue[0]),
          " - ",
          valueFormatter(currentValue[1])
        ] })
      ] }),
      /* @__PURE__ */ jsxs(
        SliderPrimitive.Root,
        {
          ref,
          min,
          max,
          step,
          value: currentValue,
          onValueChange,
          className: cn$1(
            "relative flex w-full touch-none select-none items-center",
            className
          ),
          ...props,
          children: [
            /* @__PURE__ */ jsx(SliderPrimitive.Track, { className: "relative h-2 w-full grow overflow-hidden rounded-full bg-secondary", children: /* @__PURE__ */ jsx(SliderPrimitive.Range, { className: "absolute h-full bg-primary" }) }),
            /* @__PURE__ */ jsx(
              SliderPrimitive.Thumb,
              {
                className: cn$1(
                  "block h-5 w-5 rounded-full border-2 border-primary bg-background",
                  "ring-offset-background transition-colors",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
                  "disabled:pointer-events-none disabled:opacity-50",
                  "active:scale-110 transition-transform"
                )
              }
            ),
            /* @__PURE__ */ jsx(
              SliderPrimitive.Thumb,
              {
                className: cn$1(
                  "block h-5 w-5 rounded-full border-2 border-primary bg-background",
                  "ring-offset-background transition-colors",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
                  "disabled:pointer-events-none disabled:opacity-50",
                  "active:scale-110 transition-transform"
                )
              }
            )
          ]
        }
      ),
      description && /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: description }),
      /* @__PURE__ */ jsxs("div", { className: "flex justify-between text-xs text-muted-foreground", children: [
        /* @__PURE__ */ jsx("span", { children: valueFormatter(min) }),
        /* @__PURE__ */ jsx("span", { children: valueFormatter(max) })
      ] })
    ] });
  }
);
RangeSlider.displayName = "RangeSlider";
const settingsCategories = [{
  id: "general",
  title: "General",
  description: "Basic platform configuration",
  icon: Settings,
  color: "blue",
  settings: [{
    id: "siteName",
    label: "Site Name",
    type: "input",
    value: "Vault Admin"
  }, {
    id: "siteUrl",
    label: "Site URL",
    type: "input",
    value: "https://vault.example.com"
  }, {
    id: "timezone",
    label: "Default Timezone",
    type: "select",
    value: "UTC"
  }, {
    id: "language",
    label: "Default Language",
    type: "select",
    value: "en"
  }]
}, {
  id: "authentication",
  title: "Authentication",
  description: "Login methods and security",
  icon: Shield,
  color: "green",
  href: "/settings/security",
  settings: [{
    id: "mfa",
    label: "Require MFA",
    type: "toggle",
    value: false
  }, {
    id: "magicLink",
    label: "Enable Magic Link",
    type: "toggle",
    value: true
  }, {
    id: "oauth",
    label: "Social Login",
    type: "toggle",
    value: true
  }, {
    id: "sessionDuration",
    label: "Session Duration (hours)",
    type: "slider",
    value: 24,
    min: 1,
    max: 168
  }]
}, {
  id: "email",
  title: "Email",
  description: "Email provider and templates",
  icon: Mail,
  color: "amber",
  settings: [{
    id: "provider",
    label: "Email Provider",
    type: "select",
    value: "smtp"
  }, {
    id: "fromEmail",
    label: "From Email",
    type: "input",
    value: "noreply@vault.example.com"
  }, {
    id: "templates",
    label: "Custom Templates",
    type: "toggle",
    value: false
  }]
}, {
  id: "billing",
  title: "Billing",
  description: "Payment and subscription settings",
  icon: CreditCard,
  color: "purple",
  settings: [{
    id: "enabled",
    label: "Enable Billing",
    type: "toggle",
    value: true
  }, {
    id: "provider",
    label: "Payment Provider",
    type: "select",
    value: "stripe"
  }, {
    id: "trialDays",
    label: "Trial Period (days)",
    type: "slider",
    value: 14,
    min: 0,
    max: 30
  }]
}, {
  id: "notifications",
  title: "Notifications",
  description: "Alert preferences and channels",
  icon: Bell,
  color: "rose",
  settings: [{
    id: "emailAlerts",
    label: "Email Alerts",
    type: "toggle",
    value: true
  }, {
    id: "slackAlerts",
    label: "Slack Integration",
    type: "toggle",
    value: false
  }, {
    id: "webhookAlerts",
    label: "Webhook Alerts",
    type: "toggle",
    value: false
  }]
}, {
  id: "api",
  title: "API & Webhooks",
  description: "API keys and webhook endpoints",
  icon: Webhook,
  color: "indigo",
  href: "/settings/webhooks",
  settings: [{
    id: "rateLimit",
    label: "Rate Limit (requests/min)",
    type: "slider",
    value: 60,
    min: 10,
    max: 1e3
  }, {
    id: "cors",
    label: "CORS Origins",
    type: "input",
    value: "*"
  }, {
    id: "apiVersion",
    label: "API Version",
    type: "select",
    value: "v1"
  }]
}, {
  id: "security",
  title: "Security",
  description: "Advanced security settings",
  icon: Lock,
  color: "red",
  settings: [{
    id: "hibp",
    label: "Check Breached Passwords",
    type: "toggle",
    value: true
  }, {
    id: "geoip",
    label: "GeoIP Blocking",
    type: "toggle",
    value: false
  }, {
    id: "captcha",
    label: "CAPTCHA Protection",
    type: "toggle",
    value: true
  }, {
    id: "auditRetention",
    label: "Audit Log Retention (days)",
    type: "slider",
    value: 90,
    min: 30,
    max: 365
  }]
}, {
  id: "analytics",
  title: "Analytics",
  description: "Usage tracking and insights",
  icon: BarChart3,
  color: "cyan",
  settings: [{
    id: "enabled",
    label: "Enable Analytics",
    type: "toggle",
    value: true
  }, {
    id: "provider",
    label: "Analytics Provider",
    type: "select",
    value: "posthog"
  }, {
    id: "anonymize",
    label: "Anonymize IPs",
    type: "toggle",
    value: true
  }]
}, {
  id: "system",
  title: "System",
  description: "Maintenance and advanced options",
  icon: Server,
  color: "slate",
  settings: [{
    id: "maintenance",
    label: "Maintenance Mode",
    type: "toggle",
    value: false
  }, {
    id: "debug",
    label: "Debug Mode",
    type: "toggle",
    value: false
  }, {
    id: "backups",
    label: "Auto Backups",
    type: "toggle",
    value: true
  }]
}];
function SettingsPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [activeCategory, setActiveCategory] = useState(null);
  const [settings, setSettings] = useState({
    // General
    siteName: "Vault Admin",
    siteUrl: "https://vault.example.com",
    timezone: "UTC",
    language: "en",
    darkMode: false,
    // Auth
    mfa: false,
    magicLink: true,
    oauth: true,
    sessionDuration: 24,
    // Email
    emailProvider: "smtp",
    fromEmail: "noreply@vault.example.com",
    templates: false,
    // Billing
    billingEnabled: true,
    paymentProvider: "stripe",
    trialDays: 14,
    // Notifications
    emailAlerts: true,
    slackAlerts: false,
    webhookAlerts: false,
    // API
    rateLimit: 60,
    cors: "*",
    apiVersion: "v1",
    // Security
    hibp: true,
    geoip: false,
    captcha: true,
    auditRetention: 90,
    // Analytics
    analyticsEnabled: true,
    analyticsProvider: "posthog",
    anonymize: true,
    // System
    maintenance: false,
    debug: false,
    backups: true
  });
  const [hasChanges, setHasChanges] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const {
    data: uiConfig
  } = useQuery({
    queryKey: ["ui-config"],
    queryFn: () => getUiConfig()
  });
  const prefersReducedMotion = useReducedMotion();
  const internalApiBaseUrl = uiConfig?.internalApiBaseUrl || "http://localhost:3000/api/v1/internal";
  const hasApiKey = uiConfig?.hasApiKey ?? false;
  const filteredCategories = useMemo(() => {
    if (!searchQuery.trim()) return settingsCategories;
    const query = searchQuery.toLowerCase();
    return settingsCategories.filter((category) => {
      if (category.title.toLowerCase().includes(query)) return true;
      if (category.description.toLowerCase().includes(query)) return true;
      return category.settings.some((setting) => setting.label.toLowerCase().includes(query));
    });
  }, [searchQuery]);
  const updateSetting = (key, value) => {
    setSettings((prev) => ({
      ...prev,
      [key]: value
    }));
    setHasChanges(true);
  };
  const handleSave = async () => {
    setIsSaving(true);
    try {
      await new Promise((resolve) => setTimeout(resolve, 1e3));
      toast.success("Settings saved successfully");
      setHasChanges(false);
    } catch {
      toast.error("Failed to save settings");
    } finally {
      setIsSaving(false);
    }
  };
  const renderSetting = (setting) => {
    const value = settings[setting.id];
    switch (setting.type) {
      case "toggle":
        return /* @__PURE__ */ jsx(Switch, { checked: value, onCheckedChange: (checked) => updateSetting(setting.id, checked) });
      case "input":
        return /* @__PURE__ */ jsx(Input, { value, onChange: (e) => updateSetting(setting.id, e.target.value), className: "max-w-xs" });
      case "select":
        return /* @__PURE__ */ jsxs("select", { value, onChange: (e) => updateSetting(setting.id, e.target.value), className: "rounded-md border border-input bg-background px-3 py-2 text-sm max-w-xs", children: [
          /* @__PURE__ */ jsx("option", { value: "en", children: "English" }),
          /* @__PURE__ */ jsx("option", { value: "es", children: "Spanish" }),
          /* @__PURE__ */ jsx("option", { value: "fr", children: "French" }),
          /* @__PURE__ */ jsx("option", { value: "de", children: "German" })
        ] });
      case "slider":
        return /* @__PURE__ */ jsx("div", { className: "w-48", children: /* @__PURE__ */ jsx(Slider, { value: [value], onValueChange: ([v]) => updateSetting(setting.id, v), min: setting.min, max: setting.max, showValue: true }) });
      default:
        return null;
    }
  };
  const activeCategoryData = settingsCategories.find((c) => c.id === activeCategory);
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "Settings", description: "Configure your platform settings", breadcrumbs: [{
      label: "Settings"
    }] }),
    /* @__PURE__ */ jsxs("div", { className: "relative", children: [
      /* @__PURE__ */ jsx(Search, { className: "absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" }),
      /* @__PURE__ */ jsx(Input, { placeholder: "Search settings...", value: searchQuery, onChange: (e) => setSearchQuery(e.target.value), className: "pl-10" }),
      searchQuery && /* @__PURE__ */ jsx("button", { onClick: () => setSearchQuery(""), className: "absolute right-3 top-1/2 -translate-y-1/2", children: /* @__PURE__ */ jsx(X, { className: "h-4 w-4 text-muted-foreground" }) })
    ] }),
    /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-1 lg:grid-cols-4 gap-6", children: [
      /* @__PURE__ */ jsxs("div", { className: "lg:col-span-1 space-y-2", children: [
        /* @__PURE__ */ jsx("h3", { className: "text-sm font-medium text-muted-foreground mb-3", children: "Categories" }),
        filteredCategories.map((category) => {
          const Icon = category.icon;
          const isActive = activeCategory === category.id;
          return /* @__PURE__ */ jsxs("button", { onClick: () => setActiveCategory(category.id), className: cn("w-full flex items-center gap-3 p-3 rounded-lg text-left transition-colors", isActive ? "bg-primary/10 text-primary" : "hover:bg-muted"), children: [
            /* @__PURE__ */ jsx("div", { className: cn("p-2 rounded-lg", isActive ? "bg-primary/20" : "bg-muted"), children: /* @__PURE__ */ jsx(Icon, { className: "h-4 w-4" }) }),
            /* @__PURE__ */ jsxs("div", { className: "flex-1", children: [
              /* @__PURE__ */ jsx("p", { className: "font-medium text-sm", children: category.title }),
              /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground line-clamp-1", children: category.description })
            ] }),
            isActive && /* @__PURE__ */ jsx(ChevronRight, { className: "h-4 w-4" })
          ] }, category.id);
        })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "lg:col-span-3 space-y-6", children: [
        activeCategoryData ? /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
          opacity: 0,
          y: 10
        }, animate: {
          opacity: 1,
          y: 0
        }, children: /* @__PURE__ */ jsxs(Card, { children: [
          /* @__PURE__ */ jsx(CardHeader, { children: /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
            /* @__PURE__ */ jsx("div", { className: `p-2 rounded-lg bg-${activeCategoryData.color}-100`, children: /* @__PURE__ */ jsx(activeCategoryData.icon, { className: `h-5 w-5 text-${activeCategoryData.color}-600` }) }),
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx(CardTitle, { children: activeCategoryData.title }),
              /* @__PURE__ */ jsx(CardDescription, { children: activeCategoryData.description })
            ] })
          ] }) }),
          /* @__PURE__ */ jsx(CardContent, { className: "space-y-6", children: activeCategoryData.settings.map((setting) => /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between py-3 border-b last:border-0", children: [
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx("p", { className: "font-medium", children: setting.label }),
              setting.type === "slider" && /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground", children: [
                "Current: ",
                settings[setting.id],
                setting.id.includes("Duration") && " hours",
                setting.id.includes("Retention") && " days",
                setting.id.includes("Limit") && " requests/min",
                setting.id.includes("trial") && " days"
              ] })
            ] }),
            renderSetting(setting)
          ] }, setting.id)) })
        ] }) }) : /* @__PURE__ */ jsx("div", { className: "grid grid-cols-1 sm:grid-cols-2 gap-4", children: filteredCategories.map((category, index) => {
          const Icon = category.icon;
          return /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
            opacity: 0,
            y: 20
          }, animate: {
            opacity: 1,
            y: 0
          }, transition: prefersReducedMotion ? {
            duration: 0
          } : {
            delay: index * 0.05
          }, children: /* @__PURE__ */ jsx(Card, { className: "cursor-pointer hover:border-primary/50 transition-colors", onClick: () => setActiveCategory(category.id), children: /* @__PURE__ */ jsx(CardContent, { className: "p-6", children: /* @__PURE__ */ jsxs("div", { className: "flex items-start gap-4", children: [
            /* @__PURE__ */ jsx("div", { className: `p-3 rounded-lg bg-${category.color}-100`, children: /* @__PURE__ */ jsx(Icon, { className: `h-5 w-5 text-${category.color}-600` }) }),
            /* @__PURE__ */ jsxs("div", { className: "flex-1", children: [
              /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
                /* @__PURE__ */ jsx("h3", { className: "font-semibold", children: category.title }),
                category.href && /* @__PURE__ */ jsx(Badge, { variant: "outline", className: "text-xs", children: "Page" })
              ] }),
              /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground mt-1", children: category.description }),
              /* @__PURE__ */ jsxs("p", { className: "text-xs text-muted-foreground mt-2", children: [
                category.settings.length,
                " settings"
              ] })
            ] }),
            /* @__PURE__ */ jsx(ChevronRight, { className: "h-5 w-5 text-muted-foreground" })
          ] }) }) }) }, category.id);
        }) }),
        /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
          opacity: 0,
          y: 20
        }, animate: {
          opacity: 1,
          y: 0
        }, transition: prefersReducedMotion ? {
          duration: 0
        } : {
          delay: 0.3
        }, children: /* @__PURE__ */ jsxs(Card, { children: [
          /* @__PURE__ */ jsx(CardHeader, { children: /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
            /* @__PURE__ */ jsx("div", { className: "p-2 rounded-lg bg-primary/10", children: /* @__PURE__ */ jsx(Key, { className: "h-5 w-5 text-primary" }) }),
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx(CardTitle, { children: "API Configuration" }),
              /* @__PURE__ */ jsx(CardDescription, { children: "Manage internal API settings" })
            ] })
          ] }) }),
          /* @__PURE__ */ jsxs(CardContent, { className: "space-y-4", children: [
            /* @__PURE__ */ jsxs("div", { className: "p-4 rounded-lg bg-muted", children: [
              /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between mb-2", children: [
                /* @__PURE__ */ jsx("span", { className: "text-sm font-medium", children: "Internal API URL" }),
                /* @__PURE__ */ jsx(Badge, { variant: "outline", children: "Configured" })
              ] }),
              /* @__PURE__ */ jsx("code", { className: "text-sm text-muted-foreground", children: internalApiBaseUrl })
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between p-4 rounded-lg bg-muted", children: [
              /* @__PURE__ */ jsxs("div", { children: [
                /* @__PURE__ */ jsx("span", { className: "text-sm font-medium", children: "API Key Status" }),
                /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: hasApiKey ? "Key configured" : "No key set" })
              ] }),
              /* @__PURE__ */ jsx(Badge, { variant: hasApiKey ? "success" : "warning", children: hasApiKey ? "Active" : "Missing" })
            ] })
          ] })
        ] }) }),
        /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
          opacity: 0,
          y: 20
        }, animate: {
          opacity: 1,
          y: 0
        }, transition: prefersReducedMotion ? {
          duration: 0
        } : {
          delay: 0.4
        }, children: /* @__PURE__ */ jsxs(Card, { className: "border-destructive/20", children: [
          /* @__PURE__ */ jsx(CardHeader, { children: /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
            /* @__PURE__ */ jsx("div", { className: "p-2 rounded-lg bg-destructive/10", children: /* @__PURE__ */ jsx(AlertTriangle, { className: "h-5 w-5 text-destructive" }) }),
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx(CardTitle, { className: "text-destructive", children: "Danger Zone" }),
              /* @__PURE__ */ jsx(CardDescription, { children: "Destructive actions that cannot be undone" })
            ] })
          ] }) }),
          /* @__PURE__ */ jsxs(CardContent, { className: "space-y-4", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between p-4 rounded-lg border border-destructive/20 bg-destructive/5", children: [
              /* @__PURE__ */ jsxs("div", { children: [
                /* @__PURE__ */ jsx("p", { className: "font-medium text-destructive", children: "Reset Platform" }),
                /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Delete all tenant data and reset to factory defaults" })
              ] }),
              /* @__PURE__ */ jsx(Button, { variant: "destructive", children: "Reset" })
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between p-4 rounded-lg border border-destructive/20 bg-destructive/5", children: [
              /* @__PURE__ */ jsxs("div", { children: [
                /* @__PURE__ */ jsx("p", { className: "font-medium text-destructive", children: "Clear Cache" }),
                /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Clear all cached data and sessions" })
              ] }),
              /* @__PURE__ */ jsx(Button, { variant: "outline", className: "border-destructive/50 text-destructive hover:bg-destructive/10", children: "Clear" })
            ] })
          ] })
        ] }) })
      ] })
    ] }),
    /* @__PURE__ */ jsx(AnimatePresence, { children: hasChanges && /* @__PURE__ */ jsx(motion.div, { initial: {
      opacity: 0,
      y: 50
    }, animate: {
      opacity: 1,
      y: 0
    }, exit: {
      opacity: 0,
      y: 50
    }, className: "fixed bottom-6 left-1/2 -translate-x-1/2 z-50", children: /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-4 px-6 py-3 bg-background border rounded-full shadow-lg", children: [
      /* @__PURE__ */ jsx("span", { className: "text-sm font-medium", children: "You have unsaved changes" }),
      /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsx(Button, { variant: "ghost", size: "sm", onClick: () => setHasChanges(false), children: "Discard" }),
        /* @__PURE__ */ jsxs(Button, { size: "sm", onClick: handleSave, isLoading: isSaving, children: [
          /* @__PURE__ */ jsx(CheckCircle, { className: "mr-2 h-4 w-4" }),
          "Save Changes"
        ] })
      ] })
    ] }) }) })
  ] });
}
function cn(...classes) {
  return classes.filter(Boolean).join(" ");
}
export {
  SettingsPage as component
};
