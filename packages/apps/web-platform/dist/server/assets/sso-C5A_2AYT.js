import { jsxs, jsx, Fragment } from "react/jsx-runtime";
import { c as cn, B as Button, a as Badge, e as env, P as PageHeader } from "./router-BqFKwE1w.js";
import { C as Card, a as CardHeader, b as CardTitle, c as CardDescription, d as CardContent } from "./Card-DiqECnNB.js";
import { T as Tabs, a as TabsList, b as TabsTrigger, c as TabsContent } from "./Tabs-Dlqc7sYx.js";
import { useState, useEffect } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { I as Input } from "./Input-D8nMsmC2.js";
import { S as Switch } from "./Switch-DnK4UYa_.js";
import { Upload, CheckCircle, AlertTriangle, Copy, ExternalLink, Download, Shield, Chrome, Github, Building2, Apple, Lock, Globe } from "lucide-react";
import "./internal-api-DaRn9LSO.js";
import "sonner";
import "clsx";
import "@tanstack/react-router";
import "@t3-oss/env-core";
import "zod";
import "tailwind-merge";
import "@radix-ui/react-slot";
import "class-variance-authority";
import "@radix-ui/react-dialog";
import "cmdk";
import "@radix-ui/react-checkbox";
import "@radix-ui/react-label";
import "@sentry/react";
import "@radix-ui/react-tabs";
import "@radix-ui/react-switch";
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
import "./auth-middleware-Bbw8ptVi.js";
import "ioredis";
import "./server-Dz7KC5sb.js";
import "./logger-D87hn870.js";
import "loglayer";
const defaultConfig$1 = {
  enabled: false,
  provider: "",
  entityId: "",
  ssoUrl: "",
  certificate: "",
  signInUrl: "",
  nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  allowCreate: true
};
const nameIdFormats = [
  { value: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", label: "Email Address" },
  { value: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", label: "Unspecified" },
  { value: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", label: "Persistent" },
  { value: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", label: "Transient" }
];
function SamlConfiguration() {
  const [config, setConfig] = useState(defaultConfig$1);
  const [isLoading, setIsLoading] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [testStatus, setTestStatus] = useState("idle");
  const [activeTab, setActiveTab] = useState("general");
  const [connectionId, setConnectionId] = useState(null);
  const [saveError, setSaveError] = useState(null);
  useEffect(() => {
    let cancelled = false;
    async function loadConnection() {
      try {
        const response = await fetch("/api/v1/admin/sso/saml/connections", {
          credentials: "include"
        });
        if (!response.ok) return;
        const payload = await response.json();
        const first = payload.data?.[0];
        if (!first || cancelled) return;
        setConnectionId(first.id);
        setConfig((prev) => ({
          ...prev,
          enabled: first.status === "active",
          provider: first.name || "",
          entityId: first.idp_entity_id || "",
          ssoUrl: first.idp_sso_url || "",
          signInUrl: first.idp_slo_url || "",
          nameIdFormat: first.name_id_format || prev.nameIdFormat,
          allowCreate: first.jit_provisioning_enabled ?? true
        }));
      } catch {
      }
    }
    void loadConnection();
    return () => {
      cancelled = true;
    };
  }, []);
  const handleSave = async () => {
    setIsLoading(true);
    try {
      const payload = {
        name: config.provider || "Default SAML",
        idp_entity_id: config.entityId || null,
        idp_sso_url: config.ssoUrl || null,
        idp_slo_url: config.signInUrl || null,
        idp_certificate: config.certificate || null,
        name_id_format: config.nameIdFormat,
        jit_provisioning_enabled: config.allowCreate,
        status: config.enabled ? "active" : "inactive"
      };
      const url = connectionId ? `/api/v1/admin/sso/saml/connections/${connectionId}` : "/api/v1/admin/sso/saml/connections";
      const method = connectionId ? "PATCH" : "POST";
      const response = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(payload)
      });
      if (!response.ok) {
        throw new Error("Failed to save SAML configuration");
      }
      if (!connectionId) {
        const created = await response.json();
        if (created.id) {
          setConnectionId(created.id);
        }
      }
      setSaveError(null);
      setTestStatus("idle");
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : "Failed to save SAML configuration");
    } finally {
      setIsLoading(false);
    }
  };
  const handleTestConnection = async () => {
    setIsTesting(true);
    setTestStatus("idle");
    try {
      if (!connectionId) {
        throw new Error("Save configuration before testing");
      }
      const response = await fetch(`/api/v1/admin/sso/saml/connections/${connectionId}/test`, {
        method: "POST",
        credentials: "include"
      });
      if (!response.ok) {
        throw new Error("Connection test failed");
      }
      setTestStatus("success");
    } catch {
      setTestStatus("error");
    } finally {
      setIsTesting(false);
    }
  };
  const copyMetadataUrl = () => {
    navigator.clipboard.writeText(`${window.location.origin}/api/auth/saml/metadata`);
  };
  const copyAcsUrl = () => {
    navigator.clipboard.writeText(`${window.location.origin}/api/auth/saml/acs`);
  };
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsx("h2", { className: "text-2xl font-bold tracking-tight", children: "SAML SSO Configuration" }),
        /* @__PURE__ */ jsx("p", { className: "text-muted-foreground", children: "Configure SAML 2.0 single sign-on integration with your identity provider" })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsx(
          Switch,
          {
            checked: config.enabled,
            onCheckedChange: (checked) => setConfig({ ...config, enabled: checked })
          }
        ),
        /* @__PURE__ */ jsx("span", { className: cn("text-sm font-medium", config.enabled ? "text-green-600" : "text-muted-foreground"), children: config.enabled ? "Enabled" : "Disabled" })
      ] })
    ] }),
    saveError && /* @__PURE__ */ jsx("div", { className: "rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive", children: saveError }),
    /* @__PURE__ */ jsxs(Tabs, { value: activeTab, onValueChange: setActiveTab, children: [
      /* @__PURE__ */ jsxs(TabsList, { children: [
        /* @__PURE__ */ jsx(TabsTrigger, { value: "general", children: "General" }),
        /* @__PURE__ */ jsx(TabsTrigger, { value: "provider", children: "Identity Provider" }),
        /* @__PURE__ */ jsx(TabsTrigger, { value: "metadata", children: "Service Provider" })
      ] }),
      /* @__PURE__ */ jsx(TabsContent, { value: "general", className: "space-y-4", children: /* @__PURE__ */ jsxs(Card, { children: [
        /* @__PURE__ */ jsxs(CardHeader, { children: [
          /* @__PURE__ */ jsx(CardTitle, { children: "General Settings" }),
          /* @__PURE__ */ jsx(CardDescription, { children: "Basic SAML configuration options" })
        ] }),
        /* @__PURE__ */ jsxs(CardContent, { className: "space-y-4", children: [
          /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
            /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", htmlFor: "provider-name", children: "Provider Name" }),
            /* @__PURE__ */ jsx(
              Input,
              {
                id: "provider-name",
                placeholder: "e.g., Okta, Azure AD, OneLogin",
                value: config.provider,
                onChange: (e) => setConfig({ ...config, provider: e.target.value })
              }
            )
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
            /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", htmlFor: "name-id-format", children: "Name ID Format" }),
            /* @__PURE__ */ jsx(
              "select",
              {
                id: "name-id-format",
                className: "w-full rounded-md border border-input bg-background px-3 py-2 text-sm",
                value: config.nameIdFormat,
                onChange: (e) => setConfig({ ...config, nameIdFormat: e.target.value }),
                children: nameIdFormats.map((format) => /* @__PURE__ */ jsx("option", { value: format.value, children: format.label }, format.value))
              }
            )
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between rounded-lg border p-4", children: [
            /* @__PURE__ */ jsxs("div", { className: "space-y-0.5", children: [
              /* @__PURE__ */ jsx("label", { className: "text-base font-medium", children: "Allow Account Creation" }),
              /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Automatically create accounts for new users authenticated via SAML" })
            ] }),
            /* @__PURE__ */ jsx(
              Switch,
              {
                checked: config.allowCreate,
                onCheckedChange: (checked) => setConfig({ ...config, allowCreate: checked })
              }
            )
          ] })
        ] })
      ] }) }),
      /* @__PURE__ */ jsxs(TabsContent, { value: "provider", className: "space-y-4", children: [
        /* @__PURE__ */ jsxs(Card, { children: [
          /* @__PURE__ */ jsxs(CardHeader, { children: [
            /* @__PURE__ */ jsx(CardTitle, { children: "Identity Provider Settings" }),
            /* @__PURE__ */ jsx(CardDescription, { children: "Configure your IdP connection details" })
          ] }),
          /* @__PURE__ */ jsxs(CardContent, { className: "space-y-4", children: [
            /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
              /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", htmlFor: "entity-id", children: "Entity ID (Issuer)" }),
              /* @__PURE__ */ jsx(
                Input,
                {
                  id: "entity-id",
                  placeholder: "https://your-idp.com/saml/metadata",
                  value: config.entityId,
                  onChange: (e) => setConfig({ ...config, entityId: e.target.value })
                }
              )
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
              /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", htmlFor: "sso-url", children: "SSO URL (Login URL)" }),
              /* @__PURE__ */ jsx(
                Input,
                {
                  id: "sso-url",
                  placeholder: "https://your-idp.com/saml/sso",
                  value: config.ssoUrl,
                  onChange: (e) => setConfig({ ...config, ssoUrl: e.target.value })
                }
              )
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
              /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", htmlFor: "certificate", children: "X.509 Certificate" }),
              /* @__PURE__ */ jsxs("div", { className: "relative", children: [
                /* @__PURE__ */ jsx(
                  "textarea",
                  {
                    id: "certificate",
                    rows: 6,
                    className: "w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono",
                    placeholder: "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWg…\n-----END CERTIFICATE-----",
                    value: config.certificate,
                    onChange: (e) => setConfig({ ...config, certificate: e.target.value })
                  }
                ),
                /* @__PURE__ */ jsxs(
                  Button,
                  {
                    variant: "outline",
                    size: "sm",
                    className: "absolute right-2 top-2",
                    onClick: () => document.getElementById("cert-upload")?.click(),
                    children: [
                      /* @__PURE__ */ jsx(Upload, { className: "mr-2 h-4 w-4" }),
                      "Upload"
                    ]
                  }
                ),
                /* @__PURE__ */ jsx(
                  "input",
                  {
                    id: "cert-upload",
                    type: "file",
                    accept: ".pem,.crt,.cer",
                    className: "hidden",
                    onChange: (e) => {
                      const file = e.target.files?.[0];
                      if (file) {
                        const reader = new FileReader();
                        reader.onload = (ev) => {
                          setConfig({ ...config, certificate: ev.target?.result });
                        };
                        reader.readAsText(file);
                      }
                    }
                  }
                )
              ] })
            ] })
          ] })
        ] }),
        /* @__PURE__ */ jsx(AnimatePresence, { children: testStatus !== "idle" && /* @__PURE__ */ jsx(
          motion.div,
          {
            initial: { opacity: 0, y: -10 },
            animate: { opacity: 1, y: 0 },
            exit: { opacity: 0, y: -10 },
            children: testStatus === "success" ? /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2 rounded-lg bg-green-50 p-4 text-green-800 dark:bg-green-900/20 dark:text-green-400", children: [
              /* @__PURE__ */ jsx(CheckCircle, { className: "h-5 w-5" }),
              /* @__PURE__ */ jsx("span", { children: "Connection test successful! SAML SSO is properly configured." })
            ] }) : /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2 rounded-lg bg-red-50 p-4 text-red-800 dark:bg-red-900/20 dark:text-red-400", children: [
              /* @__PURE__ */ jsx(AlertTriangle, { className: "h-5 w-5" }),
              /* @__PURE__ */ jsx("span", { children: "Connection test failed. Please verify your configuration." })
            ] })
          }
        ) })
      ] }),
      /* @__PURE__ */ jsx(TabsContent, { value: "metadata", className: "space-y-4", children: /* @__PURE__ */ jsxs(Card, { children: [
        /* @__PURE__ */ jsxs(CardHeader, { children: [
          /* @__PURE__ */ jsx(CardTitle, { children: "Service Provider Metadata" }),
          /* @__PURE__ */ jsx(CardDescription, { children: "Share these details with your identity provider" })
        ] }),
        /* @__PURE__ */ jsxs(CardContent, { className: "space-y-4", children: [
          /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
            /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", children: "SP Metadata URL" }),
            /* @__PURE__ */ jsxs("div", { className: "flex gap-2", children: [
              /* @__PURE__ */ jsx("code", { className: "flex-1 rounded bg-muted px-3 py-2 text-sm", children: typeof window !== "undefined" ? `${window.location.origin}/api/auth/saml/metadata` : "" }),
              /* @__PURE__ */ jsx(
                Button,
                {
                  variant: "outline",
                  size: "icon",
                  "aria-label": "Copy SP metadata URL",
                  onClick: copyMetadataUrl,
                  children: /* @__PURE__ */ jsx(Copy, { className: "h-4 w-4" })
                }
              ),
              /* @__PURE__ */ jsx(Button, { variant: "outline", size: "icon", "aria-label": "Open SP metadata", asChild: true, children: /* @__PURE__ */ jsx("a", { href: "/api/auth/saml/metadata", target: "_blank", rel: "noopener noreferrer", children: /* @__PURE__ */ jsx(ExternalLink, { className: "h-4 w-4" }) }) })
            ] })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
            /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", children: "ACS (Assertion Consumer Service) URL" }),
            /* @__PURE__ */ jsxs("div", { className: "flex gap-2", children: [
              /* @__PURE__ */ jsx("code", { className: "flex-1 rounded bg-muted px-3 py-2 text-sm", children: typeof window !== "undefined" ? `${window.location.origin}/api/auth/saml/acs` : "" }),
              /* @__PURE__ */ jsx(
                Button,
                {
                  variant: "outline",
                  size: "icon",
                  "aria-label": "Copy ACS URL",
                  onClick: copyAcsUrl,
                  children: /* @__PURE__ */ jsx(Copy, { className: "h-4 w-4" })
                }
              )
            ] })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
            /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", children: "SP Entity ID" }),
            /* @__PURE__ */ jsxs("div", { className: "flex gap-2", children: [
              /* @__PURE__ */ jsx("code", { className: "flex-1 rounded bg-muted px-3 py-2 text-sm", children: "vault-saml" }),
              /* @__PURE__ */ jsx(
                Button,
                {
                  variant: "outline",
                  size: "icon",
                  "aria-label": "Copy SP entity ID",
                  onClick: () => navigator.clipboard.writeText("vault-saml"),
                  children: /* @__PURE__ */ jsx(Copy, { className: "h-4 w-4" })
                }
              )
            ] })
          ] }),
          /* @__PURE__ */ jsx("div", { className: "pt-4", children: /* @__PURE__ */ jsxs(Button, { variant: "outline", className: "w-full", children: [
            /* @__PURE__ */ jsx(Download, { className: "mr-2 h-4 w-4" }),
            "Download SP Metadata XML"
          ] }) })
        ] })
      ] }) })
    ] }),
    /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-end gap-4", children: [
      /* @__PURE__ */ jsx(
        Button,
        {
          variant: "outline",
          onClick: handleTestConnection,
          disabled: isTesting || !config.enabled,
          children: isTesting ? /* @__PURE__ */ jsxs(Fragment, { children: [
            /* @__PURE__ */ jsx(
              motion.div,
              {
                className: "mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
              }
            ),
            "Testing…"
          ] }) : /* @__PURE__ */ jsxs(Fragment, { children: [
            /* @__PURE__ */ jsx(Shield, { className: "mr-2 h-4 w-4" }),
            "Test Connection"
          ] })
        }
      ),
      /* @__PURE__ */ jsx(Button, { onClick: handleSave, disabled: isLoading, children: isLoading ? /* @__PURE__ */ jsxs(Fragment, { children: [
        /* @__PURE__ */ jsx(
          motion.div,
          {
            className: "mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
          }
        ),
        "Saving…"
      ] }) : "Save Configuration" })
    ] })
  ] });
}
const defaultProviderConfig = {
  enabled: false,
  clientId: "",
  clientSecret: "",
  scopes: "",
  allowedDomains: ""
};
const defaultConfig = {
  google: { id: "google", ...defaultProviderConfig, scopes: "openid email profile" },
  github: { id: "github", ...defaultProviderConfig, scopes: "read:user user:email" },
  microsoft: { id: "microsoft", ...defaultProviderConfig, scopes: "openid email profile" },
  apple: { id: "apple", ...defaultProviderConfig, scopes: "name email" }
};
const oauthProviders = [
  {
    id: "google",
    name: "Google",
    description: "Sign in with Google accounts",
    icon: Chrome,
    envKey: "VITE_OAUTH_GOOGLE_ENABLED",
    defaultScopes: "openid email profile",
    docsUrl: "https://developers.google.com/identity/protocols/oauth2"
  },
  {
    id: "github",
    name: "GitHub",
    description: "Sign in with GitHub accounts",
    icon: Github,
    envKey: "VITE_OAUTH_GITHUB_ENABLED",
    defaultScopes: "read:user user:email",
    docsUrl: "https://docs.github.com/en/developers/apps/building-oauth-apps"
  },
  {
    id: "microsoft",
    name: "Microsoft",
    description: "Sign in with Microsoft/Azure AD accounts",
    icon: Building2,
    envKey: "VITE_OAUTH_MICROSOFT_ENABLED",
    defaultScopes: "openid email profile",
    docsUrl: "https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow"
  },
  {
    id: "apple",
    name: "Apple",
    description: "Sign in with Apple ID",
    icon: Apple,
    envKey: "VITE_OAUTH_APPLE_ENABLED",
    defaultScopes: "name email",
    docsUrl: "https://developer.apple.com/documentation/sign_in_with_apple"
  }
];
function isProviderEnabled(provider) {
  return env[provider.envKey] === "true";
}
function OAuthProviderSettings() {
  const [configs, setConfigs] = useState(defaultConfig);
  const [isLoading, setIsLoading] = useState(false);
  const [showSecrets, setShowSecrets] = useState(false);
  const [secretState, setSecretState] = useState({});
  const [activeProvider, setActiveProvider] = useState(null);
  const hasAnyProviderEnabled = oauthProviders.some(isProviderEnabled);
  const updateProviderConfig = (providerId, key, value) => {
    setConfigs((prev) => ({
      ...prev,
      [providerId]: { ...prev[providerId], [key]: value }
    }));
  };
  const handleSave = async () => {
    setIsLoading(true);
    try {
      await new Promise((resolve) => setTimeout(resolve, 1e3));
      setSecretState((prev) => {
        const next = { ...prev };
        oauthProviders.forEach((provider) => {
          const secret = configs[provider.id].clientSecret?.trim();
          if (secret) next[provider.id] = true;
        });
        return next;
      });
      setConfigs((prev) => {
        const next = { ...prev };
        oauthProviders.forEach((provider) => {
          if (next[provider.id].clientSecret?.trim()) {
            next[provider.id] = { ...next[provider.id], clientSecret: "" };
          }
        });
        return next;
      });
    } finally {
      setIsLoading(false);
    }
  };
  const copyRedirectUri = () => {
    navigator.clipboard.writeText(`${window.location.origin}/api/auth/callback`);
  };
  const activeProviderDef = activeProvider ? oauthProviders.find((p) => p.id === activeProvider) : null;
  const isActiveProviderEnabled = activeProviderDef ? isProviderEnabled(activeProviderDef) : false;
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxs("div", { children: [
      /* @__PURE__ */ jsx("h2", { className: "text-2xl font-bold tracking-tight", children: "OAuth Providers" }),
      /* @__PURE__ */ jsx("p", { className: "text-muted-foreground", children: "Configure social login providers for your application" })
    ] }),
    !hasAnyProviderEnabled && /* @__PURE__ */ jsx("div", { className: "rounded-lg bg-muted p-4 text-muted-foreground", children: /* @__PURE__ */ jsx("p", { className: "text-sm", children: "No OAuth providers are enabled. Set the corresponding environment variables to enable social login." }) }),
    /* @__PURE__ */ jsx("div", { className: "grid gap-4 sm:grid-cols-2", children: oauthProviders.map((provider) => {
      const isEnabled = isProviderEnabled(provider);
      const config = configs[provider.id];
      const Icon = provider.icon;
      const isActive = activeProvider === provider.id;
      return /* @__PURE__ */ jsx(
        Card,
        {
          className: cn(
            "relative cursor-pointer transition-colors",
            isEnabled ? isActive ? "border-primary bg-primary/5" : "hover:border-primary/50" : "cursor-not-allowed border-muted bg-muted/30 opacity-60"
          ),
          onClick: () => isEnabled && setActiveProvider(provider.id),
          children: /* @__PURE__ */ jsxs(CardContent, { className: "p-4", children: [
            !isEnabled && /* @__PURE__ */ jsx("div", { className: "absolute right-3 top-3", children: /* @__PURE__ */ jsx(Lock, { className: "h-4 w-4 text-muted-foreground" }) }),
            /* @__PURE__ */ jsxs("div", { className: "flex items-start gap-3", children: [
              /* @__PURE__ */ jsx(
                "div",
                {
                  className: cn(
                    "flex h-10 w-10 shrink-0 items-center justify-center rounded-lg",
                    isActive && isEnabled ? "bg-primary text-primary-foreground" : "bg-muted"
                  ),
                  children: /* @__PURE__ */ jsx(Icon, { className: "h-5 w-5" })
                }
              ),
              /* @__PURE__ */ jsxs("div", { className: "flex-1", children: [
                /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
                  /* @__PURE__ */ jsx("span", { className: "font-semibold", children: provider.name }),
                  config.enabled && isEnabled && /* @__PURE__ */ jsx(Badge, { variant: "default", className: "text-xs", children: "Active" })
                ] }),
                /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: provider.description }),
                isEnabled && config.clientId && /* @__PURE__ */ jsxs("p", { className: "mt-1 text-xs text-muted-foreground", children: [
                  "Client ID: ",
                  config.clientId.slice(0, 8),
                  "…"
                ] }),
                !isEnabled && /* @__PURE__ */ jsxs("p", { className: "mt-2 text-xs text-muted-foreground", children: [
                  "Set ",
                  provider.envKey,
                  "=true to enable"
                ] })
              ] })
            ] })
          ] })
        },
        provider.id
      );
    }) }),
    activeProvider && isActiveProviderEnabled && /* @__PURE__ */ jsx(
      motion.div,
      {
        initial: { opacity: 0, y: 10 },
        animate: { opacity: 1, y: 0 },
        children: /* @__PURE__ */ jsxs(Card, { children: [
          /* @__PURE__ */ jsxs(CardHeader, { children: [
            /* @__PURE__ */ jsxs(CardTitle, { className: "flex items-center gap-2", children: [
              (() => {
                const Icon = activeProviderDef?.icon || Globe;
                return /* @__PURE__ */ jsx(Icon, { className: "h-5 w-5" });
              })(),
              activeProviderDef?.name,
              " Configuration"
            ] }),
            /* @__PURE__ */ jsxs(CardDescription, { children: [
              "Configure your ",
              activeProviderDef?.name,
              " OAuth application credentials"
            ] })
          ] }),
          /* @__PURE__ */ jsxs(CardContent, { className: "space-y-6", children: [
            /* @__PURE__ */ jsx("div", { className: "rounded-lg bg-blue-50 p-4 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400", children: /* @__PURE__ */ jsxs("div", { className: "flex items-start gap-2", children: [
              /* @__PURE__ */ jsx(Globe, { className: "mt-0.5 h-4 w-4 shrink-0" }),
              /* @__PURE__ */ jsxs("div", { className: "text-sm", children: [
                /* @__PURE__ */ jsx("p", { className: "font-medium", children: "Redirect URI" }),
                /* @__PURE__ */ jsxs("p", { className: "mt-1", children: [
                  "Add this redirect URI to your ",
                  activeProviderDef?.name,
                  " OAuth app:"
                ] }),
                /* @__PURE__ */ jsxs("div", { className: "mt-2 flex items-center gap-2", children: [
                  /* @__PURE__ */ jsx("code", { className: "flex-1 rounded bg-blue-100 px-2 py-1 text-xs dark:bg-blue-900/40", children: typeof window !== "undefined" ? `${window.location.origin}/api/auth/callback` : "" }),
                  /* @__PURE__ */ jsx(
                    Button,
                    {
                      variant: "outline",
                      size: "icon",
                      className: "h-7 w-7",
                      onClick: copyRedirectUri,
                      "aria-label": "Copy redirect URI",
                      children: /* @__PURE__ */ jsx(Copy, { className: "h-3 w-3" })
                    }
                  )
                ] })
              ] })
            ] }) }),
            /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between rounded-lg border p-4", children: [
              /* @__PURE__ */ jsxs("div", { className: "space-y-0.5", children: [
                /* @__PURE__ */ jsxs("span", { className: "text-base font-medium", children: [
                  "Enable ",
                  activeProviderDef?.name,
                  " Login"
                ] }),
                /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground", children: [
                  "Allow users to sign in with ",
                  activeProviderDef?.name
                ] })
              ] }),
              /* @__PURE__ */ jsx(
                Switch,
                {
                  checked: configs[activeProvider].enabled,
                  onCheckedChange: (checked) => updateProviderConfig(activeProvider, "enabled", checked)
                }
              )
            ] }),
            /* @__PURE__ */ jsx("div", { className: "h-px bg-border" }),
            /* @__PURE__ */ jsxs("div", { className: "space-y-4", children: [
              /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
                /* @__PURE__ */ jsx("label", { htmlFor: "client-id", className: "text-sm font-medium leading-none", children: "Client ID" }),
                /* @__PURE__ */ jsx(
                  Input,
                  {
                    id: "client-id",
                    value: configs[activeProvider].clientId,
                    onChange: (e) => updateProviderConfig(activeProvider, "clientId", e.target.value),
                    placeholder: `Enter your ${activeProviderDef?.name} Client ID`
                  }
                )
              ] }),
              /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
                /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
                  /* @__PURE__ */ jsx("label", { htmlFor: "client-secret", className: "text-sm font-medium leading-none", children: "Client Secret" }),
                  secretState[activeProvider] && !configs[activeProvider].clientSecret && /* @__PURE__ */ jsx(Badge, { variant: "outline", className: "text-xs", children: "Set" })
                ] }),
                /* @__PURE__ */ jsx(
                  Input,
                  {
                    id: "client-secret",
                    type: showSecrets ? "text" : "password",
                    value: configs[activeProvider].clientSecret,
                    onChange: (e) => updateProviderConfig(activeProvider, "clientSecret", e.target.value),
                    placeholder: secretState[activeProvider] && !configs[activeProvider].clientSecret ? "******** (set)" : `Enter your ${activeProviderDef?.name} Client Secret`
                  }
                )
              ] }),
              /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
                /* @__PURE__ */ jsx("label", { htmlFor: "scopes", className: "text-sm font-medium leading-none", children: "Scopes" }),
                /* @__PURE__ */ jsx(
                  Input,
                  {
                    id: "scopes",
                    value: configs[activeProvider].scopes,
                    onChange: (e) => updateProviderConfig(activeProvider, "scopes", e.target.value),
                    placeholder: activeProviderDef?.defaultScopes
                  }
                ),
                /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: "Space-separated list of OAuth scopes" })
              ] }),
              /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
                /* @__PURE__ */ jsx("label", { htmlFor: "allowed-domains", className: "text-sm font-medium leading-none", children: "Allowed Domains (Optional)" }),
                /* @__PURE__ */ jsx(
                  Input,
                  {
                    id: "allowed-domains",
                    value: configs[activeProvider].allowedDomains,
                    onChange: (e) => updateProviderConfig(activeProvider, "allowedDomains", e.target.value),
                    placeholder: "example.com, company.org"
                  }
                ),
                /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: "Restrict login to specific email domains (comma-separated)" })
              ] }),
              /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
                /* @__PURE__ */ jsx(
                  Switch,
                  {
                    id: "show-secrets",
                    checked: showSecrets,
                    onCheckedChange: setShowSecrets
                  }
                ),
                /* @__PURE__ */ jsx("label", { htmlFor: "show-secrets", className: "text-sm font-medium leading-none", children: "Show Secrets" })
              ] })
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2 text-sm text-muted-foreground", children: [
              /* @__PURE__ */ jsx(CheckCircle, { className: "h-4 w-4" }),
              /* @__PURE__ */ jsxs(
                "a",
                {
                  href: activeProviderDef?.docsUrl,
                  target: "_blank",
                  rel: "noopener noreferrer",
                  className: "hover:underline",
                  children: [
                    "View ",
                    activeProviderDef?.name,
                    " OAuth documentation"
                  ]
                }
              )
            ] })
          ] })
        ] })
      }
    ),
    activeProvider && !isActiveProviderEnabled && /* @__PURE__ */ jsx("div", { className: "rounded-lg bg-amber-50 p-4 text-amber-800 dark:bg-amber-900/20 dark:text-amber-400", children: /* @__PURE__ */ jsxs("p", { className: "text-sm font-medium", children: [
      "This provider is disabled. Set ",
      activeProviderDef?.envKey,
      "=true to enable."
    ] }) }),
    /* @__PURE__ */ jsx("div", { className: "flex items-center justify-end gap-4", children: /* @__PURE__ */ jsx(Button, { onClick: handleSave, disabled: isLoading, children: isLoading ? /* @__PURE__ */ jsxs(Fragment, { children: [
      /* @__PURE__ */ jsx(motion.div, { className: "mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" }),
      "Saving…"
    ] }) : "Save Configuration" }) })
  ] });
}
function SsoSettingsPage() {
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "SSO & Integrations", description: "Configure SAML and OAuth providers", breadcrumbs: [{
      label: "Settings",
      href: "/settings"
    }, {
      label: "SSO"
    }] }),
    /* @__PURE__ */ jsxs(Tabs, { defaultValue: "saml", className: "space-y-6", children: [
      /* @__PURE__ */ jsxs(TabsList, { children: [
        /* @__PURE__ */ jsx(TabsTrigger, { value: "saml", children: "SAML" }),
        /* @__PURE__ */ jsx(TabsTrigger, { value: "oauth", children: "OAuth" })
      ] }),
      /* @__PURE__ */ jsx(TabsContent, { value: "saml", className: "space-y-4", children: /* @__PURE__ */ jsx(Card, { className: "p-6", children: /* @__PURE__ */ jsx(SamlConfiguration, {}) }) }),
      /* @__PURE__ */ jsx(TabsContent, { value: "oauth", className: "space-y-4", children: /* @__PURE__ */ jsx(Card, { className: "p-6", children: /* @__PURE__ */ jsx(OAuthProviderSettings, {}) }) })
    ] })
  ] });
}
export {
  SsoSettingsPage as component
};
