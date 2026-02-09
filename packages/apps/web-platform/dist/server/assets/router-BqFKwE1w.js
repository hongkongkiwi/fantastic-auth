import { jsx, jsxs, Fragment } from "react/jsx-runtime";
import { useNavigate, useLocation, Link, createRootRoute, useRouterState, HeadContent, Scripts, Outlet, createFileRoute, lazyRouteComponent, createRouter } from "@tanstack/react-router";
import * as React from "react";
import { useState, useEffect, useCallback, useMemo, createContext, useContext, useRef } from "react";
import { createEnv } from "@t3-oss/env-core";
import { z } from "zod";
import { Toaster as Toaster$1, toast as toast$1 } from "sonner";
import { useReducedMotion, motion, AnimatePresence } from "framer-motion";
import { Loader2, Shield, LayoutDashboard, Building2, CreditCard, ClipboardList, Server, Settings, ChevronRight, ChevronLeft, LogOut, X, Menu, Users, Lock, BarChart3, Bell, LifeBuoy, Plus, Search, Command, ArrowRight, ExternalLink, Key, Home, Webhook, Moon, Check, FileText, ShieldAlert, AlertTriangle, Clock, Eye } from "lucide-react";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { Slot } from "@radix-ui/react-slot";
import { cva } from "class-variance-authority";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { Command as Command$1 } from "cmdk";
import * as CheckboxPrimitive from "@radix-ui/react-checkbox";
import * as LabelPrimitive from "@radix-ui/react-label";
import * as Sentry from "@sentry/react";
const __vite_import_meta_env__ = { "BASE_URL": "/", "DEV": false, "MODE": "production", "PROD": true, "SSR": true, "TSS_CLIENT_OUTPUT_DIR": "dist/client", "TSS_DEV_SERVER": "false", "TSS_ROUTER_BASEPATH": "", "TSS_SERVER_FN_BASE": "/_serverFn/" };
const env = createEnv({
  clientPrefix: "VITE_",
  client: {
    VITE_INTERNAL_API_BASE_URL: z.string().url().optional(),
    VITE_SENTRY_DSN: z.string().url().optional(),
    VITE_SENTRY_ENVIRONMENT: z.string().min(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE: z.coerce.number().min(0).max(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE_HIGH: z.coerce.number().min(0).max(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE_HIGH_ROUTES: z.string().min(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE_LOW: z.coerce.number().min(0).max(1).optional(),
    VITE_SENTRY_TRACES_SAMPLE_RATE_LOW_ROUTES: z.string().min(1).optional(),
    VITE_LOG_LEVEL: z.enum(["trace", "debug", "info", "warn", "error", "fatal"]).optional(),
    VITE_ENABLE_SUPPORT_IMPERSONATION: z.enum(["true", "false"]).optional().default("false"),
    // CAPTCHA Providers - Set to 'true' to enable each provider
    VITE_CAPTCHA_RECAPTCHA_V2_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_CAPTCHA_RECAPTCHA_V3_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_CAPTCHA_HCAPTCHA_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_CAPTCHA_TURNSTILE_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    // OAuth Providers - Set to 'true' to enable each provider
    VITE_OAUTH_GOOGLE_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_OAUTH_GITHUB_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_OAUTH_MICROSOFT_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_OAUTH_APPLE_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    // Email Providers - Set to 'true' to enable each provider
    VITE_EMAIL_SMTP_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_EMAIL_SENDGRID_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_EMAIL_MAILGUN_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_EMAIL_AWS_SES_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_EMAIL_POSTMARK_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_EMAIL_RESEND_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    // SMS Providers - Set to 'true' to enable each provider
    VITE_SMS_TWILIO_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_SMS_MESSAGE_BIRD_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_SMS_VONAGE_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    // Storage Providers - Set to 'true' to enable each provider
    VITE_STORAGE_S3_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_STORAGE_R2_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_STORAGE_AZURE_BLOB_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    // Payment Providers - Set to 'true' to enable each provider
    VITE_PAYMENT_STRIPE_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_PAYMENT_PADDLE_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    // Analytics - Set to 'true' to enable
    VITE_ANALYTICS_POSTHOG_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_ANALYTICS_PLAUSIBLE_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    // Security - Set to 'true' to enable
    VITE_SECURITY_HIBP_ENABLED: z.enum(["true", "false"]).optional().default("false"),
    VITE_SECURITY_MAXMIND_ENABLED: z.enum(["true", "false"]).optional().default("false")
  },
  runtimeEnv: __vite_import_meta_env__,
  emptyStringAsUndefined: true
});
class AuthMfaRequiredError extends Error {
  code = "MFA_REQUIRED";
  mfaToken;
  constructor(message, mfaToken) {
    super(message);
    this.name = "AuthMfaRequiredError";
    this.mfaToken = mfaToken;
  }
}
const SESSION_COOKIE_NAME = "vault_ui_session";
const INTERNAL_API_BASE_URL = env.VITE_INTERNAL_API_BASE_URL || "/api/v1";
const AuthContext = createContext(null);
const parseCookie = (cookieHeader, name) => {
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(";");
  for (const part of parts) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) {
      return decodeURIComponent(rest.join("="));
    }
  }
  return null;
};
const buildApiUrl = (path) => {
  const normalizedBase = INTERNAL_API_BASE_URL.endsWith("/") ? INTERNAL_API_BASE_URL.slice(0, -1) : INTERNAL_API_BASE_URL;
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  if (/^https?:\/\//.test(normalizedBase)) {
    return `${normalizedBase}${normalizedPath}`;
  }
  const origin = typeof window !== "undefined" ? window.location.origin : "http://localhost";
  return new URL(`${normalizedBase}${normalizedPath}`, origin).toString();
};
function useProvideAuth() {
  const navigate = useNavigate();
  const [state, setState] = useState({
    user: null,
    isAuthenticated: false,
    isLoading: true,
    error: null,
    csrfToken: null
  });
  useEffect(() => {
    const checkSession = async () => {
      const sessionCookie = parseCookie(document.cookie, SESSION_COOKIE_NAME);
      if (!sessionCookie) {
        setState((prev) => ({ ...prev, isLoading: false }));
        return;
      }
      try {
        const response = await fetch(buildApiUrl("/auth/verify"), {
          credentials: "include"
        });
        if (!response.ok) {
          setState((prev) => ({ ...prev, isLoading: false }));
          return;
        }
        const data = await response.json();
        setState((prev) => ({
          ...prev,
          user: data.user,
          isAuthenticated: true,
          isLoading: false,
          csrfToken: data.csrfToken
        }));
      } catch {
        setState((prev) => ({ ...prev, isLoading: false }));
      }
    };
    void checkSession();
  }, []);
  const refreshCsrfToken = useCallback(async () => {
    try {
      const response = await fetch(buildApiUrl("/auth/csrf"), {
        credentials: "include"
      });
      if (response.ok) {
        const data = await response.json();
        setState((prev) => ({ ...prev, csrfToken: data.csrfToken }));
      }
    } catch (error) {
      console.error("Failed to refresh CSRF token:", error);
    }
  }, []);
  const login = useCallback(
    async (email, password, mfaCode, mfaToken) => {
      setState((prev) => ({ ...prev, isLoading: true, error: null }));
      try {
        const response = await fetch(buildApiUrl("/auth/login"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ email, password, mfaCode, mfaToken })
        });
        const data = await response.json();
        const requiresMfa = Boolean(data?.mfaRequired || data?.requires_mfa);
        if (requiresMfa) {
          throw new AuthMfaRequiredError(
            "Multi-factor authentication code required.",
            data?.mfaToken || data?.mfa_token
          );
        }
        if (!response.ok) {
          throw new Error(data.message || "Login failed");
        }
        setState({
          user: data.user,
          isAuthenticated: true,
          isLoading: false,
          error: null,
          csrfToken: data.csrfToken
        });
        navigate({ to: "/" });
      } catch (error) {
        setState((prev) => ({
          ...prev,
          isLoading: false,
          error: error instanceof Error ? error.message : "Login failed"
        }));
        throw error;
      }
    },
    [navigate]
  );
  const logout = useCallback(async () => {
    setState((prev) => ({ ...prev, isLoading: true }));
    try {
      await fetch(buildApiUrl("/auth/logout"), {
        method: "POST",
        credentials: "include",
        headers: {
          "X-CSRF-Token": state.csrfToken || ""
        }
      });
    } catch (error) {
      console.error("Logout error:", error);
    } finally {
      setState({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
        csrfToken: null
      });
      navigate({ to: "/login" });
    }
  }, [navigate, state.csrfToken]);
  const clearError = useCallback(() => {
    setState((prev) => ({ ...prev, error: null }));
  }, []);
  return useMemo(
    () => ({
      ...state,
      login,
      logout,
      clearError,
      refreshCsrfToken
    }),
    [state, login, logout, clearError, refreshCsrfToken]
  );
}
function AuthProvider({ children }) {
  const value = useProvideAuth();
  return /* @__PURE__ */ jsx(AuthContext.Provider, { value, children });
}
function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
const ThemeContext = React.createContext(void 0);
const THEME_STORAGE_KEY = "vault-theme";
function ThemeProvider({
  children,
  defaultTheme = "system"
}) {
  const [theme, setThemeState] = React.useState(() => {
    if (typeof window === "undefined") return defaultTheme;
    return localStorage.getItem(THEME_STORAGE_KEY) || defaultTheme;
  });
  const [resolvedTheme, setResolvedTheme] = React.useState("light");
  React.useEffect(() => {
    const root = window.document.documentElement;
    const applyTheme = (newTheme) => {
      root.classList.remove("light", "dark");
      root.classList.add(newTheme);
      setResolvedTheme(newTheme);
    };
    if (theme === "system") {
      const systemTheme = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
      applyTheme(systemTheme);
      const listener = (e) => {
        applyTheme(e.matches ? "dark" : "light");
      };
      window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", listener);
      return () => window.matchMedia("(prefers-color-scheme: dark)").removeEventListener("change", listener);
    } else {
      applyTheme(theme);
    }
  }, [theme]);
  const setTheme = (newTheme) => {
    localStorage.setItem(THEME_STORAGE_KEY, newTheme);
    setThemeState(newTheme);
  };
  const toggleTheme = () => {
    if (theme === "dark") {
      setTheme("light");
    } else if (theme === "light") {
      setTheme("dark");
    } else {
      setTheme(resolvedTheme === "dark" ? "light" : "dark");
    }
  };
  return /* @__PURE__ */ jsx(ThemeContext.Provider, { value: { theme, setTheme, resolvedTheme, toggleTheme }, children });
}
function useTheme() {
  const context = React.useContext(ThemeContext);
  if (context === void 0) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return context;
}
function ThemeToggle() {
  const { resolvedTheme, toggleTheme } = useTheme();
  return /* @__PURE__ */ jsx(
    "button",
    {
      type: "button",
      onClick: toggleTheme,
      className: "p-2 rounded-lg hover:bg-accent transition-colors",
      "aria-label": `Switch to ${resolvedTheme === "dark" ? "light" : "dark"} mode`,
      children: resolvedTheme === "dark" ? /* @__PURE__ */ jsx("svg", { className: "h-5 w-5", fill: "none", viewBox: "0 0 24 24", stroke: "currentColor", children: /* @__PURE__ */ jsx(
        "path",
        {
          strokeLinecap: "round",
          strokeLinejoin: "round",
          strokeWidth: 2,
          d: "M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
        }
      ) }) : /* @__PURE__ */ jsx("svg", { className: "h-5 w-5", fill: "none", viewBox: "0 0 24 24", stroke: "currentColor", children: /* @__PURE__ */ jsx(
        "path",
        {
          strokeLinecap: "round",
          strokeLinejoin: "round",
          strokeWidth: 2,
          d: "M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
        }
      ) })
    }
  );
}
const Toaster = ({ ...props }) => {
  return /* @__PURE__ */ jsx(
    Toaster$1,
    {
      theme: "system",
      className: "toaster group",
      toastOptions: {
        classNames: {
          toast: "group toast group-[.toaster]:bg-background group-[.toaster]:text-foreground group-[.toaster]:border-border group-[.toaster]:shadow-elevated",
          description: "group-[.toast]:text-muted-foreground",
          actionButton: "group-[.toast]:bg-primary group-[.toast]:text-primary-foreground",
          cancelButton: "group-[.toast]:bg-muted group-[.toast]:text-muted-foreground",
          success: "group-[.toaster]:border-success group-[.toaster]:text-success",
          error: "group-[.toaster]:border-destructive group-[.toaster]:text-destructive",
          warning: "group-[.toaster]:border-warning group-[.toaster]:text-warning",
          info: "group-[.toaster]:border-info group-[.toaster]:text-info"
        }
      },
      ...props
    }
  );
};
const toast = {
  success: (message, description) => toast$1.success(message, description ? { description } : void 0),
  error: (message, description) => toast$1.error(message, description ? { description } : void 0),
  warning: (message, description) => toast$1.warning(message, description ? { description } : void 0),
  info: (message, description) => toast$1.info(message, description ? { description } : void 0),
  loading: (message) => toast$1.loading(message),
  promise: (promise, messages) => toast$1.promise(promise, {
    loading: messages.loading,
    success: messages.success,
    error: messages.error
  })
};
const RealtimeContext = React.createContext(void 0);
function RealtimeProvider({ children }) {
  const [isConnected, setIsConnected] = React.useState(false);
  const [lastMessage, setLastMessage] = React.useState(null);
  const eventSourceRef = React.useRef(null);
  const handlersRef = React.useRef(/* @__PURE__ */ new Set());
  const subscribe = React.useCallback((handler) => {
    handlersRef.current.add(handler);
    return () => {
      handlersRef.current.delete(handler);
    };
  }, []);
  const sendMessage = React.useCallback((message) => {
    const fullMessage = {
      ...message,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
    handlersRef.current.forEach((handler) => handler(fullMessage));
  }, []);
  React.useEffect(() => {
    const connect = () => {
      setIsConnected(true);
      const interval = setInterval(() => {
        const messages = [
          "tenant.created",
          "user.login",
          "ping"
        ];
        const randomType = messages[Math.floor(Math.random() * messages.length)];
        if (randomType !== "ping") {
          const message = {
            type: randomType,
            data: {},
            timestamp: (/* @__PURE__ */ new Date()).toISOString()
          };
          setLastMessage(message);
          handlersRef.current.forEach((handler) => handler(message));
          if (randomType === "tenant.created") {
            toast.info(
              "New tenant created",
              "A new tenant has been added to the platform"
            );
          }
        }
      }, 3e4);
      return () => clearInterval(interval);
    };
    const cleanup = connect();
    return () => {
      cleanup?.();
      eventSourceRef.current?.close();
    };
  }, []);
  return /* @__PURE__ */ jsx(RealtimeContext.Provider, { value: { isConnected, lastMessage, subscribe, sendMessage }, children });
}
const PWAContext = React.createContext(null);
function PWAProvider({ children }) {
  const [isInstalled, setIsInstalled] = React.useState(false);
  const [canInstall, setCanInstall] = React.useState(false);
  const [deferredPrompt, setDeferredPrompt] = React.useState(null);
  const [isOnline, setIsOnline] = React.useState(navigator.onLine);
  const [updateAvailable, setUpdateAvailable] = React.useState(false);
  const [waitingWorker, setWaitingWorker] = React.useState(null);
  React.useEffect(() => {
    if (window.matchMedia("(display-mode: standalone)").matches) {
      setIsInstalled(true);
    }
  }, []);
  React.useEffect(() => {
    const handleBeforeInstallPrompt = (e) => {
      e.preventDefault();
      setDeferredPrompt(e);
      setCanInstall(true);
    };
    const handleAppInstalled = () => {
      setIsInstalled(true);
      setCanInstall(false);
      setDeferredPrompt(null);
      toast.success("Vault Admin installed successfully!");
    };
    window.addEventListener("beforeinstallprompt", handleBeforeInstallPrompt);
    window.addEventListener("appinstalled", handleAppInstalled);
    return () => {
      window.removeEventListener("beforeinstallprompt", handleBeforeInstallPrompt);
      window.removeEventListener("appinstalled", handleAppInstalled);
    };
  }, []);
  React.useEffect(() => {
    const handleOnline = () => {
      setIsOnline(true);
      toast.success("You are back online");
    };
    const handleOffline = () => {
      setIsOnline(false);
      toast.info("You are offline. Some features may be limited.");
    };
    window.addEventListener("online", handleOnline);
    window.addEventListener("offline", handleOffline);
    return () => {
      window.removeEventListener("online", handleOnline);
      window.removeEventListener("offline", handleOffline);
    };
  }, []);
  React.useEffect(() => {
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.ready.then((registration) => {
        if (registration.waiting) {
          setUpdateAvailable(true);
          setWaitingWorker(registration.waiting);
        }
        registration.addEventListener("updatefound", () => {
          const newWorker = registration.installing;
          if (newWorker) {
            newWorker.addEventListener("statechange", () => {
              if (newWorker.state === "installed" && navigator.serviceWorker.controller) {
                setUpdateAvailable(true);
                setWaitingWorker(newWorker);
                toast.info("Update available! Refresh to apply.");
              }
            });
          }
        });
      });
      navigator.serviceWorker.addEventListener("message", (event) => {
        if (event.data?.type === "UPDATE_AVAILABLE") {
          setUpdateAvailable(true);
          toast.info("A new version is available!");
        }
      });
    }
  }, []);
  const install = async () => {
    if (!deferredPrompt) return;
    deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    if (outcome === "accepted") {
      setDeferredPrompt(null);
      setCanInstall(false);
    }
  };
  const applyUpdate = () => {
    if (waitingWorker) {
      waitingWorker.postMessage({ type: "SKIP_WAITING" });
      window.location.reload();
    }
  };
  const value = {
    isInstalled,
    canInstall,
    install,
    isOnline,
    updateAvailable,
    applyUpdate
  };
  return /* @__PURE__ */ jsx(PWAContext.Provider, { value, children });
}
function usePWA() {
  const context = React.useContext(PWAContext);
  if (!context) {
    throw new Error("usePWA must be used within a PWAProvider");
  }
  return context;
}
function InstallPrompt() {
  const { canInstall, install, isInstalled } = usePWA();
  const [isVisible, setIsVisible] = React.useState(false);
  React.useEffect(() => {
    if (canInstall && !isInstalled) {
      const timer = setTimeout(() => setIsVisible(true), 3e3);
      return () => clearTimeout(timer);
    }
  }, [canInstall, isInstalled]);
  const handleDismiss = () => {
    setIsVisible(false);
    localStorage.setItem("install-prompt-dismissed", Date.now().toString());
  };
  if (!isVisible) return null;
  return /* @__PURE__ */ jsx("div", { className: "fixed bottom-4 left-1/2 -translate-x-1/2 z-50 animate-slide-up", children: /* @__PURE__ */ jsxs("div", { className: "bg-background border rounded-lg shadow-lg p-4 flex items-center gap-4 max-w-sm", children: [
    /* @__PURE__ */ jsx("div", { className: "p-2 bg-primary/10 rounded-lg", children: /* @__PURE__ */ jsx("svg", { className: "h-6 w-6 text-primary", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", children: /* @__PURE__ */ jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: 2, d: "M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" }) }) }),
    /* @__PURE__ */ jsxs("div", { className: "flex-1", children: [
      /* @__PURE__ */ jsx("p", { className: "font-medium", children: "Install Vault Admin" }),
      /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Add to home screen for quick access" })
    ] }),
    /* @__PURE__ */ jsx(
      "button",
      {
        type: "button",
        onClick: install,
        className: "px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90",
        children: "Install"
      }
    ),
    /* @__PURE__ */ jsx(
      "button",
      {
        type: "button",
        onClick: handleDismiss,
        className: "p-1 text-muted-foreground hover:text-foreground",
        "aria-label": "Dismiss",
        children: /* @__PURE__ */ jsx("svg", { className: "h-4 w-4", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", children: /* @__PURE__ */ jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: 2, d: "M6 18L18 6M6 6l12 12" }) })
      }
    )
  ] }) });
}
function OfflineIndicator() {
  const { isOnline } = usePWA();
  if (isOnline) return null;
  return /* @__PURE__ */ jsx("div", { className: "fixed top-0 left-0 right-0 z-50 bg-amber-500 text-white text-center py-1 text-sm", children: "You are offline. Some features may be limited." });
}
function UpdateNotification() {
  const { updateAvailable, applyUpdate } = usePWA();
  if (!updateAvailable) return null;
  return /* @__PURE__ */ jsx("div", { className: "fixed bottom-4 right-4 z-50 animate-slide-up", children: /* @__PURE__ */ jsxs("div", { className: "bg-background border rounded-lg shadow-lg p-4 flex items-center gap-4", children: [
    /* @__PURE__ */ jsx("div", { className: "p-2 bg-blue-100 rounded-lg", children: /* @__PURE__ */ jsx("svg", { className: "h-5 w-5 text-blue-600", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", children: /* @__PURE__ */ jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: 2, d: "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" }) }) }),
    /* @__PURE__ */ jsxs("div", { children: [
      /* @__PURE__ */ jsx("p", { className: "font-medium", children: "Update Available" }),
      /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Refresh to get the latest version" })
    ] }),
    /* @__PURE__ */ jsx(
      "button",
      {
        type: "button",
        onClick: applyUpdate,
        className: "px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90",
        children: "Update"
      }
    )
  ] }) });
}
function cn(...inputs) {
  return twMerge(clsx(inputs));
}
function formatDate(date, options) {
  const d = typeof date === "string" ? new Date(date) : date;
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    ...options
  }).format(d);
}
function formatDateTime(date) {
  return formatDate(date, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
}
function formatNumber(num, options) {
  return new Intl.NumberFormat("en-US", options).format(num);
}
function formatCurrency(amount, currency = "USD") {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency
  }).format(amount);
}
function formatRelativeTime(date) {
  const d = typeof date === "string" ? new Date(date) : date;
  const now = /* @__PURE__ */ new Date();
  const diffInSeconds = Math.floor((now.getTime() - d.getTime()) / 1e3);
  if (Number.isNaN(diffInSeconds)) return "invalid date";
  if (Math.abs(diffInSeconds) < 5) return "just now";
  const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  const thresholds = [
    { limit: 60, unit: "second", divisor: 1 },
    { limit: 3600, unit: "minute", divisor: 60 },
    { limit: 86400, unit: "hour", divisor: 3600 },
    { limit: 604800, unit: "day", divisor: 86400 },
    { limit: 2629800, unit: "week", divisor: 604800 },
    { limit: 31557600, unit: "month", divisor: 2629800 },
    { limit: Infinity, unit: "year", divisor: 31557600 }
  ];
  const abs = Math.abs(diffInSeconds);
  const threshold = thresholds.find((t) => abs < t.limit) ?? thresholds[thresholds.length - 1];
  const value = Math.round(diffInSeconds / threshold.divisor);
  return rtf.format(-value, threshold.unit);
}
const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors transition-shadow transition-transform duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 active:scale-[0.98]",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground shadow-sm hover:bg-primary-600 hover:shadow-glow",
        destructive: "bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/90",
        outline: "border border-input bg-background shadow-sm hover:bg-accent hover:text-accent-foreground",
        secondary: "bg-secondary text-secondary-foreground shadow-sm hover:bg-secondary/80",
        ghost: "hover:bg-accent hover:text-accent-foreground",
        link: "text-primary underline-offset-4 hover:underline",
        soft: "bg-primary/10 text-primary hover:bg-primary/20"
      },
      size: {
        default: "h-10 px-4 py-2",
        sm: "h-8 rounded-md px-3 text-xs",
        lg: "h-11 rounded-md px-8",
        icon: "h-10 w-10",
        "icon-sm": "h-8 w-8",
        "icon-lg": "h-11 w-11"
      },
      fullWidth: {
        true: "w-full"
      }
    },
    defaultVariants: {
      variant: "default",
      size: "default"
    }
  }
);
const Button = React.forwardRef(
  ({
    className,
    variant,
    size,
    fullWidth,
    asChild = false,
    isLoading,
    leftIcon,
    rightIcon,
    children,
    disabled,
    ...props
  }, ref) => {
    const useSlot = asChild && React.isValidElement(children) && children.type !== React.Fragment;
    const Comp = useSlot ? Slot : "button";
    const content = useSlot ? children : isLoading ? /* @__PURE__ */ jsxs(Fragment, { children: [
      /* @__PURE__ */ jsx(Loader2, { className: "h-4 w-4 animate-spin" }),
      children
    ] }) : /* @__PURE__ */ jsxs(Fragment, { children: [
      leftIcon && /* @__PURE__ */ jsx("span", { className: "flex items-center", children: leftIcon }),
      children,
      rightIcon && /* @__PURE__ */ jsx("span", { className: "flex items-center", children: rightIcon })
    ] });
    return /* @__PURE__ */ jsx(
      Comp,
      {
        className: cn(buttonVariants({ variant, size, fullWidth, className })),
        ref,
        disabled: disabled || isLoading,
        ...props,
        children: content
      }
    );
  }
);
Button.displayName = "Button";
const navItems$1 = [
  {
    title: "Dashboard",
    href: "/",
    icon: LayoutDashboard
  },
  {
    title: "Tenants",
    href: "/tenants",
    icon: Building2,
    children: [
      { title: "All Tenants", href: "/tenants" },
      { title: "Create Tenant", href: "/tenants/create" }
    ]
  },
  {
    title: "Billing",
    href: "/billing",
    icon: CreditCard,
    children: [
      { title: "Subscriptions", href: "/billing/subscriptions" },
      { title: "Invoices", href: "/billing/invoices" }
    ]
  },
  {
    title: "Platform Audit",
    href: "/audit",
    icon: ClipboardList
  },
  {
    title: "System",
    href: "/system",
    icon: Server
  },
  {
    title: "Settings",
    href: "/settings",
    icon: Settings,
    children: [
      { title: "General", href: "/settings" },
      { title: "Security", href: "/settings/security" },
      { title: "API Keys", href: "/settings/api-keys" },
      { title: "SSO & Integrations", href: "/settings/sso" },
      { title: "Webhooks", href: "/settings/webhooks" }
    ]
  }
];
function Sidebar({ isCollapsed, onToggle, onLogout, user, items }) {
  const location = useLocation();
  const [expandedItems, setExpandedItems] = React.useState(["Tenants"]);
  const prefersReducedMotion = useReducedMotion();
  const navList = items ?? navItems$1;
  const toggleExpand = (title) => {
    setExpandedItems(
      (prev) => prev.includes(title) ? prev.filter((t) => t !== title) : [...prev, title]
    );
  };
  const isActive = (href) => {
    if (href === "/") {
      return location.pathname === "/";
    }
    return location.pathname === href || location.pathname.startsWith(`${href}/`);
  };
  return /* @__PURE__ */ jsxs(
    motion.aside,
    {
      initial: false,
      animate: { width: isCollapsed ? 80 : 260 },
      transition: prefersReducedMotion ? { duration: 0 } : { duration: 0.3, ease: [0.34, 1.56, 0.64, 1] },
      className: cn(
        "fixed left-0 top-0 z-40 h-screen border-r bg-sidebar flex flex-col",
        isCollapsed && "items-center"
      ),
      children: [
        /* @__PURE__ */ jsx("div", { className: "flex h-16 items-center justify-between px-4 border-b border-sidebar-border", children: /* @__PURE__ */ jsxs(Link, { to: "/", preload: "intent", className: "flex items-center gap-3 overflow-hidden", children: [
          /* @__PURE__ */ jsx("div", { className: "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary", children: /* @__PURE__ */ jsx(Shield, { className: "h-5 w-5 text-primary-foreground" }) }),
          /* @__PURE__ */ jsx(AnimatePresence, { mode: "wait", children: !isCollapsed && /* @__PURE__ */ jsx(
            motion.span,
            {
              initial: prefersReducedMotion ? false : { opacity: 0, x: -10 },
              animate: { opacity: 1, x: 0 },
              exit: prefersReducedMotion ? { opacity: 0 } : { opacity: 0, x: -10 },
              className: "font-semibold text-sidebar-foreground whitespace-nowrap",
              children: "Vault Admin"
            }
          ) })
        ] }) }),
        /* @__PURE__ */ jsx("nav", { className: "flex-1 overflow-y-auto py-4 px-3", children: /* @__PURE__ */ jsx("ul", { className: "space-y-1", children: navList.map((item) => {
          const active = isActive(item.href);
          const hasChildren = item.children && item.children.length > 0;
          const isExpanded = expandedItems.includes(item.title);
          return /* @__PURE__ */ jsx("li", { children: hasChildren && !isCollapsed ? /* @__PURE__ */ jsxs("div", { className: "space-y-1", children: [
            /* @__PURE__ */ jsxs(
              "button",
              {
                type: "button",
                onClick: () => toggleExpand(item.title),
                className: cn(
                  "w-full flex items-center justify-between gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary",
                  active ? "bg-sidebar-accent text-sidebar-accent-foreground" : "text-sidebar-foreground hover:bg-sidebar-accent/50"
                ),
                children: [
                  /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3", children: [
                    /* @__PURE__ */ jsx(item.icon, { className: "h-5 w-5 shrink-0", "aria-hidden": "true" }),
                    /* @__PURE__ */ jsx("span", { children: item.title })
                  ] }),
                  /* @__PURE__ */ jsx(
                    motion.div,
                    {
                      animate: { rotate: isExpanded ? 90 : 0 },
                      transition: prefersReducedMotion ? { duration: 0 } : { duration: 0.2 },
                      children: /* @__PURE__ */ jsx(ChevronRight, { className: "h-4 w-4", "aria-hidden": "true" })
                    }
                  )
                ]
              }
            ),
            /* @__PURE__ */ jsx(AnimatePresence, { children: isExpanded && /* @__PURE__ */ jsx(
              motion.ul,
              {
                initial: prefersReducedMotion ? false : { height: 0, opacity: 0 },
                animate: { height: "auto", opacity: 1 },
                exit: prefersReducedMotion ? { opacity: 0 } : { height: 0, opacity: 0 },
                transition: prefersReducedMotion ? { duration: 0 } : { duration: 0.2 },
                className: "overflow-hidden pl-10 space-y-1",
                children: item.children?.map((child) => /* @__PURE__ */ jsx("li", { children: /* @__PURE__ */ jsx(
                  Link,
                  {
                    to: child.href,
                    preload: "intent",
                    className: cn(
                      "block rounded-lg px-3 py-2 text-sm transition-colors",
                      "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary",
                      isActive(child.href) ? "bg-sidebar-accent text-sidebar-accent-foreground" : "text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground"
                    ),
                    children: child.title
                  }
                ) }, child.href))
              }
            ) })
          ] }) : /* @__PURE__ */ jsxs(
            Link,
            {
              to: item.href,
              preload: "intent",
              className: cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary",
                active ? "bg-sidebar-accent text-sidebar-accent-foreground" : "text-sidebar-foreground hover:bg-sidebar-accent/50",
                isCollapsed && "justify-center"
              ),
              title: isCollapsed ? item.title : void 0,
              "aria-label": isCollapsed ? item.title : void 0,
              children: [
                /* @__PURE__ */ jsx(item.icon, { className: "h-5 w-5 shrink-0", "aria-hidden": "true" }),
                /* @__PURE__ */ jsx(AnimatePresence, { mode: "wait", children: !isCollapsed && /* @__PURE__ */ jsx(
                  motion.span,
                  {
                    initial: prefersReducedMotion ? false : { opacity: 0, width: 0 },
                    animate: { opacity: 1, width: "auto" },
                    exit: prefersReducedMotion ? { opacity: 0 } : { opacity: 0, width: 0 },
                    className: "whitespace-nowrap overflow-hidden",
                    children: item.title
                  }
                ) }),
                item.badge && !isCollapsed && /* @__PURE__ */ jsx("span", { className: "ml-auto text-xs bg-primary text-primary-foreground px-2 py-0.5 rounded-full", children: item.badge })
              ]
            }
          ) }, item.title);
        }) }) }),
        /* @__PURE__ */ jsxs("div", { className: "border-t border-sidebar-border p-3 space-y-3", children: [
          /* @__PURE__ */ jsxs(
            "div",
            {
              className: cn(
                "flex items-center gap-3 rounded-lg px-3 py-2",
                isCollapsed && "justify-center px-2"
              ),
              children: [
                /* @__PURE__ */ jsx("div", { className: "h-8 w-8 shrink-0 rounded-full bg-primary/10 flex items-center justify-center", children: /* @__PURE__ */ jsx("span", { className: "text-sm font-medium text-primary", children: user?.name?.[0] || user?.email?.[0] || "A" }) }),
                /* @__PURE__ */ jsx(AnimatePresence, { mode: "wait", children: !isCollapsed && /* @__PURE__ */ jsxs(
                  motion.div,
                  {
                    initial: prefersReducedMotion ? false : { opacity: 0, width: 0 },
                    animate: { opacity: 1, width: "auto" },
                    exit: prefersReducedMotion ? { opacity: 0 } : { opacity: 0, width: 0 },
                    className: "flex-1 min-w-0 overflow-hidden",
                    children: [
                      /* @__PURE__ */ jsx("p", { className: "text-sm font-medium text-sidebar-foreground truncate", children: user?.name || "Admin User" }),
                      /* @__PURE__ */ jsx("p", { className: "text-xs text-sidebar-foreground/60 truncate", children: user?.email || "admin@vault.local" })
                    ]
                  }
                ) })
              ]
            }
          ),
          /* @__PURE__ */ jsx(
            Button,
            {
              variant: "ghost",
              size: isCollapsed ? "icon" : "default",
              onClick: onToggle,
              className: cn(
                "w-full",
                isCollapsed && "justify-center"
              ),
              "aria-label": isCollapsed ? "Expand sidebar" : "Collapse sidebar",
              leftIcon: isCollapsed ? /* @__PURE__ */ jsx(ChevronRight, { className: "h-4 w-4" }) : /* @__PURE__ */ jsx(ChevronLeft, { className: "h-4 w-4" }),
              children: !isCollapsed && "Collapse"
            }
          ),
          onLogout && /* @__PURE__ */ jsx(
            Button,
            {
              variant: "ghost",
              size: isCollapsed ? "icon" : "default",
              onClick: onLogout,
              className: cn(
                "w-full text-destructive hover:text-destructive hover:bg-destructive/10",
                isCollapsed && "justify-center"
              ),
              "aria-label": isCollapsed ? "Log out" : void 0,
              leftIcon: /* @__PURE__ */ jsx(LogOut, { className: "h-4 w-4" }),
              children: !isCollapsed && "Logout"
            }
          )
        ] })
      ]
    }
  );
}
const navItems = [
  {
    title: "Dashboard",
    href: "/",
    icon: LayoutDashboard
  },
  {
    title: "Tenants",
    href: "/tenants",
    icon: Building2
  },
  {
    title: "Users",
    href: "/users",
    icon: Users
  },
  {
    title: "Roles",
    href: "/roles",
    icon: Lock
  },
  {
    title: "Usage",
    href: "/usage",
    icon: BarChart3
  },
  {
    title: "Billing",
    href: "/billing",
    icon: CreditCard
  },
  {
    title: "Audit",
    href: "/audit",
    icon: ClipboardList
  },
  {
    title: "Notifications",
    href: "/notifications",
    icon: Bell
  },
  {
    title: "Support",
    href: "/support",
    icon: LifeBuoy
  },
  {
    title: "System",
    href: "/system",
    icon: Server
  },
  {
    title: "Settings",
    href: "/settings",
    icon: Settings
  }
];
function MobileNav({ isOpen, onClose, onLogout, user }) {
  const location = useLocation();
  const prefersReducedMotion = useReducedMotion();
  const isActive = (href) => {
    if (href === "/") {
      return location.pathname === "/";
    }
    return location.pathname === href || location.pathname.startsWith(`${href}/`);
  };
  return /* @__PURE__ */ jsxs(Fragment, { children: [
    /* @__PURE__ */ jsx(
      "button",
      {
        type: "button",
        onClick: () => isOpen ? onClose() : null,
        className: "lg:hidden fixed top-4 left-4 z-50 p-2 rounded-lg bg-background border shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary",
        "aria-label": isOpen ? "Close navigation menu" : "Open navigation menu",
        children: isOpen ? /* @__PURE__ */ jsx(X, { className: "h-5 w-5", "aria-hidden": "true" }) : /* @__PURE__ */ jsx(Menu, { className: "h-5 w-5", "aria-hidden": "true" })
      }
    ),
    /* @__PURE__ */ jsx(AnimatePresence, { children: isOpen && /* @__PURE__ */ jsx(
      motion.button,
      {
        initial: { opacity: 0 },
        animate: { opacity: 1 },
        exit: { opacity: 0 },
        onClick: onClose,
        className: "fixed inset-0 z-40 bg-black/50 backdrop-blur-sm lg:hidden",
        "aria-label": "Close navigation menu",
        type: "button",
        transition: prefersReducedMotion ? { duration: 0 } : { duration: 0.2 }
      }
    ) }),
    /* @__PURE__ */ jsx(AnimatePresence, { children: isOpen && /* @__PURE__ */ jsxs(
      motion.div,
      {
        initial: { x: "-100%" },
        animate: { x: 0 },
        exit: { x: "-100%" },
        transition: prefersReducedMotion ? { duration: 0 } : { type: "spring", damping: 25, stiffness: 200 },
        className: "fixed left-0 top-0 z-50 h-full w-72 bg-sidebar border-r lg:hidden",
        children: [
          /* @__PURE__ */ jsxs("div", { className: "flex h-16 items-center justify-between px-4 border-b border-sidebar-border", children: [
            /* @__PURE__ */ jsxs(Link, { to: "/", preload: "intent", className: "flex items-center gap-3", onClick: onClose, children: [
              /* @__PURE__ */ jsx("div", { className: "flex h-9 w-9 items-center justify-center rounded-lg bg-primary", children: /* @__PURE__ */ jsx(Shield, { className: "h-5 w-5 text-primary-foreground" }) }),
              /* @__PURE__ */ jsx("span", { className: "font-semibold text-sidebar-foreground", children: "Vault Admin" })
            ] }),
            /* @__PURE__ */ jsx(
              "button",
              {
                type: "button",
                onClick: onClose,
                className: "p-2 rounded-lg text-sidebar-foreground hover:bg-sidebar-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary",
                "aria-label": "Close navigation menu",
                children: /* @__PURE__ */ jsx(X, { className: "h-5 w-5", "aria-hidden": "true" })
              }
            )
          ] }),
          /* @__PURE__ */ jsx("nav", { className: "flex-1 overflow-y-auto py-4 px-3", children: /* @__PURE__ */ jsx("ul", { className: "space-y-1", children: navItems.map((item) => {
            const active = isActive(item.href);
            return /* @__PURE__ */ jsx("li", { children: /* @__PURE__ */ jsxs(
              Link,
              {
                to: item.href,
                preload: "intent",
                onClick: onClose,
                className: cn(
                  "flex items-center gap-3 rounded-lg px-3 py-3 text-sm font-medium transition-colors",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary",
                  active ? "bg-sidebar-accent text-sidebar-accent-foreground" : "text-sidebar-foreground hover:bg-sidebar-accent/50"
                ),
                children: [
                  /* @__PURE__ */ jsx(item.icon, { className: "h-5 w-5 shrink-0", "aria-hidden": "true" }),
                  /* @__PURE__ */ jsx("span", { children: item.title }),
                  /* @__PURE__ */ jsx(ChevronRight, { className: "h-4 w-4 ml-auto opacity-50", "aria-hidden": "true" })
                ]
              }
            ) }, item.title);
          }) }) }),
          /* @__PURE__ */ jsxs("div", { className: "border-t border-sidebar-border p-4 space-y-3", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3 rounded-lg px-3 py-2", children: [
              /* @__PURE__ */ jsx("div", { className: "h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center", children: /* @__PURE__ */ jsx("span", { className: "text-sm font-medium text-primary", children: user?.name?.[0] || user?.email?.[0] || "A" }) }),
              /* @__PURE__ */ jsxs("div", { className: "flex-1 min-w-0", children: [
                /* @__PURE__ */ jsx("p", { className: "text-sm font-medium text-sidebar-foreground truncate", children: user?.name || "Admin User" }),
                /* @__PURE__ */ jsx("p", { className: "text-xs text-sidebar-foreground/60 truncate", children: user?.email || "admin@vault.local" })
              ] })
            ] }),
            onLogout && /* @__PURE__ */ jsx(
              Button,
              {
                variant: "ghost",
                onClick: onLogout,
                className: "w-full justify-start text-destructive hover:text-destructive hover:bg-destructive/10",
                leftIcon: /* @__PURE__ */ jsx(LogOut, { className: "h-4 w-4" }),
                children: "Logout"
              }
            )
          ] })
        ]
      }
    ) })
  ] });
}
function MobileBottomNav() {
  const location = useLocation();
  const prefersReducedMotion = useReducedMotion();
  const isActive = (href) => {
    if (href === "/") {
      return location.pathname === "/";
    }
    return location.pathname === href || location.pathname.startsWith(`${href}/`);
  };
  const mainItems = navItems.slice(0, 5);
  return /* @__PURE__ */ jsx(
    motion.nav,
    {
      className: "lg:hidden fixed bottom-0 left-0 right-0 z-40 bg-background border-t safe-area-pb",
      initial: prefersReducedMotion ? false : { y: 20, opacity: 0 },
      animate: { y: 0, opacity: 1 },
      transition: prefersReducedMotion ? { duration: 0 } : { duration: 0.2 },
      children: /* @__PURE__ */ jsx("div", { className: "flex items-center justify-around", children: mainItems.map((item) => {
        const active = isActive(item.href);
        return /* @__PURE__ */ jsxs(
          Link,
          {
            to: item.href,
            preload: "intent",
            className: cn(
              "flex flex-col items-center justify-center py-2 px-3 min-w-[60px]",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary",
              active ? "text-primary" : "text-muted-foreground"
            ),
            children: [
              /* @__PURE__ */ jsx(item.icon, { className: cn("h-5 w-5", active && "stroke-[2.5px]"), "aria-hidden": "true" }),
              /* @__PURE__ */ jsx("span", { className: "text-[10px] mt-1 font-medium", children: item.title })
            ]
          },
          item.title
        );
      }) })
    }
  );
}
const Dialog = DialogPrimitive.Root;
const DialogPortal = DialogPrimitive.Portal;
const DialogOverlay = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  DialogPrimitive.Overlay,
  {
    ref,
    className: cn(
      "fixed inset-0 z-50 bg-black/60 backdrop-blur-sm overscroll-contain data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
      className
    ),
    ...props
  }
));
DialogOverlay.displayName = DialogPrimitive.Overlay.displayName;
const DialogContent = React.forwardRef(({ className, children, showClose = true, size = "default", ...props }, ref) => /* @__PURE__ */ jsxs(DialogPortal, { children: [
  /* @__PURE__ */ jsx(DialogOverlay, {}),
  /* @__PURE__ */ jsxs(
    DialogPrimitive.Content,
    {
      ref,
      className: cn(
        "fixed left-[50%] top-[50%] z-50 grid w-full translate-x-[-50%] translate-y-[-50%] gap-4 border bg-background p-6 shadow-elevated duration-200 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[state=closed]:slide-out-to-left-1/2 data-[state=closed]:slide-out-to-top-[48%] data-[state=open]:slide-in-from-left-1/2 data-[state=open]:slide-in-from-top-[48%] sm:rounded-lg",
        size === "sm" && "max-w-sm",
        size === "default" && "max-w-lg",
        size === "lg" && "max-w-2xl",
        size === "xl" && "max-w-4xl",
        size === "full" && "max-w-[95vw] h-[90vh]",
        className
      ),
      ...props,
      children: [
        children,
        showClose && /* @__PURE__ */ jsxs(DialogPrimitive.Close, { className: "absolute right-4 top-4 rounded-sm opacity-70 ring-offset-background transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:pointer-events-none data-[state=open]:bg-accent data-[state=open]:text-muted-foreground", children: [
          /* @__PURE__ */ jsx(X, { className: "h-4 w-4" }),
          /* @__PURE__ */ jsx("span", { className: "sr-only", children: "Close" })
        ] })
      ]
    }
  )
] }));
DialogContent.displayName = DialogPrimitive.Content.displayName;
const DialogHeader = ({
  className,
  ...props
}) => /* @__PURE__ */ jsx(
  "div",
  {
    className: cn(
      "flex flex-col space-y-1.5 text-center sm:text-left",
      className
    ),
    ...props
  }
);
DialogHeader.displayName = "DialogHeader";
const DialogFooter = ({
  className,
  ...props
}) => /* @__PURE__ */ jsx(
  "div",
  {
    className: cn(
      "flex flex-col-reverse sm:flex-row sm:justify-end sm:space-x-2",
      className
    ),
    ...props
  }
);
DialogFooter.displayName = "DialogFooter";
const DialogTitle = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  DialogPrimitive.Title,
  {
    ref,
    className: cn(
      "text-lg font-semibold leading-none tracking-tight",
      className
    ),
    ...props
  }
));
DialogTitle.displayName = DialogPrimitive.Title.displayName;
const DialogDescription = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  DialogPrimitive.Description,
  {
    ref,
    className: cn("text-sm text-muted-foreground", className),
    ...props
  }
));
DialogDescription.displayName = DialogPrimitive.Description.displayName;
function ConfirmDialog({
  isOpen,
  onClose,
  onConfirm,
  title,
  description,
  confirmText = "Confirm",
  cancelText = "Cancel",
  variant = "default",
  isLoading
}) {
  return /* @__PURE__ */ jsx(Dialog, { open: isOpen, onOpenChange: onClose, children: /* @__PURE__ */ jsxs(DialogContent, { size: "sm", showClose: false, children: [
    /* @__PURE__ */ jsxs(DialogHeader, { children: [
      /* @__PURE__ */ jsx(DialogTitle, { children: title }),
      /* @__PURE__ */ jsx(DialogDescription, { children: description })
    ] }),
    /* @__PURE__ */ jsxs(DialogFooter, { className: "mt-4", children: [
      /* @__PURE__ */ jsx(
        "button",
        {
          type: "button",
          onClick: onClose,
          className: "inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 border border-input bg-background hover:bg-accent hover:text-accent-foreground h-10 px-4 py-2",
          children: cancelText
        }
      ),
      /* @__PURE__ */ jsx(
        "button",
        {
          type: "button",
          onClick: onConfirm,
          disabled: isLoading,
          className: cn(
            "inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 h-10 px-4 py-2",
            variant === "destructive" ? "bg-destructive text-destructive-foreground hover:bg-destructive/90" : "bg-primary text-primary-foreground hover:bg-primary/90"
          ),
          children: isLoading ? "Loading…" : confirmText
        }
      )
    ] })
  ] }) });
}
function GlobalSearch({ items }) {
  const [isOpen, setIsOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const [selectedIndex, setSelectedIndex] = React.useState(0);
  const navigate = useNavigate();
  const { logout } = useAuth();
  const prefersReducedMotion = useReducedMotion();
  const inputRef = React.useRef(null);
  const deferredQuery = React.useDeferredValue(query);
  React.useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setIsOpen(true);
      }
      if (e.key === "Escape") {
        setIsOpen(false);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, []);
  const searchItems = items ?? [
    // Navigation
    {
      id: "dashboard",
      title: "Dashboard",
      icon: LayoutDashboard,
      href: "/",
      section: "Navigation"
    },
    {
      id: "tenants",
      title: "Tenants",
      icon: Building2,
      href: "/tenants",
      section: "Navigation"
    },
    {
      id: "create-tenant",
      title: "Create New Tenant",
      subtitle: "Add a new tenant to the platform",
      icon: Plus,
      href: "/tenants/create",
      section: "Navigation"
    },
    {
      id: "users",
      title: "Users",
      icon: Users,
      href: "/users",
      section: "Navigation"
    },
    {
      id: "roles",
      title: "Roles & Permissions",
      icon: Lock,
      href: "/roles",
      section: "Navigation"
    },
    {
      id: "usage",
      title: "Usage & Analytics",
      icon: BarChart3,
      href: "/usage",
      section: "Navigation"
    },
    {
      id: "billing",
      title: "Billing",
      icon: CreditCard,
      href: "/billing",
      section: "Navigation"
    },
    {
      id: "audit",
      title: "Audit Logs",
      icon: ClipboardList,
      href: "/audit",
      section: "Navigation"
    },
    {
      id: "notifications",
      title: "Notifications",
      icon: Bell,
      href: "/notifications",
      section: "Navigation"
    },
    {
      id: "support",
      title: "Support",
      icon: LifeBuoy,
      href: "/support",
      section: "Navigation"
    },
    {
      id: "system",
      title: "System",
      icon: Server,
      href: "/system",
      section: "Navigation"
    },
    {
      id: "settings",
      title: "Settings",
      icon: Settings,
      href: "/settings",
      section: "Navigation"
    },
    // Actions
    {
      id: "logout",
      title: "Logout",
      subtitle: "Sign out of your account",
      icon: LogOut,
      action: () => logout(),
      section: "Actions"
    }
  ];
  const filteredItems = React.useMemo(() => {
    if (!deferredQuery.trim()) return searchItems;
    const lowerQuery = deferredQuery.toLowerCase();
    return searchItems.filter(
      (item) => item.title.toLowerCase().includes(lowerQuery) || item.subtitle?.toLowerCase().includes(lowerQuery)
    );
  }, [deferredQuery]);
  const groupedItems = React.useMemo(() => {
    const groups = {};
    filteredItems.forEach((item) => {
      if (!groups[item.section]) groups[item.section] = [];
      groups[item.section].push(item);
    });
    return groups;
  }, [filteredItems]);
  const flatItems = React.useMemo(() => {
    return Object.values(groupedItems).flat();
  }, [groupedItems]);
  const handleSelect = (item) => {
    setIsOpen(false);
    setQuery("");
    if (item.action) {
      item.action();
    } else if (item.href) {
      navigate({ to: item.href });
    }
  };
  React.useEffect(() => {
    const handleKeyDown = (e) => {
      if (!isOpen) return;
      switch (e.key) {
        case "ArrowDown":
          e.preventDefault();
          setSelectedIndex(
            (prev) => prev < flatItems.length - 1 ? prev + 1 : prev
          );
          break;
        case "ArrowUp":
          e.preventDefault();
          setSelectedIndex((prev) => prev > 0 ? prev - 1 : prev);
          break;
        case "Enter":
          e.preventDefault();
          if (flatItems[selectedIndex]) {
            handleSelect(flatItems[selectedIndex]);
          }
          break;
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, flatItems, selectedIndex]);
  React.useEffect(() => {
    setSelectedIndex(0);
  }, [query]);
  React.useEffect(() => {
    if (!isOpen) return;
    const isFinePointer = window.matchMedia?.("(pointer: fine)")?.matches ?? false;
    if (isFinePointer) {
      inputRef.current?.focus();
    }
  }, [isOpen]);
  return /* @__PURE__ */ jsxs(Fragment, { children: [
    /* @__PURE__ */ jsxs(
      "button",
      {
        type: "button",
        onClick: () => setIsOpen(true),
        className: "flex items-center gap-2 px-3 py-2 rounded-lg bg-muted hover:bg-accent transition-colors text-sm text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary",
        "aria-label": "Open global search",
        children: [
          /* @__PURE__ */ jsx(Search, { className: "h-4 w-4", "aria-hidden": "true" }),
          /* @__PURE__ */ jsx("span", { className: "hidden sm:inline", children: "Search…" }),
          /* @__PURE__ */ jsxs("kbd", { className: "hidden sm:inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-background text-xs font-mono", children: [
            /* @__PURE__ */ jsx(Command, { className: "h-3 w-3", "aria-hidden": "true" }),
            /* @__PURE__ */ jsx("span", { children: "K" })
          ] })
        ]
      }
    ),
    /* @__PURE__ */ jsx(Dialog, { open: isOpen, onOpenChange: setIsOpen, children: /* @__PURE__ */ jsxs(DialogContent, { className: "max-w-2xl p-0 gap-0 overflow-hidden", showClose: false, children: [
      /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3 px-4 py-4 border-b", children: [
        /* @__PURE__ */ jsx(Search, { className: "h-5 w-5 text-muted-foreground", "aria-hidden": "true" }),
        /* @__PURE__ */ jsx(
          "input",
          {
            type: "text",
            placeholder: "Search commands, pages, or actions…",
            className: "flex-1 bg-transparent text-lg placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background",
            value: query,
            onChange: (e) => setQuery(e.target.value),
            "aria-label": "Search",
            name: "global-search",
            autoComplete: "off",
            ref: inputRef
          }
        ),
        /* @__PURE__ */ jsx("kbd", { className: "hidden sm:inline-flex items-center gap-1 px-2 py-1 rounded bg-muted text-xs font-mono", children: "ESC" })
      ] }),
      /* @__PURE__ */ jsx("div", { className: "max-h-[400px] overflow-y-auto py-2", children: flatItems.length === 0 ? /* @__PURE__ */ jsxs("div", { className: "flex flex-col items-center justify-center py-12 text-center", children: [
        /* @__PURE__ */ jsx(Search, { className: "h-12 w-12 text-muted-foreground/50 mb-4", "aria-hidden": "true" }),
        /* @__PURE__ */ jsx("p", { className: "text-muted-foreground", children: "No results found" }),
        /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground/70", children: "Try searching for something else" })
      ] }) : Object.entries(groupedItems).map(([section, items2]) => /* @__PURE__ */ jsxs("div", { className: "px-2", children: [
        /* @__PURE__ */ jsx("div", { className: "px-3 py-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider", children: section }),
        items2.map((item, index) => {
          const globalIndex = flatItems.findIndex((i) => i.id === item.id);
          const isSelected = globalIndex === selectedIndex;
          return /* @__PURE__ */ jsxs(
            motion.button,
            {
              onClick: () => handleSelect(item),
              onMouseEnter: () => setSelectedIndex(globalIndex),
              className: cn(
                "w-full flex items-center gap-3 px-3 py-3 rounded-lg text-left transition-colors",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary",
                isSelected ? "bg-primary text-primary-foreground" : "hover:bg-accent"
              ),
              initial: prefersReducedMotion ? false : { opacity: 0, y: 5 },
              animate: { opacity: 1, y: 0 },
              transition: prefersReducedMotion ? { duration: 0 } : { delay: index * 0.02 },
              children: [
                /* @__PURE__ */ jsx(
                  item.icon,
                  {
                    className: cn(
                      "h-5 w-5",
                      isSelected ? "text-primary-foreground" : "text-muted-foreground"
                    ),
                    "aria-hidden": "true"
                  }
                ),
                /* @__PURE__ */ jsxs("div", { className: "flex-1 min-w-0", children: [
                  /* @__PURE__ */ jsx("p", { className: cn("font-medium", isSelected && "text-primary-foreground"), children: item.title }),
                  item.subtitle && /* @__PURE__ */ jsx(
                    "p",
                    {
                      className: cn(
                        "text-sm truncate",
                        isSelected ? "text-primary-foreground/80" : "text-muted-foreground"
                      ),
                      children: item.subtitle
                    }
                  )
                ] }),
                item.shortcut && /* @__PURE__ */ jsx(
                  "kbd",
                  {
                    className: cn(
                      "px-2 py-1 rounded text-xs font-mono",
                      isSelected ? "bg-primary-foreground/20" : "bg-muted"
                    ),
                    children: item.shortcut
                  }
                ),
                isSelected && /* @__PURE__ */ jsx(ArrowRight, { className: "h-4 w-4", "aria-hidden": "true" })
              ]
            },
            item.id
          );
        })
      ] }, section)) }),
      /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between px-4 py-3 border-t bg-muted/50 text-xs text-muted-foreground", children: [
        /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-4", children: [
          /* @__PURE__ */ jsxs("span", { className: "flex items-center gap-1", children: [
            /* @__PURE__ */ jsx("kbd", { className: "px-1.5 py-0.5 rounded bg-background border", children: "↑" }),
            /* @__PURE__ */ jsx("kbd", { className: "px-1.5 py-0.5 rounded bg-background border", children: "↓" }),
            /* @__PURE__ */ jsx("span", { children: "to navigate" })
          ] }),
          /* @__PURE__ */ jsxs("span", { className: "flex items-center gap-1", children: [
            /* @__PURE__ */ jsx("kbd", { className: "px-1.5 py-0.5 rounded bg-background border", children: "↵" }),
            /* @__PURE__ */ jsx("span", { children: "to select" })
          ] })
        ] }),
        /* @__PURE__ */ jsxs("span", { children: [
          flatItems.length,
          " results"
        ] })
      ] })
    ] }) })
  ] });
}
function CommandPalette({ open, onOpenChange }) {
  const navigate = useNavigate();
  const { logout } = useAuth();
  const [search, setSearch] = React.useState("");
  const [pages, setPages] = React.useState([]);
  const activePage = pages[pages.length - 1];
  const inputRef = React.useRef(null);
  React.useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [open]);
  React.useEffect(() => {
    const down = (e) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        onOpenChange(!open);
      }
    };
    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, [open, onOpenChange]);
  const pushPage = (page) => {
    setPages([...pages, page]);
  };
  const popPage = () => {
    setPages(pages.slice(0, -1));
  };
  const goTo = (href) => {
    navigate({ to: href });
    onOpenChange(false);
    setSearch("");
    setPages([]);
  };
  const mainCommands = [
    // Navigation
    {
      id: "dashboard",
      title: "Dashboard",
      subtitle: "Go to dashboard",
      icon: /* @__PURE__ */ jsx(Home, { className: "h-4 w-4" }),
      shortcut: ["G", "D"],
      href: "/",
      section: "Navigation"
    },
    {
      id: "tenants",
      title: "Tenants",
      subtitle: "Manage platform tenants",
      icon: /* @__PURE__ */ jsx(Building2, { className: "h-4 w-4" }),
      shortcut: ["G", "T"],
      href: "/tenants",
      section: "Navigation"
    },
    {
      id: "users",
      title: "Users",
      subtitle: "Manage platform users",
      icon: /* @__PURE__ */ jsx(Users, { className: "h-4 w-4" }),
      shortcut: ["G", "U"],
      href: "/users",
      section: "Navigation"
    },
    {
      id: "roles",
      title: "Roles & Permissions",
      subtitle: "Manage access control",
      icon: /* @__PURE__ */ jsx(Lock, { className: "h-4 w-4" }),
      shortcut: ["G", "R"],
      href: "/roles",
      section: "Navigation"
    },
    {
      id: "usage",
      title: "Usage & Analytics",
      subtitle: "Platform usage and exports",
      icon: /* @__PURE__ */ jsx(BarChart3, { className: "h-4 w-4" }),
      shortcut: ["G", "Y"],
      href: "/usage",
      section: "Navigation"
    },
    {
      id: "billing",
      title: "Billing",
      subtitle: "Subscriptions and invoices",
      icon: /* @__PURE__ */ jsx(CreditCard, { className: "h-4 w-4" }),
      shortcut: ["G", "B"],
      href: "/billing",
      section: "Navigation"
    },
    {
      id: "audit",
      title: "Audit Logs",
      subtitle: "View platform activity",
      icon: /* @__PURE__ */ jsx(ClipboardList, { className: "h-4 w-4" }),
      shortcut: ["G", "A"],
      href: "/audit",
      section: "Navigation"
    },
    {
      id: "notifications-nav",
      title: "Notifications",
      subtitle: "System alerts and updates",
      icon: /* @__PURE__ */ jsx(Bell, { className: "h-4 w-4" }),
      shortcut: ["G", "N"],
      href: "/notifications",
      section: "Navigation"
    },
    {
      id: "support",
      title: "Support",
      subtitle: "Tickets and incidents",
      icon: /* @__PURE__ */ jsx(LifeBuoy, { className: "h-4 w-4" }),
      shortcut: ["G", "P"],
      href: "/support",
      section: "Navigation"
    },
    {
      id: "system",
      title: "System",
      subtitle: "Health and feature flags",
      icon: /* @__PURE__ */ jsx(Server, { className: "h-4 w-4" }),
      shortcut: ["G", "M"],
      href: "/system",
      section: "Navigation"
    },
    {
      id: "settings",
      title: "Settings",
      subtitle: "Configure platform",
      icon: /* @__PURE__ */ jsx(Settings, { className: "h-4 w-4" }),
      shortcut: ["G", "S"],
      href: "/settings",
      section: "Navigation"
    },
    // Quick Actions
    {
      id: "create-tenant",
      title: "Create Tenant",
      subtitle: "Add a new tenant to the platform",
      icon: /* @__PURE__ */ jsx(Plus, { className: "h-4 w-4" }),
      shortcut: ["C", "T"],
      href: "/tenants/create",
      section: "Quick Actions"
    },
    {
      id: "api-keys",
      title: "API Keys",
      subtitle: "Manage API access tokens",
      icon: /* @__PURE__ */ jsx(Key, { className: "h-4 w-4" }),
      action: () => pushPage("api-keys"),
      section: "Quick Actions"
    },
    {
      id: "webhooks",
      title: "Webhooks",
      subtitle: "Configure webhook endpoints",
      icon: /* @__PURE__ */ jsx(Webhook, { className: "h-4 w-4" }),
      href: "/settings/webhooks",
      section: "Quick Actions"
    },
    {
      id: "notifications",
      title: "Notifications",
      subtitle: "View recent notifications",
      icon: /* @__PURE__ */ jsx(Bell, { className: "h-4 w-4" }),
      href: "/notifications",
      section: "Quick Actions"
    },
    // Settings
    {
      id: "security-settings",
      title: "Security Settings",
      subtitle: "MFA, sessions, password",
      icon: /* @__PURE__ */ jsx(Shield, { className: "h-4 w-4" }),
      href: "/settings/security",
      section: "Settings"
    },
    {
      id: "theme",
      title: "Toggle Theme",
      subtitle: "Switch between light and dark mode",
      icon: /* @__PURE__ */ jsx(Moon, { className: "h-4 w-4" }),
      shortcut: ["T", "T"],
      action: () => {
        onOpenChange(false);
      },
      section: "Settings"
    },
    // Account
    {
      id: "logout",
      title: "Logout",
      subtitle: "Sign out of your account",
      icon: /* @__PURE__ */ jsx(LogOut, { className: "h-4 w-4" }),
      shortcut: ["⇧", "Q"],
      action: () => {
        logout();
        onOpenChange(false);
      },
      section: "Account"
    }
  ];
  const apiKeyCommands = [
    {
      id: "back",
      title: "Back",
      subtitle: "Return to main menu",
      icon: /* @__PURE__ */ jsx(Command, { className: "h-4 w-4" }),
      action: popPage,
      section: "Navigation"
    },
    {
      id: "view-api-keys",
      title: "View API Keys",
      subtitle: "See all configured API keys",
      icon: /* @__PURE__ */ jsx(Key, { className: "h-4 w-4" }),
      action: () => {
        navigate({ to: "/settings/api-keys" });
        onOpenChange(false);
      },
      section: "API Keys"
    },
    {
      id: "generate-key",
      title: "Generate New Key",
      subtitle: "Create a new API key",
      icon: /* @__PURE__ */ jsx(Plus, { className: "h-4 w-4" }),
      action: () => {
        navigate({ to: "/settings/api-keys" });
        onOpenChange(false);
      },
      section: "API Keys"
    }
  ];
  const commands = activePage === "api-keys" ? apiKeyCommands : mainCommands;
  const sections = [...new Set(commands.map((c) => c.section))];
  const handleKeyDown = (e) => {
    if (!activePage) {
      for (const cmd of mainCommands) {
        if (cmd.shortcut && cmd.shortcut.length === 2) {
          const [, second] = cmd.shortcut;
          if (e.key.toUpperCase() === second && e.shiftKey) {
            if (cmd.href) {
              goTo(cmd.href);
              return;
            } else if (cmd.action) {
              cmd.action();
              return;
            }
          }
        }
      }
    }
    if (e.key === "Backspace" && !search && activePage) {
      e.preventDefault();
      popPage();
    }
  };
  return /* @__PURE__ */ jsx(AnimatePresence, { children: open && /* @__PURE__ */ jsxs(Fragment, { children: [
    /* @__PURE__ */ jsx(
      motion.div,
      {
        initial: { opacity: 0 },
        animate: { opacity: 1 },
        exit: { opacity: 0 },
        onClick: () => onOpenChange(false),
        className: "fixed inset-0 z-50 bg-black/50 backdrop-blur-sm"
      }
    ),
    /* @__PURE__ */ jsx(
      motion.div,
      {
        initial: { opacity: 0, scale: 0.95, y: 10 },
        animate: { opacity: 1, scale: 1, y: 0 },
        exit: { opacity: 0, scale: 0.95, y: 10 },
        transition: { duration: 0.15 },
        className: "fixed left-1/2 top-[20%] z-50 w-full max-w-2xl -translate-x-1/2",
        children: /* @__PURE__ */ jsxs(
          Command$1,
          {
            className: "overflow-hidden rounded-xl border bg-popover shadow-2xl",
            onKeyDown: handleKeyDown,
            children: [
              /* @__PURE__ */ jsxs("div", { className: "flex items-center border-b px-4", children: [
                /* @__PURE__ */ jsx(Search, { className: "mr-2 h-4 w-4 shrink-0 text-muted-foreground" }),
                /* @__PURE__ */ jsx(
                  Command$1.Input,
                  {
                    ref: inputRef,
                    value: search,
                    onValueChange: setSearch,
                    placeholder: activePage ? "Search..." : "Type a command or search...",
                    className: "flex h-12 w-full rounded-md bg-transparent py-3 text-sm outline-none placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50"
                  }
                ),
                activePage && /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-1 text-xs text-muted-foreground", children: [
                  /* @__PURE__ */ jsx("kbd", { className: "rounded bg-muted px-1.5 py-0.5", children: "←" }),
                  /* @__PURE__ */ jsx("span", { children: "Back" })
                ] })
              ] }),
              /* @__PURE__ */ jsxs(Command$1.List, { className: "max-h-[60vh] overflow-y-auto p-2", children: [
                /* @__PURE__ */ jsxs(Command$1.Empty, { className: "py-6 text-center text-sm text-muted-foreground", children: [
                  'No results found for "',
                  search,
                  '"'
                ] }),
                sections.map((section) => {
                  const sectionCommands = commands.filter((c) => c.section === section);
                  if (sectionCommands.length === 0) return null;
                  return /* @__PURE__ */ jsxs(
                    Command$1.Group,
                    {
                      heading: section,
                      className: "overflow-hidden p-1 text-foreground",
                      children: [
                        /* @__PURE__ */ jsx("div", { className: "px-2 py-1.5 text-xs font-medium text-muted-foreground", children: section }),
                        sectionCommands.map((cmd) => /* @__PURE__ */ jsxs(
                          Command$1.Item,
                          {
                            value: `${cmd.title} ${cmd.subtitle} ${cmd.keywords?.join(" ") || ""}`,
                            onSelect: () => {
                              if (cmd.action) {
                                cmd.action();
                              } else if (cmd.href) {
                                goTo(cmd.href);
                              }
                            },
                            className: cn(
                              "relative flex cursor-pointer select-none items-center rounded-sm px-2 py-2.5 text-sm outline-none",
                              "data-[selected=true]:bg-accent data-[selected=true]:text-accent-foreground",
                              "hover:bg-accent hover:text-accent-foreground"
                            ),
                            children: [
                              /* @__PURE__ */ jsxs("div", { className: "flex flex-1 items-center gap-3", children: [
                                cmd.icon && /* @__PURE__ */ jsx("div", { className: "flex h-8 w-8 items-center justify-center rounded-md bg-muted", children: cmd.icon }),
                                /* @__PURE__ */ jsxs("div", { className: "flex flex-col", children: [
                                  /* @__PURE__ */ jsx("span", { className: "font-medium", children: cmd.title }),
                                  cmd.subtitle && /* @__PURE__ */ jsx("span", { className: "text-xs text-muted-foreground", children: cmd.subtitle })
                                ] })
                              ] }),
                              cmd.shortcut && /* @__PURE__ */ jsx("div", { className: "flex items-center gap-1", children: cmd.shortcut.map((key, i) => /* @__PURE__ */ jsx(
                                "kbd",
                                {
                                  className: "rounded bg-muted px-1.5 py-0.5 text-xs font-mono",
                                  children: key
                                },
                                i
                              )) }),
                              cmd.href && !cmd.shortcut && /* @__PURE__ */ jsx(ExternalLink, { className: "h-3 w-3 text-muted-foreground" })
                            ]
                          },
                          cmd.id
                        ))
                      ]
                    },
                    section
                  );
                })
              ] }),
              /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between border-t px-4 py-2 text-xs text-muted-foreground", children: [
                /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-4", children: [
                  /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-1", children: [
                    /* @__PURE__ */ jsx("kbd", { className: "rounded bg-muted px-1.5 py-0.5", children: "↑↓" }),
                    /* @__PURE__ */ jsx("span", { children: "Navigate" })
                  ] }),
                  /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-1", children: [
                    /* @__PURE__ */ jsx("kbd", { className: "rounded bg-muted px-1.5 py-0.5", children: "↵" }),
                    /* @__PURE__ */ jsx("span", { children: "Select" })
                  ] }),
                  activePage && /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-1", children: [
                    /* @__PURE__ */ jsx("kbd", { className: "rounded bg-muted px-1.5 py-0.5", children: "←" }),
                    /* @__PURE__ */ jsx("span", { children: "Back" })
                  ] })
                ] }),
                /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-1", children: [
                  /* @__PURE__ */ jsx("kbd", { className: "rounded bg-muted px-1.5 py-0.5", children: "⌘" }),
                  /* @__PURE__ */ jsx("kbd", { className: "rounded bg-muted px-1.5 py-0.5", children: "K" }),
                  /* @__PURE__ */ jsx("span", { children: "to open" })
                ] })
              ] })
            ]
          }
        )
      }
    )
  ] }) });
}
function SkipLinks() {
  const [isVisible, setIsVisible] = useState(false);
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Tab") {
        setIsVisible(true);
      }
    };
    const handleClick = () => {
      setIsVisible(false);
    };
    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("click", handleClick);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("click", handleClick);
    };
  }, []);
  const handleSkipToMain = () => {
    const mainContent = document.getElementById("main-content");
    if (mainContent) {
      mainContent.focus();
      mainContent.scrollIntoView({ behavior: "smooth" });
      setIsVisible(false);
    }
  };
  const handleSkipToNav = () => {
    const nav = document.querySelector('nav[role="navigation"]');
    if (nav) {
      nav.focus();
      setIsVisible(false);
    }
  };
  if (!isVisible) {
    return /* @__PURE__ */ jsx(
      "a",
      {
        href: "#main-content",
        className: "sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-primary-foreground focus:rounded-md focus:shadow-lg",
        onClick: (e) => {
          e.preventDefault();
          handleSkipToMain();
        },
        children: "Skip to main content"
      }
    );
  }
  return /* @__PURE__ */ jsxs("div", { className: "fixed top-0 left-0 right-0 z-50 bg-background border-b shadow-lg p-4 flex gap-4", children: [
    /* @__PURE__ */ jsx(
      "button",
      {
        type: "button",
        onClick: handleSkipToMain,
        className: "px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-ring",
        children: "Skip to main content"
      }
    ),
    /* @__PURE__ */ jsx(
      "button",
      {
        type: "button",
        onClick: handleSkipToNav,
        className: "px-4 py-2 bg-secondary text-secondary-foreground rounded-md hover:bg-secondary/90 focus:outline-none focus:ring-2 focus:ring-ring",
        children: "Skip to navigation"
      }
    )
  ] });
}
function Announcer() {
  return /* @__PURE__ */ jsxs(Fragment, { children: [
    /* @__PURE__ */ jsx(
      "div",
      {
        id: "aria-announcer-polite",
        role: "status",
        "aria-live": "polite",
        "aria-atomic": "true",
        className: "sr-only"
      }
    ),
    /* @__PURE__ */ jsx(
      "div",
      {
        id: "aria-announcer-assertive",
        role: "alert",
        "aria-live": "assertive",
        "aria-atomic": "true",
        className: "sr-only"
      }
    )
  ] });
}
function Layout({ children }) {
  const [isSidebarCollapsed, setIsSidebarCollapsed] = React.useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState(false);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = React.useState(false);
  const { user, logout } = useAuth();
  const prefersReducedMotion = useReducedMotion();
  React.useEffect(() => {
    const saved = localStorage.getItem("sidebar-collapsed");
    if (saved) {
      setIsSidebarCollapsed(saved === "true");
    }
  }, []);
  React.useEffect(() => {
    localStorage.setItem("sidebar-collapsed", String(isSidebarCollapsed));
  }, [isSidebarCollapsed]);
  React.useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth >= 1024) {
        setIsMobileMenuOpen(false);
      }
    };
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);
  return /* @__PURE__ */ jsxs("div", { className: "min-h-screen bg-background", children: [
    /* @__PURE__ */ jsx(SkipLinks, {}),
    /* @__PURE__ */ jsx("div", { className: "hidden lg:block", children: /* @__PURE__ */ jsx(
      Sidebar,
      {
        isCollapsed: isSidebarCollapsed,
        onToggle: () => setIsSidebarCollapsed(!isSidebarCollapsed),
        onLogout: logout,
        user: user ? { name: user.name, email: user.email } : void 0
      }
    ) }),
    /* @__PURE__ */ jsx(
      MobileNav,
      {
        isOpen: isMobileMenuOpen,
        onClose: () => setIsMobileMenuOpen(false),
        onLogout: logout,
        user: user ? { name: user.name, email: user.email } : void 0
      }
    ),
    /* @__PURE__ */ jsxs(
      motion.main,
      {
        initial: false,
        animate: {
          marginLeft: isSidebarCollapsed ? 80 : 260
        },
        transition: prefersReducedMotion ? { duration: 0 } : { duration: 0.3, ease: [0.34, 1.56, 0.64, 1] },
        className: cn(
          "min-h-screen transition-[margin] duration-300",
          "lg:ml-0",
          "pb-20 lg:pb-0"
        ),
        id: "main-content",
        children: [
          /* @__PURE__ */ jsx("header", { className: "sticky top-0 z-30 bg-background/80 backdrop-blur-md border-b", children: /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between h-16 px-4 lg:px-8", children: [
            /* @__PURE__ */ jsx(
              "button",
              {
                type: "button",
                onClick: () => setIsMobileMenuOpen(true),
                className: "lg:hidden p-2 -ml-2 rounded-lg hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary",
                "aria-label": "Open navigation menu",
                children: /* @__PURE__ */ jsx("svg", { className: "h-6 w-6", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24", "aria-hidden": "true", children: /* @__PURE__ */ jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: 2, d: "M4 6h16M4 12h16M4 18h16" }) })
              }
            ),
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-4 ml-auto", children: [
              /* @__PURE__ */ jsxs(
                "button",
                {
                  type: "button",
                  onClick: () => setIsCommandPaletteOpen(true),
                  className: "hidden md:flex items-center gap-2 px-3 py-1.5 text-sm text-muted-foreground bg-muted rounded-md hover:text-foreground transition-colors",
                  children: [
                    /* @__PURE__ */ jsx("span", { children: "Search..." }),
                    /* @__PURE__ */ jsx("kbd", { className: "text-xs bg-background px-1.5 py-0.5 rounded border", children: "⌘K" })
                  ]
                }
              ),
              /* @__PURE__ */ jsx("div", { className: "md:hidden", children: /* @__PURE__ */ jsx(GlobalSearch, {}) }),
              /* @__PURE__ */ jsx(ThemeToggle, {})
            ] })
          ] }) }),
          /* @__PURE__ */ jsx("div", { className: "p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto", children })
        ]
      }
    ),
    /* @__PURE__ */ jsx(MobileBottomNav, {}),
    /* @__PURE__ */ jsx(CommandPalette, { open: isCommandPaletteOpen, onOpenChange: setIsCommandPaletteOpen }),
    /* @__PURE__ */ jsx(Announcer, {})
  ] });
}
function PageHeader({ title, description, actions, breadcrumbs }) {
  const prefersReducedMotion = useReducedMotion();
  return /* @__PURE__ */ jsxs("div", { className: "mb-8 space-y-4", children: [
    breadcrumbs && breadcrumbs.length > 0 && /* @__PURE__ */ jsx("nav", { className: "flex items-center gap-2 text-sm text-muted-foreground", children: breadcrumbs.map((crumb, index) => /* @__PURE__ */ jsxs(React.Fragment, { children: [
      index > 0 && /* @__PURE__ */ jsx("span", { children: "/" }),
      crumb.href ? /* @__PURE__ */ jsx("a", { href: crumb.href, className: "hover:text-foreground transition-colors", children: crumb.label }) : /* @__PURE__ */ jsx("span", { className: "text-foreground", children: crumb.label })
    ] }, crumb.label)) }),
    /* @__PURE__ */ jsxs("div", { className: "flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4", children: [
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsx(
          motion.h1,
          {
            initial: prefersReducedMotion ? false : { opacity: 0, y: -10 },
            animate: prefersReducedMotion ? { opacity: 1, y: 0 } : { opacity: 1, y: 0 },
            className: "text-2xl sm:text-3xl font-bold tracking-tight text-balance",
            children: title
          }
        ),
        description && /* @__PURE__ */ jsx(
          motion.p,
          {
            initial: prefersReducedMotion ? false : { opacity: 0, y: -5 },
            animate: prefersReducedMotion ? { opacity: 1, y: 0 } : { opacity: 1, y: 0 },
            transition: prefersReducedMotion ? { duration: 0 } : { delay: 0.1 },
            className: "text-muted-foreground mt-1",
            children: description
          }
        )
      ] }),
      actions && /* @__PURE__ */ jsx(
        motion.div,
        {
          initial: prefersReducedMotion ? false : { opacity: 0, scale: 0.95 },
          animate: prefersReducedMotion ? { opacity: 1, scale: 1 } : { opacity: 1, scale: 1 },
          transition: prefersReducedMotion ? { duration: 0 } : { delay: 0.1 },
          className: "flex items-center gap-2",
          children: actions
        }
      )
    ] })
  ] });
}
function StatCard({ title, value, trend, icon, color = "blue" }) {
  const prefersReducedMotion = useReducedMotion();
  const colorClasses = {
    blue: "bg-blue-500/10 text-blue-600",
    green: "bg-green-500/10 text-green-600",
    amber: "bg-amber-500/10 text-amber-600",
    purple: "bg-purple-500/10 text-purple-600",
    rose: "bg-rose-500/10 text-rose-600"
  };
  return /* @__PURE__ */ jsxs(
    motion.div,
    {
      initial: prefersReducedMotion ? false : { opacity: 0, y: 20 },
      animate: prefersReducedMotion ? { opacity: 1, y: 0 } : { opacity: 1, y: 0 },
      whileHover: prefersReducedMotion ? void 0 : { y: -2 },
      className: "rounded-xl border bg-card p-6 card-hover",
      children: [
        /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
          /* @__PURE__ */ jsx("div", { className: cn("p-3 rounded-lg", colorClasses[color]), children: icon }),
          trend && /* @__PURE__ */ jsxs(
            "div",
            {
              className: cn(
                "flex items-center gap-1 text-sm font-medium",
                trend.isPositive ? "text-green-600" : "text-rose-600"
              ),
              children: [
                trend.isPositive ? "↑" : "↓",
                " ",
                Math.abs(trend.value),
                "%"
              ]
            }
          )
        ] }),
        /* @__PURE__ */ jsxs("div", { className: "mt-4", children: [
          /* @__PURE__ */ jsx("p", { className: "text-muted-foreground text-sm", children: title }),
          /* @__PURE__ */ jsx("p", { className: "text-2xl font-bold mt-1", children: value })
        ] })
      ]
    }
  );
}
const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium transition-colors",
  {
    variants: {
      variant: {
        default: "bg-primary/10 text-primary border border-primary/20",
        secondary: "bg-secondary text-secondary-foreground",
        destructive: "bg-destructive/10 text-destructive border border-destructive/20",
        outline: "text-foreground border border-input",
        success: "bg-success/10 text-success-700 dark:text-success-400 border border-success/20",
        warning: "bg-warning/10 text-warning-700 dark:text-warning-400 border border-warning/20",
        info: "bg-info/10 text-info-700 dark:text-info-400 border border-info/20",
        muted: "bg-muted text-muted-foreground"
      },
      size: {
        default: "px-2.5 py-0.5 text-xs",
        sm: "px-2 py-0.5 text-[10px]",
        lg: "px-3 py-1 text-sm"
      }
    },
    defaultVariants: {
      variant: "default",
      size: "default"
    }
  }
);
function Badge({ className, variant, size, dot, dotColor, children, ...props }) {
  return /* @__PURE__ */ jsxs("div", { className: cn(badgeVariants({ variant, size }), className), ...props, children: [
    dot && /* @__PURE__ */ jsx(
      "span",
      {
        className: cn("h-1.5 w-1.5 rounded-full", dotColor || "bg-current")
      }
    ),
    children
  ] });
}
const alertVariants = cva(
  "relative w-full rounded-lg border px-4 py-3 text-sm [&>svg+div]:translate-y-[-3px] [&>svg]:absolute [&>svg]:left-4 [&>svg]:top-4 [&>svg]:text-foreground [&>svg~*]:pl-7",
  {
    variants: {
      variant: {
        default: "bg-background text-foreground",
        destructive: "border-destructive/50 text-destructive dark:border-destructive [&>svg]:text-destructive",
        warning: "border-yellow-500/50 text-yellow-700 dark:text-yellow-300 bg-yellow-500/10 [&>svg]:text-yellow-600 dark:[&>svg]:text-yellow-400",
        info: "border-blue-500/50 text-blue-700 dark:text-blue-300 bg-blue-500/10 [&>svg]:text-blue-600 dark:[&>svg]:text-blue-400",
        success: "border-green-500/50 text-green-700 dark:text-green-300 bg-green-500/10 [&>svg]:text-green-600 dark:[&>svg]:text-green-400"
      }
    },
    defaultVariants: {
      variant: "default"
    }
  }
);
const Alert = React.forwardRef(({ className, variant, ...props }, ref) => /* @__PURE__ */ jsx(
  "div",
  {
    ref,
    role: "alert",
    className: cn(alertVariants({ variant }), className),
    ...props
  }
));
Alert.displayName = "Alert";
const AlertTitle = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  "h5",
  {
    ref,
    className: cn("mb-1 font-medium leading-none tracking-tight", className),
    ...props
  }
));
AlertTitle.displayName = "AlertTitle";
const AlertDescription = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  "div",
  {
    ref,
    className: cn("text-sm [&_p]:leading-relaxed", className),
    ...props
  }
));
AlertDescription.displayName = "AlertDescription";
const Checkbox = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  CheckboxPrimitive.Root,
  {
    ref,
    className: cn(
      "peer h-4 w-4 shrink-0 rounded-sm border border-primary ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground",
      className
    ),
    ...props,
    children: /* @__PURE__ */ jsx(
      CheckboxPrimitive.Indicator,
      {
        className: cn("flex items-center justify-center text-current"),
        children: /* @__PURE__ */ jsx(Check, { className: "h-4 w-4" })
      }
    )
  }
));
Checkbox.displayName = CheckboxPrimitive.Root.displayName;
const Label = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  LabelPrimitive.Root,
  {
    ref,
    className: cn(
      "text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70",
      className
    ),
    ...props
  }
));
Label.displayName = LabelPrimitive.Root.displayName;
function getImpersonationAuditLog() {
  return [];
}
function endImpersonationRecord(adminId) {
}
function ImpersonationPrivacyDialog({
  tenantId,
  tenantName,
  onConfirm,
  onCancel,
  open
}) {
  const [reason, setReason] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const handleConfirm = async () => {
    if (!reason.trim()) {
      toast.error("Please provide a reason for impersonation");
      return;
    }
    if (!acknowledged) {
      toast.error("Please acknowledge the privacy warning");
      return;
    }
    setIsSubmitting(true);
    setIsSubmitting(false);
    onConfirm(reason);
  };
  return /* @__PURE__ */ jsx(Dialog, { open, onOpenChange: (isOpen) => !isOpen && onCancel(), children: /* @__PURE__ */ jsxs(DialogContent, { className: "max-w-2xl", children: [
    /* @__PURE__ */ jsxs(DialogHeader, { children: [
      /* @__PURE__ */ jsxs(DialogTitle, { className: "flex items-center gap-2 text-amber-600", children: [
        /* @__PURE__ */ jsx(ShieldAlert, { className: "h-5 w-5" }),
        "Privacy Warning: Tenant Impersonation"
      ] }),
      /* @__PURE__ */ jsx(DialogDescription, { children: "You are about to access tenant data. This action is logged and audited." })
    ] }),
    /* @__PURE__ */ jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxs(Alert, { variant: "destructive", children: [
        /* @__PURE__ */ jsx(AlertTriangle, { className: "h-4 w-4" }),
        /* @__PURE__ */ jsx(AlertTitle, { children: "Restricted Access" }),
        /* @__PURE__ */ jsx(AlertDescription, { children: "Platform administrators should NOT access tenant data except for legitimate support purposes. All access is logged and may be reviewed for compliance." })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-2 gap-4 text-sm", children: [
        /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2 p-3 rounded-lg bg-muted", children: [
          /* @__PURE__ */ jsx(Building2, { className: "h-4 w-4 text-muted-foreground" }),
          /* @__PURE__ */ jsxs("div", { children: [
            /* @__PURE__ */ jsx("p", { className: "font-medium", children: "Target Tenant" }),
            /* @__PURE__ */ jsx("p", { className: "text-muted-foreground", children: tenantName })
          ] })
        ] }),
        /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2 p-3 rounded-lg bg-muted", children: [
          /* @__PURE__ */ jsx(Clock, { className: "h-4 w-4 text-muted-foreground" }),
          /* @__PURE__ */ jsxs("div", { children: [
            /* @__PURE__ */ jsx("p", { className: "font-medium", children: "Session Start" }),
            /* @__PURE__ */ jsx("p", { className: "text-muted-foreground", children: formatDate(/* @__PURE__ */ new Date()) })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
        /* @__PURE__ */ jsxs(Label, { htmlFor: "reason", children: [
          "Reason for Access ",
          /* @__PURE__ */ jsx("span", { className: "text-destructive", children: "*" })
        ] }),
        /* @__PURE__ */ jsx(
          "textarea",
          {
            id: "reason",
            value: reason,
            onChange: (e) => setReason(e.target.value),
            placeholder: "Describe why you need to access this tenant (e.g., 'Customer reported login issues, investigating')",
            className: "w-full min-h-[100px] rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
          }
        ),
        /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: "This reason will be recorded in the audit log." })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "space-y-3 border rounded-lg p-4 bg-muted/50", children: [
        /* @__PURE__ */ jsx("p", { className: "font-medium text-sm", children: "You will have access to:" }),
        /* @__PURE__ */ jsxs("ul", { className: "text-sm text-muted-foreground space-y-1", children: [
          /* @__PURE__ */ jsxs("li", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsx(Eye, { className: "h-3.5 w-3.5" }),
            "Tenant users and their roles"
          ] }),
          /* @__PURE__ */ jsxs("li", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsx(Eye, { className: "h-3.5 w-3.5" }),
            "Organization settings and data"
          ] }),
          /* @__PURE__ */ jsxs("li", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsx(Eye, { className: "h-3.5 w-3.5" }),
            "Audit logs within this tenant"
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "flex items-start gap-3", children: [
        /* @__PURE__ */ jsx(
          Checkbox,
          {
            id: "acknowledge",
            checked: acknowledged,
            onCheckedChange: (checked) => setAcknowledged(checked)
          }
        ),
        /* @__PURE__ */ jsxs("div", { className: "grid gap-1.5 leading-none", children: [
          /* @__PURE__ */ jsx(
            Label,
            {
              htmlFor: "acknowledge",
              className: "text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70",
              children: "I acknowledge that I am accessing private customer data"
            }
          ),
          /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: "I understand this access is logged and may be reviewed. I will only access data necessary to resolve the reported issue." })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxs(DialogFooter, { className: "gap-2", children: [
      /* @__PURE__ */ jsx(Button, { variant: "outline", onClick: onCancel, children: "Cancel" }),
      /* @__PURE__ */ jsx(
        Button,
        {
          onClick: handleConfirm,
          disabled: !acknowledged || !reason.trim() || isSubmitting,
          className: "bg-amber-600 hover:bg-amber-700",
          children: isSubmitting ? /* @__PURE__ */ jsxs(Fragment, { children: [
            /* @__PURE__ */ jsx(Clock, { className: "mr-2 h-4 w-4 animate-spin" }),
            "Logging..."
          ] }) : /* @__PURE__ */ jsxs(Fragment, { children: [
            /* @__PURE__ */ jsx(Eye, { className: "mr-2 h-4 w-4" }),
            "Proceed with Impersonation"
          ] })
        }
      )
    ] })
  ] }) });
}
function ImpersonationAuditLog() {
  const [logs, setLogs] = useState([]);
  useEffect(() => {
    setLogs(getImpersonationAuditLog());
  }, []);
  if (logs.length === 0) {
    return /* @__PURE__ */ jsxs("div", { className: "text-center py-8 text-muted-foreground", children: [
      /* @__PURE__ */ jsx(FileText, { className: "h-12 w-12 mx-auto mb-3 opacity-50" }),
      /* @__PURE__ */ jsx("p", { children: "No support access records found" }),
      /* @__PURE__ */ jsx("p", { className: "text-sm mt-1", children: "Platform admins can access tenant data via the Support Access feature on tenant detail pages." })
    ] });
  }
  return /* @__PURE__ */ jsx("div", { className: "space-y-4", children: logs.map((log) => {
    const duration = log.endedAt ? Math.round((new Date(log.endedAt).getTime() - new Date(log.startedAt).getTime()) / 1e3 / 60) : null;
    return /* @__PURE__ */ jsx(
      "div",
      {
        className: "p-4 rounded-lg border border-amber-200 bg-amber-50/50 dark:bg-amber-950/20",
        children: /* @__PURE__ */ jsxs("div", { className: "flex items-start justify-between", children: [
          /* @__PURE__ */ jsxs("div", { className: "flex-1", children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
              /* @__PURE__ */ jsx(ShieldAlert, { className: "h-4 w-4 text-amber-600" }),
              /* @__PURE__ */ jsx("span", { className: "font-medium", children: "Support Access Session" }),
              !log.endedAt && /* @__PURE__ */ jsx("span", { className: "text-xs bg-amber-100 text-amber-800 px-2 py-0.5 rounded-full", children: "Active" })
            ] }),
            /* @__PURE__ */ jsxs("div", { className: "mt-2 space-y-1", children: [
              /* @__PURE__ */ jsxs("p", { className: "text-sm", children: [
                /* @__PURE__ */ jsx("span", { className: "font-medium", children: "Admin:" }),
                " ",
                /* @__PURE__ */ jsx("span", { className: "text-muted-foreground", children: log.adminEmail })
              ] }),
              /* @__PURE__ */ jsxs("p", { className: "text-sm", children: [
                /* @__PURE__ */ jsx("span", { className: "font-medium", children: "Tenant:" }),
                " ",
                /* @__PURE__ */ jsx(Badge, { variant: "secondary", className: "text-xs", children: log.tenantName })
              ] }),
              /* @__PURE__ */ jsxs("p", { className: "text-sm", children: [
                /* @__PURE__ */ jsx("span", { className: "font-medium", children: "Reason:" }),
                " ",
                /* @__PURE__ */ jsx("span", { className: "text-muted-foreground", children: log.reason })
              ] })
            ] })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "text-right text-xs text-muted-foreground space-y-1", children: [
            /* @__PURE__ */ jsxs("p", { children: [
              /* @__PURE__ */ jsx("span", { className: "font-medium", children: "Started:" }),
              " ",
              formatDate(log.startedAt)
            ] }),
            log.endedAt && /* @__PURE__ */ jsxs(Fragment, { children: [
              /* @__PURE__ */ jsxs("p", { children: [
                /* @__PURE__ */ jsx("span", { className: "font-medium", children: "Ended:" }),
                " ",
                formatDate(log.endedAt)
              ] }),
              /* @__PURE__ */ jsxs("p", { children: [
                /* @__PURE__ */ jsx("span", { className: "font-medium", children: "Duration:" }),
                " ",
                /* @__PURE__ */ jsxs(Badge, { variant: "outline", className: "text-xs", children: [
                  duration,
                  " minutes"
                ] })
              ] })
            ] })
          ] })
        ] })
      },
      log.id
    );
  }) });
}
function ImpersonationBanner({
  impersonatedUser,
  onStopImpersonating
}) {
  if (!impersonatedUser) {
    return null;
  }
  const user = impersonatedUser;
  const handleStopImpersonating = () => {
    endImpersonationRecord(user?.id || "unknown");
    onStopImpersonating?.();
    toast.success("Support access ended");
  };
  return /* @__PURE__ */ jsx("div", { className: "fixed top-0 left-0 right-0 z-50 bg-amber-500 text-white px-4 py-2", children: /* @__PURE__ */ jsxs("div", { className: "max-w-7xl mx-auto flex items-center justify-between", children: [
    /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
      /* @__PURE__ */ jsx(ShieldAlert, { className: "h-5 w-5" }),
      /* @__PURE__ */ jsxs("span", { className: "font-medium", children: [
        "Impersonating: ",
        user.name || user.email
      ] }),
      /* @__PURE__ */ jsxs("span", { className: "text-amber-100 text-sm", children: [
        "(",
        user.id,
        ")"
      ] })
    ] }),
    /* @__PURE__ */ jsxs(
      Button,
      {
        variant: "ghost",
        size: "sm",
        onClick: handleStopImpersonating,
        className: "text-white hover:bg-amber-600 gap-2",
        children: [
          /* @__PURE__ */ jsx(LogOut, { className: "h-4 w-4" }),
          "Stop Impersonating"
        ]
      }
    )
  ] }) });
}
let initialized = false;
const isBrowser = () => typeof window !== "undefined";
const initSentry = (router2) => {
  if (initialized) return;
  if (!isBrowser()) return;
  if (!env.VITE_SENTRY_DSN) return;
  const integrations = [];
  if (router2 && typeof Sentry.tanstackRouterBrowserTracingIntegration === "function") {
    integrations.push(
      Sentry.tanstackRouterBrowserTracingIntegration(router2)
    );
  } else if (typeof Sentry.browserTracingIntegration === "function") {
    integrations.push(Sentry.browserTracingIntegration());
  }
  const parseRoutes = (value) => value?.split(",").map((entry) => entry.trim()).filter(Boolean) ?? [];
  const highSampleRoutes = parseRoutes(env.VITE_SENTRY_TRACES_SAMPLE_RATE_HIGH_ROUTES);
  const lowSampleRoutes = parseRoutes(env.VITE_SENTRY_TRACES_SAMPLE_RATE_LOW_ROUTES);
  const highSampleRate = env.VITE_SENTRY_TRACES_SAMPLE_RATE_HIGH;
  const lowSampleRate = env.VITE_SENTRY_TRACES_SAMPLE_RATE_LOW;
  const defaultSampleRate = env.VITE_SENTRY_TRACES_SAMPLE_RATE ?? 0;
  const pickSampleRate = (pathname) => {
    if (!pathname) return defaultSampleRate;
    if (highSampleRate !== void 0 && highSampleRoutes.some((route) => pathname.startsWith(route))) {
      return highSampleRate;
    }
    if (lowSampleRate !== void 0 && lowSampleRoutes.some((route) => pathname.startsWith(route))) {
      return lowSampleRate;
    }
    return defaultSampleRate;
  };
  Sentry.init({
    dsn: env.VITE_SENTRY_DSN,
    environment: env.VITE_SENTRY_ENVIRONMENT,
    tracesSampleRate: defaultSampleRate,
    tracesSampler: (context) => {
      const pathname = context?.location?.pathname ?? (typeof window !== "undefined" ? window.location.pathname : void 0) ?? (typeof context?.transactionContext?.name === "string" ? context.transactionContext.name : void 0);
      return pickSampleRate(pathname);
    },
    integrations
  });
  initialized = true;
};
const isSentryInitialized = () => initialized;
const appCss = "/assets/styles-DOfG8y80.css";
const Route$o = createRootRoute({
  head: () => ({
    meta: [
      {
        charSet: "utf-8"
      },
      {
        name: "viewport",
        content: "width=device-width, initial-scale=1, maximum-scale=5, viewport-fit=cover"
      },
      {
        name: "description",
        content: "Internal admin console for Vault multi-tenant platform"
      },
      {
        name: "theme-color",
        content: "#4f46e5"
      },
      // Security meta tags
      {
        "http-equiv": "Content-Security-Policy",
        content: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self';"
      },
      {
        "http-equiv": "X-Content-Type-Options",
        content: "nosniff"
      },
      {
        "http-equiv": "Referrer-Policy",
        content: "strict-origin-when-cross-origin"
      },
      // PWA meta tags
      {
        name: "apple-mobile-web-app-capable",
        content: "yes"
      },
      {
        name: "apple-mobile-web-app-status-bar-style",
        content: "default"
      },
      {
        name: "apple-mobile-web-app-title",
        content: "Vault Admin"
      },
      {
        name: "format-detection",
        content: "telephone=no"
      },
      {
        name: "mobile-web-app-capable",
        content: "yes"
      }
    ],
    links: [
      {
        rel: "stylesheet",
        href: appCss
      },
      // PWA links
      {
        rel: "manifest",
        href: "/manifest.json"
      },
      {
        rel: "apple-touch-icon",
        href: "/logo192.png"
      },
      {
        rel: "icon",
        type: "image/png",
        href: "/logo192.png"
      }
    ]
  }),
  component: RootComponent
});
function RootComponent() {
  const { pathname } = useRouterState({ select: (state) => state.location });
  const isHostedRoute = pathname.startsWith("/hosted");
  return /* @__PURE__ */ jsxs("html", { lang: "en", className: "h-full", suppressHydrationWarning: true, children: [
    /* @__PURE__ */ jsx("head", { children: /* @__PURE__ */ jsx(HeadContent, {}) }),
    /* @__PURE__ */ jsxs("body", { className: "h-full", children: [
      /* @__PURE__ */ jsx(ThemeProvider, { defaultTheme: "system", children: isHostedRoute ? /* @__PURE__ */ jsx(AppContent, { withAdminShell: false }) : /* @__PURE__ */ jsx(AuthProvider, { children: /* @__PURE__ */ jsx(RealtimeProvider, { children: /* @__PURE__ */ jsx(PWAProvider, { children: /* @__PURE__ */ jsx(AppContent, { withAdminShell: true }) }) }) }) }),
      /* @__PURE__ */ jsx(Scripts, {})
    ] })
  ] });
}
function AppContent({ withAdminShell }) {
  const { pathname } = useRouterState({ select: (state) => state.location });
  const supportImpersonationEnabled = env.VITE_ENABLE_SUPPORT_IMPERSONATION === "true";
  const useShell = withAdminShell && pathname !== "/login" && !pathname.startsWith("/hosted");
  const mainRef = useRef(null);
  useEffect(() => {
    if (mainRef.current) {
      mainRef.current.focus();
      mainRef.current.scrollIntoView({ behavior: "auto", block: "start" });
    }
  }, [pathname]);
  return /* @__PURE__ */ jsxs(Sentry.ErrorBoundary, { fallback: /* @__PURE__ */ jsx("div", { children: "Something went wrong." }), children: [
    useShell && /* @__PURE__ */ jsx(SkipLinks, {}),
    supportImpersonationEnabled && useShell ? /* @__PURE__ */ jsx(ImpersonationBanner, {}) : null,
    useShell ? /* @__PURE__ */ jsx(OfflineIndicator, {}) : null,
    /* @__PURE__ */ jsx(
      "div",
      {
        ref: mainRef,
        id: "main-content",
        tabIndex: -1,
        role: "main",
        "aria-label": "Main content",
        children: useShell ? /* @__PURE__ */ jsx(Layout, { children: /* @__PURE__ */ jsx(Outlet, {}) }) : /* @__PURE__ */ jsx(Outlet, {})
      }
    ),
    useShell ? /* @__PURE__ */ jsx(InstallPrompt, {}) : null,
    useShell ? /* @__PURE__ */ jsx(UpdateNotification, {}) : null,
    /* @__PURE__ */ jsx(Toaster, { position: "top-right", richColors: true, closeButton: true })
  ] });
}
const $$splitComponentImporter$n = () => import("./system-M0KvSoWg.js");
const Route$n = createFileRoute("/system")({
  component: lazyRouteComponent($$splitComponentImporter$n, "component")
});
const $$splitComponentImporter$m = () => import("./settings--YKXpbKu.js");
const Route$m = createFileRoute("/settings")({
  component: lazyRouteComponent($$splitComponentImporter$m, "component")
});
const $$splitComponentImporter$l = () => import("./login-C2uJdXPn.js");
const Route$l = createFileRoute("/login")({
  component: lazyRouteComponent($$splitComponentImporter$l, "component")
});
const $$splitComponentImporter$k = () => import("./audit-Dpv5OOqs.js");
const Route$k = createFileRoute("/audit")({
  component: lazyRouteComponent($$splitComponentImporter$k, "component")
});
const $$splitComponentImporter$j = () => import("./index-CpHCFeJS.js");
const Route$j = createFileRoute("/")({
  component: lazyRouteComponent($$splitComponentImporter$j, "component")
});
const $$splitComponentImporter$i = () => import("./index-D_BFqtsM.js");
const Route$i = createFileRoute("/tenants/")({
  component: lazyRouteComponent($$splitComponentImporter$i, "component")
});
const $$splitComponentImporter$h = () => import("./index-G51FUoLv.js");
const Route$h = createFileRoute("/hosted/")({
  component: lazyRouteComponent($$splitComponentImporter$h, "component")
});
const $$splitComponentImporter$g = () => import("./index-BINwq-XU.js");
const Route$g = createFileRoute("/billing/")({
  component: lazyRouteComponent($$splitComponentImporter$g, "component")
});
const $$splitComponentImporter$f = () => import("./create-B8ylqp8u.js");
const Route$f = createFileRoute("/tenants/create")({
  component: lazyRouteComponent($$splitComponentImporter$f, "component")
});
const $$splitComponentImporter$e = () => import("./_id-CJT_MI4q.js");
const Route$e = createFileRoute("/tenants/$id")({
  component: lazyRouteComponent($$splitComponentImporter$e, "component")
});
const $$splitComponentImporter$d = () => import("./webhooks-Bm6aDG9M.js");
const Route$d = createFileRoute("/settings/webhooks")({
  component: lazyRouteComponent($$splitComponentImporter$d, "component")
});
const $$splitComponentImporter$c = () => import("./sso-C5A_2AYT.js");
const Route$c = createFileRoute("/settings/sso")({
  component: lazyRouteComponent($$splitComponentImporter$c, "component")
});
const $$splitComponentImporter$b = () => import("./security-gB2Qj_EW.js");
const Route$b = createFileRoute("/settings/security")({
  component: lazyRouteComponent($$splitComponentImporter$b, "component")
});
const $$splitComponentImporter$a = () => import("./api-keys-D3-i7zWV.js");
const Route$a = createFileRoute("/settings/api-keys")({
  component: lazyRouteComponent($$splitComponentImporter$a, "component")
});
const $$splitComponentImporter$9 = () => import("./verify-email-D62QzR_A.js");
const Route$9 = createFileRoute("/hosted/verify-email")({
  component: lazyRouteComponent($$splitComponentImporter$9, "component")
});
const $$splitComponentImporter$8 = () => import("./sign-up--KtNiQ8Q.js");
const Route$8 = createFileRoute("/hosted/sign-up")({
  component: lazyRouteComponent($$splitComponentImporter$8, "component")
});
const $$splitComponentImporter$7 = () => import("./sign-in-CaMGBHyN.js");
const Route$7 = createFileRoute("/hosted/sign-in")({
  component: lazyRouteComponent($$splitComponentImporter$7, "component")
});
const $$splitComponentImporter$6 = () => import("./oauth-callback-DCdCPQDw.js");
const Route$6 = createFileRoute("/hosted/oauth-callback")({
  component: lazyRouteComponent($$splitComponentImporter$6, "component")
});
const $$splitComponentImporter$5 = () => import("./mfa-CI0HPk7G.js");
const Route$5 = createFileRoute("/hosted/mfa")({
  component: lazyRouteComponent($$splitComponentImporter$5, "component")
});
const $$splitComponentImporter$4 = () => import("./forgot-password-DYwFVvQ5.js");
const Route$4 = createFileRoute("/hosted/forgot-password")({
  component: lazyRouteComponent($$splitComponentImporter$4, "component")
});
const $$splitComponentImporter$3 = () => import("./subscriptions-Zsal7pJa.js");
const Route$3 = createFileRoute("/billing/subscriptions")({
  component: lazyRouteComponent($$splitComponentImporter$3, "component")
});
const $$splitComponentImporter$2 = () => import("./invoices-DP-DJjH0.js");
const Route$2 = createFileRoute("/billing/invoices")({
  component: lazyRouteComponent($$splitComponentImporter$2, "component")
});
const $$splitComponentImporter$1 = () => import("./switch-DCoflIR2.js");
const Route$1 = createFileRoute("/hosted/organization/switch")({
  component: lazyRouteComponent($$splitComponentImporter$1, "component")
});
const $$splitComponentImporter = () => import("./create-DfjGRzDa.js");
const Route = createFileRoute("/hosted/organization/create")({
  component: lazyRouteComponent($$splitComponentImporter, "component")
});
const SystemRoute = Route$n.update({
  id: "/system",
  path: "/system",
  getParentRoute: () => Route$o
});
const SettingsRoute = Route$m.update({
  id: "/settings",
  path: "/settings",
  getParentRoute: () => Route$o
});
const LoginRoute = Route$l.update({
  id: "/login",
  path: "/login",
  getParentRoute: () => Route$o
});
const AuditRoute = Route$k.update({
  id: "/audit",
  path: "/audit",
  getParentRoute: () => Route$o
});
const IndexRoute = Route$j.update({
  id: "/",
  path: "/",
  getParentRoute: () => Route$o
});
const TenantsIndexRoute = Route$i.update({
  id: "/tenants/",
  path: "/tenants/",
  getParentRoute: () => Route$o
});
const HostedIndexRoute = Route$h.update({
  id: "/hosted/",
  path: "/hosted/",
  getParentRoute: () => Route$o
});
const BillingIndexRoute = Route$g.update({
  id: "/billing/",
  path: "/billing/",
  getParentRoute: () => Route$o
});
const TenantsCreateRoute = Route$f.update({
  id: "/tenants/create",
  path: "/tenants/create",
  getParentRoute: () => Route$o
});
const TenantsIdRoute = Route$e.update({
  id: "/tenants/$id",
  path: "/tenants/$id",
  getParentRoute: () => Route$o
});
const SettingsWebhooksRoute = Route$d.update({
  id: "/webhooks",
  path: "/webhooks",
  getParentRoute: () => SettingsRoute
});
const SettingsSsoRoute = Route$c.update({
  id: "/sso",
  path: "/sso",
  getParentRoute: () => SettingsRoute
});
const SettingsSecurityRoute = Route$b.update({
  id: "/security",
  path: "/security",
  getParentRoute: () => SettingsRoute
});
const SettingsApiKeysRoute = Route$a.update({
  id: "/api-keys",
  path: "/api-keys",
  getParentRoute: () => SettingsRoute
});
const HostedVerifyEmailRoute = Route$9.update({
  id: "/hosted/verify-email",
  path: "/hosted/verify-email",
  getParentRoute: () => Route$o
});
const HostedSignUpRoute = Route$8.update({
  id: "/hosted/sign-up",
  path: "/hosted/sign-up",
  getParentRoute: () => Route$o
});
const HostedSignInRoute = Route$7.update({
  id: "/hosted/sign-in",
  path: "/hosted/sign-in",
  getParentRoute: () => Route$o
});
const HostedOauthCallbackRoute = Route$6.update({
  id: "/hosted/oauth-callback",
  path: "/hosted/oauth-callback",
  getParentRoute: () => Route$o
});
const HostedMfaRoute = Route$5.update({
  id: "/hosted/mfa",
  path: "/hosted/mfa",
  getParentRoute: () => Route$o
});
const HostedForgotPasswordRoute = Route$4.update({
  id: "/hosted/forgot-password",
  path: "/hosted/forgot-password",
  getParentRoute: () => Route$o
});
const BillingSubscriptionsRoute = Route$3.update({
  id: "/billing/subscriptions",
  path: "/billing/subscriptions",
  getParentRoute: () => Route$o
});
const BillingInvoicesRoute = Route$2.update({
  id: "/billing/invoices",
  path: "/billing/invoices",
  getParentRoute: () => Route$o
});
const HostedOrganizationSwitchRoute = Route$1.update({
  id: "/hosted/organization/switch",
  path: "/hosted/organization/switch",
  getParentRoute: () => Route$o
});
const HostedOrganizationCreateRoute = Route.update({
  id: "/hosted/organization/create",
  path: "/hosted/organization/create",
  getParentRoute: () => Route$o
});
const SettingsRouteChildren = {
  SettingsApiKeysRoute,
  SettingsSecurityRoute,
  SettingsSsoRoute,
  SettingsWebhooksRoute
};
const SettingsRouteWithChildren = SettingsRoute._addFileChildren(
  SettingsRouteChildren
);
const rootRouteChildren = {
  IndexRoute,
  AuditRoute,
  LoginRoute,
  SettingsRoute: SettingsRouteWithChildren,
  SystemRoute,
  BillingInvoicesRoute,
  BillingSubscriptionsRoute,
  HostedForgotPasswordRoute,
  HostedMfaRoute,
  HostedOauthCallbackRoute,
  HostedSignInRoute,
  HostedSignUpRoute,
  HostedVerifyEmailRoute,
  TenantsIdRoute,
  TenantsCreateRoute,
  BillingIndexRoute,
  HostedIndexRoute,
  TenantsIndexRoute,
  HostedOrganizationCreateRoute,
  HostedOrganizationSwitchRoute
};
const routeTree = Route$o._addFileChildren(rootRouteChildren)._addFileTypes();
const getRouter = () => {
  const router2 = createRouter({
    routeTree,
    context: {},
    scrollRestoration: true,
    defaultPreloadStaleTime: 0,
    defaultPendingComponent: () => /* @__PURE__ */ jsx("div", { className: "min-h-screen flex items-center justify-center", children: /* @__PURE__ */ jsxs("div", { className: "flex flex-col items-center gap-4", children: [
      /* @__PURE__ */ jsx("div", { className: "h-8 w-8 border-4 border-primary border-t-transparent rounded-full animate-spin" }),
      /* @__PURE__ */ jsx("p", { className: "text-muted-foreground text-sm", children: "Loading…" })
    ] }) }),
    defaultErrorComponent: ({ error }) => /* @__PURE__ */ jsx("div", { className: "min-h-screen flex items-center justify-center p-4", children: /* @__PURE__ */ jsxs("div", { className: "max-w-md w-full text-center", children: [
      /* @__PURE__ */ jsx("div", { className: "h-12 w-12 bg-destructive/10 rounded-full flex items-center justify-center mx-auto mb-4", children: /* @__PURE__ */ jsx(
        "svg",
        {
          className: "h-6 w-6 text-destructive",
          fill: "none",
          viewBox: "0 0 24 24",
          stroke: "currentColor",
          children: /* @__PURE__ */ jsx(
            "path",
            {
              strokeLinecap: "round",
              strokeLinejoin: "round",
              strokeWidth: 2,
              d: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
            }
          )
        }
      ) }),
      /* @__PURE__ */ jsx("h1", { className: "text-xl font-bold mb-2", children: "Something went wrong" }),
      /* @__PURE__ */ jsx("p", { className: "text-muted-foreground mb-4", children: error.message || "An unexpected error occurred" }),
      /* @__PURE__ */ jsx(
        "button",
        {
          type: "button",
          onClick: () => window.location.reload(),
          className: "px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors",
          children: "Try Again"
        }
      )
    ] }) })
  });
  initSentry(router2);
  return router2;
};
const router = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  getRouter
}, Symbol.toStringTag, { value: "Module" }));
export {
  AuthMfaRequiredError as A,
  Button as B,
  ConfirmDialog as C,
  Dialog as D,
  ImpersonationAuditLog as I,
  PageHeader as P,
  StatCard as S,
  Badge as a,
  Alert as b,
  cn as c,
  AlertTitle as d,
  env as e,
  AlertDescription as f,
  formatDateTime as g,
  formatRelativeTime as h,
  formatNumber as i,
  formatCurrency as j,
  isSentryInitialized as k,
  formatDate as l,
  ImpersonationPrivacyDialog as m,
  DialogContent as n,
  DialogHeader as o,
  DialogTitle as p,
  DialogDescription as q,
  DialogFooter as r,
  Checkbox as s,
  toast as t,
  useAuth as u,
  router as v
};
