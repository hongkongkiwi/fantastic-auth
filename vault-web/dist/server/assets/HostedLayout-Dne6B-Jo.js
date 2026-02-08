import { jsx, jsxs, Fragment } from "react/jsx-runtime";
import { useState, useCallback, useEffect, useContext, createContext } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { Loader2, AlertCircle, Shield } from "lucide-react";
import { J as createSsrRpc } from "./router-BDwxh4pl.js";
import { c as createServerFn } from "../server.js";
import { A as Alert, b as AlertTitle, a as AlertDescription } from "./Alert-BGdSf0_L.js";
const getHostedConfig = createServerFn({
  method: "GET"
}).inputValidator((input) => input).handler(createSsrRpc("b92e70e16f392b15ad8c13d909d159d9277a8cea40153a7d152372a6e6cb34ef"));
const hostedSignIn = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(createSsrRpc("4c4c6efb431cb3e467a6afa9464ba1af0373f18bc7d8f2ade3f6c4ca87cf460a"));
const hostedSignUp = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(createSsrRpc("b5af2b0f5b3bfef7350538f597333f57e07504f99fcbe1b508ce57d168cbea67"));
const hostedOAuthStart = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(createSsrRpc("622b84adf3123c35c2afd21c2c10615a5d4b9aa6a92ce81bccb916f5063294fb"));
const hostedOAuthCallback = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(createSsrRpc("d4155fbcbe598960305caaa0460634889bef4ebf55939027f3c8729a9d0d4a74"));
const hostedSendMagicLink = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(createSsrRpc("188843d40400af4d3cb0176f40ac9e09380c3c2ff8b3b2a63e04559317674d7c"));
const hostedRequestPasswordReset = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(createSsrRpc("1ca42db0c2d7c66f24cfff9cb30ebd7016860272f0cdd353442eeca73c52638f"));
const hostedVerifyEmail = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(createSsrRpc("bd9cff8d3b9ce4f4e6e3cfb824b074e8b83564e739d2a433cd2f837974ae3e65"));
const hostedVerifyMfa = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(createSsrRpc("eba5296fd712cc1e557da6d47dae2405baaa57df15aaf6c6a8d1953200ec95ca"));
const hostedListOrganizations = createServerFn({
  method: "GET"
}).inputValidator((input) => input).handler(createSsrRpc("e88a814d5a618e7e6649b95cd90ac8cada5115df1d3fdefefd210a9fc9369e17"));
const hostedSwitchOrganization = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(createSsrRpc("00caa7e83ac2160de123c0d3a6fc13e26979131b0e5342bfa9e5f1f9ee4edd43"));
const hostedCreateOrganization = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(createSsrRpc("74b76322f432f923b54acfb6d8cdc556b05cbc5adeb8065dff2a0bf954828322"));
createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(createSsrRpc("bffb1b1898bf60e6171ff14d1b3a016bba0489e0e74026e9ac02d0bf7c7f45ad"));
const HostedConfigContext = createContext(void 0);
function HostedConfigProvider({ children, searchParams }) {
  const [config, setConfig] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const tenantId = searchParams.get("tenant_id");
  const redirectUrl = searchParams.get("redirect_url");
  const organizationId = searchParams.get("organization_id");
  const fetchConfig = useCallback(async () => {
    if (!tenantId) {
      setError("Missing tenant_id parameter");
      setIsLoading(false);
      return;
    }
    try {
      setIsLoading(true);
      setError(null);
      const data = await getHostedConfig({ data: { tenantId } });
      setConfig(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load configuration");
    } finally {
      setIsLoading(false);
    }
  }, [tenantId]);
  useEffect(() => {
    void fetchConfig();
  }, [fetchConfig]);
  useEffect(() => {
    if (!config) return;
    if (config.primaryColor) {
      document.documentElement.style.setProperty("--primary-color", config.primaryColor);
      const styleId = "hosted-primary-color";
      let styleEl = document.getElementById(styleId);
      if (!styleEl) {
        styleEl = document.createElement("style");
        styleEl.id = styleId;
        document.head.appendChild(styleEl);
      }
      styleEl.textContent = `
        :host, :root {
          --color-primary: ${config.primaryColor};
        }
        .hosted-primary-bg { background-color: ${config.primaryColor} !important; }
        .hosted-primary-text { color: ${config.primaryColor} !important; }
        .hosted-primary-border { border-color: ${config.primaryColor} !important; }
      `;
    }
    if (config.backgroundColor) {
      document.body.style.backgroundColor = config.backgroundColor;
    }
    if (config.customCss) {
      const cssId = "hosted-custom-css";
      let cssEl = document.getElementById(cssId);
      if (!cssEl) {
        cssEl = document.createElement("style");
        cssEl.id = cssId;
        document.head.appendChild(cssEl);
      }
      cssEl.textContent = config.customCss;
    }
    if (config.customJs) {
      const jsId = "hosted-custom-js";
      const existingJs = document.getElementById(jsId);
      if (existingJs) {
        existingJs.remove();
      }
      const scriptEl = document.createElement("script");
      scriptEl.id = jsId;
      scriptEl.textContent = config.customJs;
      document.body.appendChild(scriptEl);
    }
    if (config.faviconUrl) {
      const faviconLink = document.querySelector('link[rel="icon"]');
      if (faviconLink) {
        faviconLink.href = config.faviconUrl;
      }
    }
    return () => {
      document.documentElement.style.removeProperty("--primary-color");
      document.body.style.backgroundColor = "";
    };
  }, [config]);
  const value = {
    config,
    isLoading,
    error,
    tenantId,
    redirectUrl,
    organizationId,
    refetch: fetchConfig
  };
  return /* @__PURE__ */ jsx(HostedConfigContext.Provider, { value, children });
}
function useHostedConfig() {
  const context = useContext(HostedConfigContext);
  if (context === void 0) {
    throw new Error("useHostedConfig must be used within a HostedConfigProvider");
  }
  return context;
}
function useHostedSearchParams() {
  if (typeof window === "undefined") {
    return { tenant_id: "" };
  }
  const params = new URLSearchParams(window.location.search);
  return {
    tenant_id: params.get("tenant_id") || "",
    redirect_url: params.get("redirect_url") || void 0,
    oauth_callback: params.get("oauth_callback") || void 0,
    organization_id: params.get("organization_id") || void 0,
    error: params.get("error") || void 0,
    message: params.get("message") || void 0
  };
}
function HostedLayout({ children, searchParams, title, description }) {
  return /* @__PURE__ */ jsx(HostedConfigProvider, { searchParams, children: /* @__PURE__ */ jsx(HostedLayoutInner, { title, description, children }) });
}
function HostedLayoutInner({ children, title, description }) {
  const { config, isLoading, error, tenantId } = useHostedConfig();
  const prefersReducedMotion = useReducedMotion();
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
  }, []);
  if (isLoading) {
    return /* @__PURE__ */ jsx("div", { className: "min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted p-4", children: /* @__PURE__ */ jsxs("div", { className: "flex flex-col items-center gap-4", children: [
      /* @__PURE__ */ jsx(Loader2, { className: "h-8 w-8 animate-spin text-primary" }),
      /* @__PURE__ */ jsx("p", { className: "text-muted-foreground text-sm", children: "Loading..." })
    ] }) });
  }
  if (error || !tenantId) {
    return /* @__PURE__ */ jsx("div", { className: "min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted p-4", children: /* @__PURE__ */ jsx("div", { className: "w-full max-w-md", children: /* @__PURE__ */ jsxs(Alert, { variant: "destructive", children: [
      /* @__PURE__ */ jsx(AlertCircle, { className: "h-4 w-4" }),
      /* @__PURE__ */ jsx(AlertTitle, { children: "Configuration Error" }),
      /* @__PURE__ */ jsx(AlertDescription, { children: error || "Missing tenant_id parameter. Please check your URL and try again." })
    ] }) }) });
  }
  const companyName = config?.companyName || "Vault";
  const pageTitle = title || config?.signInTitle || `Sign in to ${companyName}`;
  const pageDescription = description || "Secure authentication powered by Vault";
  return /* @__PURE__ */ jsxs("div", { className: "min-h-screen flex flex-col bg-gradient-to-br from-background via-background to-muted", children: [
    /* @__PURE__ */ jsxs("div", { className: "fixed inset-0 overflow-hidden pointer-events-none", children: [
      /* @__PURE__ */ jsx(
        "div",
        {
          className: "absolute -top-1/2 -right-1/2 w-full h-full rounded-full blur-3xl opacity-30",
          style: {
            backgroundColor: config?.primaryColor ? `${config.primaryColor}20` : "hsl(var(--primary) / 0.05)"
          }
        }
      ),
      /* @__PURE__ */ jsx(
        "div",
        {
          className: "absolute -bottom-1/2 -left-1/2 w-full h-full rounded-full blur-3xl opacity-30",
          style: {
            backgroundColor: config?.primaryColor ? `${config.primaryColor}10` : "hsl(var(--secondary) / 0.05)"
          }
        }
      )
    ] }),
    /* @__PURE__ */ jsx("header", { className: "relative z-10 w-full p-4 sm:p-6", children: /* @__PURE__ */ jsx("div", { className: "max-w-md mx-auto flex items-center justify-center", children: /* @__PURE__ */ jsx(HostedLogo, {}) }) }),
    /* @__PURE__ */ jsx("main", { className: "relative z-10 flex-1 flex items-center justify-center p-4 sm:p-6", children: /* @__PURE__ */ jsx(
      motion.div,
      {
        initial: prefersReducedMotion ? false : { opacity: 0, y: 20 },
        animate: { opacity: 1, y: 0 },
        transition: prefersReducedMotion ? { duration: 0 } : { duration: 0.5 },
        className: "w-full max-w-md",
        children: mounted && /* @__PURE__ */ jsxs(Fragment, { children: [
          (title || description) && /* @__PURE__ */ jsxs("div", { className: "text-center mb-6", children: [
            /* @__PURE__ */ jsx("h1", { className: "text-2xl font-bold", children: pageTitle }),
            /* @__PURE__ */ jsx("p", { className: "text-muted-foreground mt-1", children: pageDescription })
          ] }),
          children
        ] })
      }
    ) }),
    /* @__PURE__ */ jsx("footer", { className: "relative z-10 w-full p-4 sm:p-6", children: /* @__PURE__ */ jsxs("div", { className: "max-w-md mx-auto text-center", children: [
      /* @__PURE__ */ jsxs("p", { className: "text-xs text-muted-foreground", children: [
        "Secured by",
        " ",
        /* @__PURE__ */ jsx(
          "a",
          {
            href: "https://vault.dev",
            target: "_blank",
            rel: "noopener noreferrer",
            className: "hover:text-foreground transition-colors",
            children: "Vault"
          }
        )
      ] }),
      (config?.termsUrl || config?.privacyUrl) && /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-center gap-4 mt-2", children: [
        config.termsUrl && /* @__PURE__ */ jsx(
          "a",
          {
            href: config.termsUrl,
            className: "text-xs text-muted-foreground hover:text-foreground transition-colors",
            children: "Terms"
          }
        ),
        config.privacyUrl && /* @__PURE__ */ jsx(
          "a",
          {
            href: config.privacyUrl,
            className: "text-xs text-muted-foreground hover:text-foreground transition-colors",
            children: "Privacy"
          }
        )
      ] })
    ] }) })
  ] });
}
function HostedLogo() {
  const { config } = useHostedConfig();
  const prefersReducedMotion = useReducedMotion();
  if (config?.logoUrl) {
    return /* @__PURE__ */ jsxs(
      motion.div,
      {
        initial: prefersReducedMotion ? false : { scale: 0.8 },
        animate: { scale: 1 },
        transition: prefersReducedMotion ? { duration: 0 } : { delay: 0.2, type: "spring" },
        className: "flex items-center gap-3",
        children: [
          /* @__PURE__ */ jsx(
            "img",
            {
              src: config.logoUrl,
              alt: config.companyName,
              className: "h-12 w-auto object-contain"
            }
          ),
          /* @__PURE__ */ jsx("span", { className: "text-xl font-semibold", children: config.companyName })
        ]
      }
    );
  }
  return /* @__PURE__ */ jsxs(
    motion.div,
    {
      initial: prefersReducedMotion ? false : { scale: 0.8 },
      animate: { scale: 1 },
      transition: prefersReducedMotion ? { duration: 0 } : { delay: 0.2, type: "spring" },
      className: "flex items-center gap-3",
      children: [
        /* @__PURE__ */ jsx(
          "div",
          {
            className: "h-12 w-12 rounded-xl flex items-center justify-center shadow-lg",
            style: { backgroundColor: config?.primaryColor || "hsl(var(--primary))" },
            children: /* @__PURE__ */ jsx(Shield, { className: "h-7 w-7 text-white" })
          }
        ),
        /* @__PURE__ */ jsx("span", { className: "text-xl font-semibold", children: config?.companyName || "Vault" })
      ]
    }
  );
}
export {
  HostedLayout as H,
  useHostedConfig as a,
  hostedSignUp as b,
  hostedOAuthStart as c,
  hostedSignIn as d,
  hostedSendMagicLink as e,
  hostedOAuthCallback as f,
  hostedVerifyMfa as g,
  hostedVerifyEmail as h,
  hostedRequestPasswordReset as i,
  hostedListOrganizations as j,
  hostedSwitchOrganization as k,
  hostedCreateOrganization as l,
  useHostedSearchParams as u
};
