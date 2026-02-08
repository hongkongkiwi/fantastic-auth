import { jsx, jsxs } from "react/jsx-runtime";
import { useState, useEffect } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Smartphone, Mail, Shield, Check, Copy, Download } from "lucide-react";
import { B as Button } from "./router-BDwxh4pl.js";
import { I as Input } from "./Input-C7MrN6IE.js";
import { QRCodeSVG } from "qrcode.react";
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
function MfaEnroll({ method, onEnroll, onCancel }) {
  const [step, setStep] = useState("intro");
  const [verificationCode, setVerificationCode] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [totpData, setTotpData] = useState(null);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);
  useEffect(() => {
    if (method === "totp" && step === "setup") {
      fetch("/api/v1/auth/mfa/totp/enroll", { method: "POST" }).then((res) => res.json()).then((data) => setTotpData(data)).catch(() => setError("Failed to generate TOTP secret"));
    }
  }, [method, step]);
  const handleVerify = async () => {
    setIsLoading(true);
    setError("");
    try {
      await onEnroll(verificationCode);
      if (method === "totp") {
        setStep("backup");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid code");
    } finally {
      setIsLoading(false);
    }
  };
  const copyToClipboard = (text, setCopied) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2e3);
  };
  const downloadBackupCodes = () => {
    if (!totpData) return;
    const content = totpData.backup_codes.join("\n");
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vault-backup-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  };
  const methodConfig = {
    totp: {
      icon: Shield,
      title: "Authenticator App",
      description: "Use an app like Google Authenticator, Authy, or 1Password"
    },
    email: {
      icon: Mail,
      title: "Email Verification",
      description: "Receive codes via email"
    },
    sms: {
      icon: Smartphone,
      title: "SMS Verification",
      description: "Receive codes via text message"
    }
  };
  const config = methodConfig[method];
  const Icon = config.icon;
  return /* @__PURE__ */ jsx("div", { className: "w-full max-w-md mx-auto", children: /* @__PURE__ */ jsxs(AnimatePresence, { mode: "wait", children: [
    step === "intro" && /* @__PURE__ */ jsxs(
      motion.div,
      {
        initial: { opacity: 0, y: 20 },
        animate: { opacity: 1, y: 0 },
        exit: { opacity: 0, y: -20 },
        className: "text-center space-y-6",
        children: [
          /* @__PURE__ */ jsx("div", { className: "w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center mx-auto", children: /* @__PURE__ */ jsx(Icon, { className: "w-8 h-8 text-primary" }) }),
          /* @__PURE__ */ jsxs("div", { children: [
            /* @__PURE__ */ jsx("h3", { className: "text-xl font-semibold", children: config.title }),
            /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground mt-2", children: config.description })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "flex gap-3", children: [
            /* @__PURE__ */ jsx(Button, { variant: "outline", onClick: onCancel, className: "flex-1", children: "Cancel" }),
            /* @__PURE__ */ jsx(Button, { onClick: () => setStep("setup"), className: "flex-1", children: "Continue" })
          ] })
        ]
      },
      "intro"
    ),
    step === "setup" && method === "totp" && totpData && /* @__PURE__ */ jsxs(
      motion.div,
      {
        initial: { opacity: 0, y: 20 },
        animate: { opacity: 1, y: 0 },
        exit: { opacity: 0, y: -20 },
        className: "space-y-6",
        children: [
          /* @__PURE__ */ jsxs("div", { className: "text-center", children: [
            /* @__PURE__ */ jsx("h3", { className: "text-lg font-semibold", children: "Scan QR Code" }),
            /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Open your authenticator app and scan this code" })
          ] }),
          /* @__PURE__ */ jsx("div", { className: "flex justify-center", children: /* @__PURE__ */ jsx("div", { className: "p-4 bg-white rounded-lg", children: /* @__PURE__ */ jsx(QRCodeSVG, { value: totpData.qr_uri, size: 200 }) }) }),
          /* @__PURE__ */ jsxs("div", { className: "space-y-2", children: [
            /* @__PURE__ */ jsx("p", { className: "text-xs text-center text-muted-foreground", children: "Can't scan? Enter this code manually:" }),
            /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
              /* @__PURE__ */ jsx("code", { className: "flex-1 p-2 bg-muted rounded text-center text-sm font-mono", children: totpData.secret }),
              /* @__PURE__ */ jsx(
                Button,
                {
                  variant: "ghost",
                  size: "icon",
                  "aria-label": copiedSecret ? "Secret copied" : "Copy setup secret",
                  onClick: () => copyToClipboard(totpData.secret, setCopiedSecret),
                  children: copiedSecret ? /* @__PURE__ */ jsx(Check, { className: "h-4 w-4" }) : /* @__PURE__ */ jsx(Copy, { className: "h-4 w-4" })
                }
              )
            ] })
          ] }),
          /* @__PURE__ */ jsx(Button, { onClick: () => setStep("verify"), fullWidth: true, children: "I've scanned the code" })
        ]
      },
      "setup"
    ),
    step === "verify" && /* @__PURE__ */ jsxs(
      motion.div,
      {
        initial: { opacity: 0, y: 20 },
        animate: { opacity: 1, y: 0 },
        exit: { opacity: 0, y: -20 },
        className: "space-y-6",
        children: [
          /* @__PURE__ */ jsxs("div", { className: "text-center", children: [
            /* @__PURE__ */ jsx("h3", { className: "text-lg font-semibold", children: "Verify Setup" }),
            /* @__PURE__ */ jsxs("p", { className: "text-sm text-muted-foreground", children: [
              "Enter the 6-digit code from your ",
              method === "totp" ? "authenticator app" : method
            ] })
          ] }),
          /* @__PURE__ */ jsx("div", { className: "space-y-2", children: /* @__PURE__ */ jsx(
            Input,
            {
              type: "text",
              placeholder: "000000",
              value: verificationCode,
              onChange: (e) => setVerificationCode(e.target.value.replace(/\D/g, "").slice(0, 6)),
              className: "text-center text-2xl tracking-widest font-mono",
              maxLength: 6,
              name: "verificationCode",
              autoComplete: "one-time-code",
              inputMode: "numeric",
              "aria-label": "Verification code",
              error
            }
          ) }),
          /* @__PURE__ */ jsxs("div", { className: "flex gap-3", children: [
            /* @__PURE__ */ jsx(
              Button,
              {
                variant: "outline",
                onClick: () => setStep(method === "totp" ? "setup" : "intro"),
                className: "flex-1",
                children: "Back"
              }
            ),
            /* @__PURE__ */ jsx(
              Button,
              {
                onClick: handleVerify,
                disabled: verificationCode.length !== 6 || isLoading,
                className: "flex-1",
                isLoading,
                children: "Verify"
              }
            )
          ] })
        ]
      },
      "verify"
    ),
    step === "backup" && totpData && /* @__PURE__ */ jsxs(
      motion.div,
      {
        initial: { opacity: 0, y: 20 },
        animate: { opacity: 1, y: 0 },
        exit: { opacity: 0, y: -20 },
        className: "space-y-6",
        children: [
          /* @__PURE__ */ jsxs("div", { className: "text-center", children: [
            /* @__PURE__ */ jsx("div", { className: "w-12 h-12 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto mb-4", children: /* @__PURE__ */ jsx(Check, { className: "w-6 h-6 text-green-600 dark:text-green-400" }) }),
            /* @__PURE__ */ jsx("h3", { className: "text-lg font-semibold", children: "MFA Enabled!" }),
            /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: "Save these backup codes in a safe place" })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800 rounded-lg p-4", children: [
            /* @__PURE__ */ jsx("p", { className: "text-xs text-amber-800 dark:text-amber-200 mb-3", children: "⚠️ These codes can be used to access your account if you lose your authenticator device. Each code can only be used once." }),
            /* @__PURE__ */ jsx("div", { className: "grid grid-cols-2 gap-2", children: totpData.backup_codes.map((code) => /* @__PURE__ */ jsx("code", { className: "text-sm font-mono text-center", children: code }, code)) })
          ] }),
          /* @__PURE__ */ jsxs("div", { className: "flex gap-3", children: [
            /* @__PURE__ */ jsxs(
              Button,
              {
                variant: "outline",
                onClick: () => copyToClipboard(totpData.backup_codes.join("\n"), setCopiedCodes),
                className: "flex-1 gap-2",
                children: [
                  copiedCodes ? /* @__PURE__ */ jsx(Check, { className: "h-4 w-4" }) : /* @__PURE__ */ jsx(Copy, { className: "h-4 w-4" }),
                  "Copy Codes"
                ]
              }
            ),
            /* @__PURE__ */ jsxs(
              Button,
              {
                variant: "outline",
                onClick: downloadBackupCodes,
                className: "flex-1 gap-2",
                children: [
                  /* @__PURE__ */ jsx(Download, { className: "h-4 w-4" }),
                  "Download"
                ]
              }
            )
          ] }),
          /* @__PURE__ */ jsx(Button, { onClick: onCancel, fullWidth: true, children: "Done" })
        ]
      },
      "backup"
    )
  ] }) });
}
export {
  MfaEnroll
};
