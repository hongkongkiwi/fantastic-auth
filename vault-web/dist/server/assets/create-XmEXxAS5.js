import { jsxs, jsx } from "react/jsx-runtime";
import { useNavigate, Link } from "@tanstack/react-router";
import { useState } from "react";
import { useReducedMotion, motion } from "framer-motion";
import { ArrowLeft, Check } from "lucide-react";
import { u as useServerFn, P as PageHeader, B as Button, j as cn, t as toast, G as createTenant } from "./router-BDwxh4pl.js";
import { C as Card, a as CardHeader, b as CardTitle, c as CardDescription, d as CardContent } from "./Card-Brxgy2gk.js";
import { I as Input } from "./Input-C7MrN6IE.js";
import { B as Badge } from "./Badge-DmGWtXSM.js";
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
const plans = [{
  value: "free",
  label: "Free"
}, {
  value: "starter",
  label: "Starter"
}, {
  value: "pro",
  label: "Pro"
}, {
  value: "enterprise",
  label: "Enterprise"
}];
function CreateTenantPage() {
  const navigate = useNavigate();
  const createTenantFn = useServerFn(createTenant);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState({
    name: "",
    slug: "",
    plan: "starter",
    ownerEmail: "",
    ownerName: "",
    customDomain: ""
  });
  const [errors, setErrors] = useState({});
  const prefersReducedMotion = useReducedMotion();
  const validateStep = (currentStep) => {
    const newErrors = {};
    if (currentStep === 1) {
      if (!formData.name.trim()) {
        newErrors.name = "Tenant name is required";
      }
      if (!formData.slug.trim()) {
        newErrors.slug = "Slug is required";
      } else if (!/^[a-z0-9-]+$/.test(formData.slug)) {
        newErrors.slug = "Slug can only contain lowercase letters, numbers, and hyphens";
      }
    }
    if (currentStep === 2) {
      if (formData.ownerEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.ownerEmail)) {
        newErrors.ownerEmail = "Please enter a valid email";
      }
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };
  const handleNext = () => {
    if (validateStep(step)) {
      setStep(step + 1);
    }
  };
  const handleBack = () => {
    setStep(step - 1);
  };
  const handleSubmit = async () => {
    if (!validateStep(step)) return;
    setIsSubmitting(true);
    try {
      await createTenantFn({
        data: {
          name: formData.name,
          slug: formData.slug,
          plan: formData.plan,
          ownerEmail: formData.ownerEmail || void 0,
          ownerName: formData.ownerName || void 0,
          customDomain: formData.customDomain || void 0
        }
      });
      toast.success("Tenant created successfully");
      navigate({
        to: "/tenants"
      });
    } catch (error) {
      toast.error("Failed to create tenant");
    } finally {
      setIsSubmitting(false);
    }
  };
  const steps = [{
    number: 1,
    title: "Basic Info",
    description: "Tenant name and slug"
  }, {
    number: 2,
    title: "Plan",
    description: "Select subscription tier"
  }, {
    number: 3,
    title: "Owner",
    description: "Set up owner details"
  }];
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6 max-w-3xl", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "Create Tenant", description: "Set up a new tenant on your platform", breadcrumbs: [{
      label: "Tenants",
      href: "/tenants"
    }, {
      label: "Create"
    }], actions: /* @__PURE__ */ jsx(Button, { variant: "outline", asChild: true, children: /* @__PURE__ */ jsxs(Link, { to: "/tenants", children: [
      /* @__PURE__ */ jsx(ArrowLeft, { className: "mr-2 h-4 w-4" }),
      "Back to Tenants"
    ] }) }) }),
    /* @__PURE__ */ jsx(Card, { className: "p-6", children: /* @__PURE__ */ jsx("div", { className: "flex items-center justify-between", children: steps.map((s, index) => /* @__PURE__ */ jsxs("div", { className: "flex items-center", children: [
      /* @__PURE__ */ jsxs("div", { className: "flex flex-col items-center", children: [
        /* @__PURE__ */ jsx("div", { className: cn("w-10 h-10 rounded-full flex items-center justify-center font-semibold transition-colors", step > s.number && "bg-green-500 text-white", step === s.number && "bg-primary text-primary-foreground", step < s.number && "bg-muted text-muted-foreground"), children: step > s.number ? /* @__PURE__ */ jsx(Check, { className: "h-5 w-5" }) : s.number }),
        /* @__PURE__ */ jsxs("div", { className: "mt-2 text-center hidden sm:block", children: [
          /* @__PURE__ */ jsx("p", { className: cn("text-sm font-medium", step >= s.number ? "text-foreground" : "text-muted-foreground"), children: s.title }),
          /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: s.description })
        ] })
      ] }),
      index < steps.length - 1 && /* @__PURE__ */ jsx("div", { className: cn("w-24 h-0.5 mx-4 hidden sm:block", step > s.number ? "bg-green-500" : "bg-muted") })
    ] }, s.number)) }) }),
    /* @__PURE__ */ jsx(motion.div, { initial: prefersReducedMotion ? false : {
      opacity: 0,
      x: 20
    }, animate: {
      opacity: 1,
      x: 0
    }, exit: {
      opacity: 0,
      x: -20
    }, transition: prefersReducedMotion ? {
      duration: 0
    } : {
      duration: 0.2
    }, children: /* @__PURE__ */ jsxs(Card, { children: [
      /* @__PURE__ */ jsxs(CardHeader, { children: [
        /* @__PURE__ */ jsx(CardTitle, { children: steps[step - 1].title }),
        /* @__PURE__ */ jsx(CardDescription, { children: steps[step - 1].description })
      ] }),
      /* @__PURE__ */ jsxs(CardContent, { className: "space-y-6", children: [
        step === 1 && /* @__PURE__ */ jsxs("div", { className: "space-y-4", children: [
          /* @__PURE__ */ jsx(Input, { label: "Tenant Name", placeholder: "Acme Corporation", value: formData.name, onChange: (e) => setFormData({
            ...formData,
            name: e.target.value
          }), error: errors.name, name: "tenantName", autoComplete: "off", required: true }),
          /* @__PURE__ */ jsx(Input, { label: "Slug", placeholder: "acme-corp", value: formData.slug, onChange: (e) => setFormData({
            ...formData,
            slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "")
          }), error: errors.slug, helperText: "Used in URLs and API calls. Lowercase letters, numbers, and hyphens only.", name: "tenantSlug", autoComplete: "off", required: true }),
          /* @__PURE__ */ jsx(Input, { label: "Custom Domain (Optional)", type: "url", placeholder: "auth.acme.com", value: formData.customDomain, onChange: (e) => setFormData({
            ...formData,
            customDomain: e.target.value
          }), name: "customDomain", autoComplete: "off" })
        ] }),
        step === 2 && /* @__PURE__ */ jsxs("div", { className: "space-y-4", children: [
          /* @__PURE__ */ jsx("label", { className: "text-sm font-medium", children: "Select Plan" }),
          /* @__PURE__ */ jsx("div", { className: "grid grid-cols-1 sm:grid-cols-2 gap-4", children: plans.map((plan) => /* @__PURE__ */ jsxs("button", { type: "button", onClick: () => setFormData({
            ...formData,
            plan: plan.value
          }), className: cn("p-4 rounded-lg border-2 text-left transition-colors transition-shadow focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary", formData.plan === plan.value ? "border-primary bg-primary/5" : "border-muted hover:border-muted-foreground/30"), "aria-pressed": formData.plan === plan.value, children: [
            /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
              /* @__PURE__ */ jsx(Badge, { variant: plan.value === "enterprise" ? "warning" : plan.value === "pro" ? "success" : "default", children: plan.label }),
              formData.plan === plan.value && /* @__PURE__ */ jsx("div", { className: "h-5 w-5 rounded-full bg-primary flex items-center justify-center", children: /* @__PURE__ */ jsx(Check, { className: "h-3 w-3 text-primary-foreground" }) })
            ] }),
            /* @__PURE__ */ jsxs("p", { className: "mt-2 text-sm text-muted-foreground", children: [
              plan.value === "free" && "Up to 100 users, basic features",
              plan.value === "starter" && "Up to 1,000 users, advanced features",
              plan.value === "pro" && "Up to 10,000 users, priority support",
              plan.value === "enterprise" && "Unlimited users, dedicated support"
            ] })
          ] }, plan.value)) })
        ] }),
        step === 3 && /* @__PURE__ */ jsxs("div", { className: "space-y-4", children: [
          /* @__PURE__ */ jsx(Input, { label: "Owner Name (Optional)", placeholder: "John Doe", value: formData.ownerName, onChange: (e) => setFormData({
            ...formData,
            ownerName: e.target.value
          }), name: "ownerName", autoComplete: "off" }),
          /* @__PURE__ */ jsx(Input, { label: "Owner Email (Optional)", type: "email", placeholder: "john@example.com", value: formData.ownerEmail, onChange: (e) => setFormData({
            ...formData,
            ownerEmail: e.target.value
          }), error: errors.ownerEmail, name: "ownerEmail", autoComplete: "email", inputMode: "email", spellCheck: false }),
          /* @__PURE__ */ jsxs("div", { className: "mt-6 p-4 bg-muted rounded-lg", children: [
            /* @__PURE__ */ jsx("h4", { className: "font-medium mb-3", children: "Summary" }),
            /* @__PURE__ */ jsxs("dl", { className: "space-y-2 text-sm", children: [
              /* @__PURE__ */ jsxs("div", { className: "flex justify-between", children: [
                /* @__PURE__ */ jsx("dt", { className: "text-muted-foreground", children: "Tenant Name" }),
                /* @__PURE__ */ jsx("dd", { className: "font-medium", children: formData.name })
              ] }),
              /* @__PURE__ */ jsxs("div", { className: "flex justify-between", children: [
                /* @__PURE__ */ jsx("dt", { className: "text-muted-foreground", children: "Slug" }),
                /* @__PURE__ */ jsx("dd", { className: "font-medium", children: formData.slug })
              ] }),
              /* @__PURE__ */ jsxs("div", { className: "flex justify-between", children: [
                /* @__PURE__ */ jsx("dt", { className: "text-muted-foreground", children: "Plan" }),
                /* @__PURE__ */ jsx("dd", { children: /* @__PURE__ */ jsx(Badge, { variant: formData.plan === "enterprise" ? "warning" : formData.plan === "pro" ? "success" : "default", children: formData.plan.charAt(0).toUpperCase() + formData.plan.slice(1) }) })
              ] }),
              formData.ownerName && /* @__PURE__ */ jsxs("div", { className: "flex justify-between", children: [
                /* @__PURE__ */ jsx("dt", { className: "text-muted-foreground", children: "Owner" }),
                /* @__PURE__ */ jsx("dd", { className: "font-medium", children: formData.ownerName })
              ] })
            ] })
          ] })
        ] }),
        /* @__PURE__ */ jsxs("div", { className: "flex justify-between pt-4", children: [
          step === 1 ? /* @__PURE__ */ jsx(Button, { variant: "outline", asChild: true, children: /* @__PURE__ */ jsx(Link, { to: "/tenants", children: "Cancel" }) }) : /* @__PURE__ */ jsx(Button, { variant: "outline", onClick: handleBack, children: "Back" }),
          /* @__PURE__ */ jsx(Button, { onClick: step === 3 ? handleSubmit : handleNext, isLoading: isSubmitting, children: step === 3 ? "Create Tenant" : "Continue" })
        ] })
      ] })
    ] }) }, step)
  ] });
}
export {
  CreateTenantPage as component
};
