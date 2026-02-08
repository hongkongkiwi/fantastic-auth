import { jsxs, jsx } from "react/jsx-runtime";
import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Plus, Building2, Users, Shield, ChevronRight, MoreHorizontal } from "lucide-react";
import { motion } from "framer-motion";
import { P as PageHeader, B as Button } from "./router-BDwxh4pl.js";
import { C as Card } from "./Card-Brxgy2gk.js";
import { B as Badge } from "./Badge-DmGWtXSM.js";
import { D as DropdownMenu, a as DropdownMenuTrigger, b as DropdownMenuContent, c as DropdownMenuItem } from "./DropdownMenu-CUcXj7WN.js";
import "react";
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
import "@radix-ui/react-dropdown-menu";
function OrganizationsPage() {
  const {
    data: organizations,
    isLoading
  } = useQuery({
    queryKey: ["organizations"],
    queryFn: async () => {
      const res = await fetch("/api/v1/admin/organizations");
      if (!res.ok) throw new Error("Failed to load organizations");
      return res.json();
    }
  });
  return /* @__PURE__ */ jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsx(PageHeader, { title: "Organizations", description: "Manage teams and organizations", actions: /* @__PURE__ */ jsxs(Button, { children: [
      /* @__PURE__ */ jsx(Plus, { className: "mr-2 h-4 w-4" }),
      "New Organization"
    ] }) }),
    /* @__PURE__ */ jsx("div", { className: "grid gap-4", children: isLoading ? /* @__PURE__ */ jsx(Card, { className: "p-8 text-center", children: /* @__PURE__ */ jsxs("div", { className: "animate-pulse space-y-4", children: [
      /* @__PURE__ */ jsx("div", { className: "h-12 w-12 bg-muted rounded-full mx-auto" }),
      /* @__PURE__ */ jsx("div", { className: "h-4 w-48 bg-muted rounded mx-auto" })
    ] }) }) : organizations?.length === 0 ? /* @__PURE__ */ jsxs(Card, { className: "p-8 text-center", children: [
      /* @__PURE__ */ jsx(Building2, { className: "h-12 w-12 mx-auto text-muted-foreground/50 mb-4" }),
      /* @__PURE__ */ jsx("h3", { className: "text-lg font-medium", children: "No organizations" }),
      /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground mt-1", children: "Create an organization to start collaborating with your team" }),
      /* @__PURE__ */ jsxs(Button, { className: "mt-4", children: [
        /* @__PURE__ */ jsx(Plus, { className: "mr-2 h-4 w-4" }),
        "Create Organization"
      ] })
    ] }) : organizations?.map((org, index) => /* @__PURE__ */ jsx(motion.div, { initial: {
      opacity: 0,
      y: 20
    }, animate: {
      opacity: 1,
      y: 0
    }, transition: {
      delay: index * 0.1
    }, children: /* @__PURE__ */ jsx(Card, { className: "p-6 hover:shadow-md transition-shadow", children: /* @__PURE__ */ jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-4", children: [
        /* @__PURE__ */ jsx("div", { className: "h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center", children: /* @__PURE__ */ jsx(Building2, { className: "h-6 w-6 text-primary" }) }),
        /* @__PURE__ */ jsxs("div", { children: [
          /* @__PURE__ */ jsx("h3", { className: "font-semibold", children: org.name }),
          /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-3 mt-1", children: [
            /* @__PURE__ */ jsxs("span", { className: "text-sm text-muted-foreground", children: [
              "@",
              org.slug
            ] }),
            /* @__PURE__ */ jsxs(Badge, { variant: "secondary", className: "gap-1", children: [
              /* @__PURE__ */ jsx(Users, { className: "h-3 w-3" }),
              org.member_count,
              " members"
            ] }),
            org.sso_enabled && /* @__PURE__ */ jsxs(Badge, { variant: "outline", className: "gap-1", children: [
              /* @__PURE__ */ jsx(Shield, { className: "h-3 w-3" }),
              "SSO"
            ] })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsx(Button, { variant: "ghost", size: "sm", asChild: true, children: /* @__PURE__ */ jsxs(Link, { to: "/organizations", children: [
          "Manage",
          /* @__PURE__ */ jsx(ChevronRight, { className: "ml-1 h-4 w-4" })
        ] }) }),
        /* @__PURE__ */ jsxs(DropdownMenu, { children: [
          /* @__PURE__ */ jsx(DropdownMenuTrigger, { asChild: true, children: /* @__PURE__ */ jsx(Button, { variant: "ghost", size: "icon", "aria-label": "Open organization actions", children: /* @__PURE__ */ jsx(MoreHorizontal, { className: "h-4 w-4" }) }) }),
          /* @__PURE__ */ jsxs(DropdownMenuContent, { align: "end", children: [
            /* @__PURE__ */ jsx(DropdownMenuItem, { children: "View Settings" }),
            /* @__PURE__ */ jsx(DropdownMenuItem, { children: "Manage Members" }),
            org.role === "owner" && /* @__PURE__ */ jsx(DropdownMenuItem, { className: "text-destructive", children: "Delete Organization" })
          ] })
        ] })
      ] })
    ] }) }) }, org.id)) })
  ] });
}
export {
  OrganizationsPage as component
};
