import { jsx } from "react/jsx-runtime";
import * as React from "react";
import { j as cn } from "./router-BDwxh4pl.js";
const Card = React.forwardRef(({ className, variant = "default", hover = false, padding = "default", ...props }, ref) => /* @__PURE__ */ jsx(
  "div",
  {
    ref,
    className: cn(
      "rounded-xl border text-card-foreground shadow-card",
      variant === "default" && "bg-card",
      variant === "glass" && "glass border-white/20 dark:border-white/10",
      variant === "outline" && "bg-transparent",
      hover && "card-hover cursor-pointer",
      padding === "none" && "",
      padding === "sm" && "p-4",
      padding === "default" && "p-6",
      padding === "lg" && "p-8",
      className
    ),
    ...props
  }
));
Card.displayName = "Card";
const CardHeader = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  "div",
  {
    ref,
    className: cn("flex flex-col space-y-1.5", className),
    ...props
  }
));
CardHeader.displayName = "CardHeader";
const CardTitle = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  "h3",
  {
    ref,
    className: cn("font-semibold leading-none tracking-tight", className),
    ...props
  }
));
CardTitle.displayName = "CardTitle";
const CardDescription = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  "p",
  {
    ref,
    className: cn("text-sm text-muted-foreground", className),
    ...props
  }
));
CardDescription.displayName = "CardDescription";
const CardContent = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx("div", { ref, className: cn("", className), ...props }));
CardContent.displayName = "CardContent";
const CardFooter = React.forwardRef(({ className, ...props }, ref) => /* @__PURE__ */ jsx(
  "div",
  {
    ref,
    className: cn("flex items-center gap-2", className),
    ...props
  }
));
CardFooter.displayName = "CardFooter";
export {
  Card as C,
  CardHeader as a,
  CardTitle as b,
  CardDescription as c,
  CardContent as d
};
