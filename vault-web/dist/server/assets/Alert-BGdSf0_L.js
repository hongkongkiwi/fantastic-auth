import { jsx } from "react/jsx-runtime";
import * as React from "react";
import { cva } from "class-variance-authority";
import { j as cn } from "./router-BDwxh4pl.js";
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
export {
  Alert as A,
  AlertDescription as a,
  AlertTitle as b
};
