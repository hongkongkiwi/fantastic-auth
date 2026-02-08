import { jsxs, jsx } from "react/jsx-runtime";
import { cva } from "class-variance-authority";
import { j as cn } from "./router-BDwxh4pl.js";
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
export {
  Badge as B
};
