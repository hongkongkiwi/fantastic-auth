import { jsx, jsxs } from "react/jsx-runtime";
import * as React from "react";
import * as CheckboxPrimitive from "@radix-ui/react-checkbox";
import { Minus, Check } from "lucide-react";
import { j as cn } from "./router-BDwxh4pl.js";
const Checkbox = React.forwardRef(({ className, label, description, error, indeterminate, ...props }, ref) => {
  const innerRef = React.useRef(null);
  React.useImperativeHandle(ref, () => innerRef.current);
  React.useEffect(() => {
    if (innerRef.current) {
      innerRef.current.indeterminate = indeterminate ?? false;
    }
  }, [indeterminate]);
  const checkboxContent = /* @__PURE__ */ jsx(
    CheckboxPrimitive.Root,
    {
      ref: innerRef,
      className: cn(
        "peer h-4 w-4 shrink-0 rounded-sm border border-primary shadow",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
        "disabled:cursor-not-allowed disabled:opacity-50",
        "data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground",
        "data-[state=indeterminate]:bg-primary data-[state=indeterminate]:text-primary-foreground",
        error && "border-destructive focus-visible:ring-destructive",
        className
      ),
      ...props,
      children: /* @__PURE__ */ jsx(
        CheckboxPrimitive.Indicator,
        {
          className: cn("flex items-center justify-center text-current"),
          children: indeterminate ? /* @__PURE__ */ jsx(Minus, { className: "h-3 w-3" }) : /* @__PURE__ */ jsx(Check, { className: "h-3 w-3" })
        }
      )
    }
  );
  if (!label && !description) {
    return checkboxContent;
  }
  return /* @__PURE__ */ jsxs("div", { className: "flex items-start gap-3", children: [
    checkboxContent,
    /* @__PURE__ */ jsxs("div", { className: "grid gap-1.5 leading-none", children: [
      label && /* @__PURE__ */ jsx(
        "label",
        {
          htmlFor: props.id,
          className: cn(
            "text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70",
            error && "text-destructive"
          ),
          children: label
        }
      ),
      description && /* @__PURE__ */ jsx("p", { className: "text-xs text-muted-foreground", children: description }),
      error && /* @__PURE__ */ jsx("p", { className: "text-xs text-destructive", children: error })
    ] })
  ] });
});
Checkbox.displayName = CheckboxPrimitive.Root.displayName;
export {
  Checkbox as C
};
