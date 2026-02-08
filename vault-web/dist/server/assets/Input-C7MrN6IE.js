import { jsxs, jsx } from "react/jsx-runtime";
import * as React from "react";
import { j as cn } from "./router-BDwxh4pl.js";
const Input = React.forwardRef(
  ({
    className,
    type,
    error,
    label,
    helperText,
    leftIcon,
    rightIcon,
    fullWidth,
    id,
    ...props
  }, ref) => {
    const inputId = id || React.useId();
    const hasError = !!error;
    return /* @__PURE__ */ jsxs("div", { className: cn("space-y-1.5", fullWidth && "w-full"), children: [
      label && /* @__PURE__ */ jsxs(
        "label",
        {
          htmlFor: inputId,
          className: "text-sm font-medium text-foreground",
          children: [
            label,
            props.required && /* @__PURE__ */ jsx("span", { className: "text-destructive ml-1", children: "*" })
          ]
        }
      ),
      /* @__PURE__ */ jsxs("div", { className: "relative", children: [
        leftIcon && /* @__PURE__ */ jsx("div", { className: "absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground", children: leftIcon }),
        /* @__PURE__ */ jsx(
          "input",
          {
            type,
            id: inputId,
            className: cn(
              "flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background transition-colors transition-shadow duration-200",
              "file:border-0 file:bg-transparent file:text-sm file:font-medium",
              "placeholder:text-muted-foreground",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
              "disabled:cursor-not-allowed disabled:opacity-50",
              "hover:border-muted-foreground/30",
              hasError && "border-destructive focus-visible:ring-destructive",
              leftIcon && "pl-10",
              rightIcon && "pr-10",
              className
            ),
            ref,
            "aria-invalid": hasError,
            "aria-describedby": hasError ? `${inputId}-error` : void 0,
            ...props
          }
        ),
        rightIcon && /* @__PURE__ */ jsx("div", { className: "absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground", children: rightIcon })
      ] }),
      hasError ? /* @__PURE__ */ jsx(
        "p",
        {
          id: `${inputId}-error`,
          className: "text-sm text-destructive animate-fade-in",
          children: error
        }
      ) : helperText ? /* @__PURE__ */ jsx("p", { className: "text-sm text-muted-foreground", children: helperText }) : null
    ] });
  }
);
Input.displayName = "Input";
export {
  Input as I
};
