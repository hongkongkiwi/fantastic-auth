import { jsx, jsxs } from "react/jsx-runtime";
import { c as cn } from "./router-BqFKwE1w.js";
function Skeleton({
  className,
  variant = "default",
  width,
  height,
  lines = 1
}) {
  const baseClasses = "animate-pulse rounded-md bg-muted motion-reduce:animate-none";
  const style = {
    width,
    height
  };
  if (variant === "circle") {
    return /* @__PURE__ */ jsx(
      "div",
      {
        className: cn(baseClasses, "rounded-full", className),
        style
      }
    );
  }
  if (variant === "text") {
    return /* @__PURE__ */ jsx("div", { className: "space-y-2 w-full", children: Array.from({ length: lines }).map((_, i) => /* @__PURE__ */ jsx(
      "div",
      {
        className: cn(
          baseClasses,
          "h-4",
          i === lines - 1 && lines > 1 && "w-3/4",
          className
        ),
        style
      },
      i
    )) });
  }
  if (variant === "card") {
    return /* @__PURE__ */ jsxs("div", { className: cn("rounded-xl border bg-card p-6 space-y-4", className), children: [
      /* @__PURE__ */ jsx("div", { className: cn(baseClasses, "h-6 w-1/3") }),
      /* @__PURE__ */ jsx("div", { className: cn(baseClasses, "h-4 w-full") }),
      /* @__PURE__ */ jsx("div", { className: cn(baseClasses, "h-4 w-2/3") })
    ] });
  }
  return /* @__PURE__ */ jsx(
    "div",
    {
      className: cn(baseClasses, className),
      style
    }
  );
}
function SkeletonStatCard() {
  return /* @__PURE__ */ jsxs("div", { className: "rounded-xl border bg-card p-6 space-y-3", children: [
    /* @__PURE__ */ jsxs("div", { className: "flex items-center gap-2", children: [
      /* @__PURE__ */ jsx(Skeleton, { variant: "circle", width: 40, height: 40 }),
      /* @__PURE__ */ jsx(Skeleton, { width: 80, height: 20 })
    ] }),
    /* @__PURE__ */ jsx(Skeleton, { width: 120, height: 32 }),
    /* @__PURE__ */ jsx(Skeleton, { width: 60, height: 16 })
  ] });
}
export {
  SkeletonStatCard as S,
  Skeleton as a
};
