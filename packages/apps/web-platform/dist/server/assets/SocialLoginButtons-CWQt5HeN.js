import { jsxs, jsx } from "react/jsx-runtime";
import { B as Button } from "./router-BqFKwE1w.js";
import { Chrome, Github, Apple, BadgeCheck, Slack, Gamepad2 } from "lucide-react";
function SocialLoginButtons({
  onGoogleClick,
  onGitHubClick,
  onMicrosoftClick,
  onAppleClick,
  onSlackClick,
  onDiscordClick,
  isLoading
}) {
  const hasProviders = Boolean(
    onGoogleClick || onGitHubClick || onMicrosoftClick || onAppleClick || onSlackClick || onDiscordClick
  );
  if (!hasProviders) {
    return null;
  }
  return /* @__PURE__ */ jsxs("div", { className: "space-y-3", children: [
    /* @__PURE__ */ jsxs("div", { className: "relative", children: [
      /* @__PURE__ */ jsx("div", { className: "absolute inset-0 flex items-center", children: /* @__PURE__ */ jsx("span", { className: "w-full border-t" }) }),
      /* @__PURE__ */ jsx("div", { className: "relative flex justify-center text-xs uppercase", children: /* @__PURE__ */ jsx("span", { className: "bg-background px-2 text-muted-foreground", children: "Or continue with" }) })
    ] }),
    /* @__PURE__ */ jsxs("div", { className: "grid grid-cols-2 gap-3", children: [
      onGoogleClick && /* @__PURE__ */ jsxs(
        Button,
        {
          variant: "outline",
          onClick: onGoogleClick,
          disabled: isLoading,
          className: "gap-2",
          children: [
            /* @__PURE__ */ jsx(Chrome, { className: "h-4 w-4 text-red-500" }),
            "Google"
          ]
        }
      ),
      onGitHubClick && /* @__PURE__ */ jsxs(
        Button,
        {
          variant: "outline",
          onClick: onGitHubClick,
          disabled: isLoading,
          className: "gap-2",
          children: [
            /* @__PURE__ */ jsx(Github, { className: "h-4 w-4" }),
            "GitHub"
          ]
        }
      ),
      onAppleClick && /* @__PURE__ */ jsxs(
        Button,
        {
          variant: "outline",
          onClick: onAppleClick,
          disabled: isLoading,
          className: "gap-2",
          children: [
            /* @__PURE__ */ jsx(Apple, { className: "h-4 w-4" }),
            "Apple"
          ]
        }
      ),
      onMicrosoftClick && /* @__PURE__ */ jsxs(
        Button,
        {
          variant: "outline",
          onClick: onMicrosoftClick,
          disabled: isLoading,
          className: "gap-2",
          children: [
            /* @__PURE__ */ jsx(BadgeCheck, { className: "h-4 w-4 text-blue-600" }),
            "Microsoft"
          ]
        }
      ),
      onSlackClick && /* @__PURE__ */ jsxs(
        Button,
        {
          variant: "outline",
          onClick: onSlackClick,
          disabled: isLoading,
          className: "gap-2",
          children: [
            /* @__PURE__ */ jsx(Slack, { className: "h-4 w-4 text-purple-500" }),
            "Slack"
          ]
        }
      ),
      onDiscordClick && /* @__PURE__ */ jsxs(
        Button,
        {
          variant: "outline",
          onClick: onDiscordClick,
          disabled: isLoading,
          className: "gap-2",
          children: [
            /* @__PURE__ */ jsx(Gamepad2, { className: "h-4 w-4 text-indigo-500" }),
            "Discord"
          ]
        }
      )
    ] })
  ] });
}
export {
  SocialLoginButtons as S
};
