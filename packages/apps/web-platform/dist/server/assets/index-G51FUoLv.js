import { jsx, jsxs } from "react/jsx-runtime";
import { useNavigate } from "@tanstack/react-router";
import { useEffect } from "react";
import { Loader2 } from "lucide-react";
function HostedIndexPage() {
  const navigate = useNavigate();
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const tenantId = params.get("tenant_id");
    const redirectUrl = params.get("redirect_url");
    const organizationId = params.get("organization_id");
    navigate({
      to: "/hosted/sign-in",
      search: {
        tenant_id: tenantId || "",
        redirect_url: redirectUrl || void 0,
        organization_id: organizationId || void 0
      }
    });
  }, [navigate]);
  return /* @__PURE__ */ jsx("div", { className: "min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted p-4", children: /* @__PURE__ */ jsxs("div", { className: "flex flex-col items-center gap-4", children: [
    /* @__PURE__ */ jsx(Loader2, { className: "h-8 w-8 animate-spin text-primary" }),
    /* @__PURE__ */ jsx("p", { className: "text-muted-foreground text-sm", children: "Redirecting..." })
  ] }) });
}
export {
  HostedIndexPage as component
};
