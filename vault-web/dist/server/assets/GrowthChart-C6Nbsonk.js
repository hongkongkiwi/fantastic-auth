import { jsx, jsxs } from "react/jsx-runtime";
import { ResponsiveContainer, AreaChart, CartesianGrid, XAxis, YAxis, Tooltip, Area } from "recharts";
function GrowthChart({ data }) {
  return /* @__PURE__ */ jsx(ResponsiveContainer, { width: "100%", height: "100%", children: /* @__PURE__ */ jsxs(AreaChart, { data, children: [
    /* @__PURE__ */ jsxs("defs", { children: [
      /* @__PURE__ */ jsxs("linearGradient", { id: "colorTenants", x1: "0", y1: "0", x2: "0", y2: "1", children: [
        /* @__PURE__ */ jsx("stop", { offset: "5%", stopColor: "#6366f1", stopOpacity: 0.3 }),
        /* @__PURE__ */ jsx("stop", { offset: "95%", stopColor: "#6366f1", stopOpacity: 0 })
      ] }),
      /* @__PURE__ */ jsxs("linearGradient", { id: "colorUsers", x1: "0", y1: "0", x2: "0", y2: "1", children: [
        /* @__PURE__ */ jsx("stop", { offset: "5%", stopColor: "#10b981", stopOpacity: 0.3 }),
        /* @__PURE__ */ jsx("stop", { offset: "95%", stopColor: "#10b981", stopOpacity: 0 })
      ] })
    ] }),
    /* @__PURE__ */ jsx(CartesianGrid, { strokeDasharray: "3 3", stroke: "#e2e8f0" }),
    /* @__PURE__ */ jsx(XAxis, { dataKey: "month", stroke: "#64748b", fontSize: 12 }),
    /* @__PURE__ */ jsx(YAxis, { stroke: "#64748b", fontSize: 12 }),
    /* @__PURE__ */ jsx(
      Tooltip,
      {
        contentStyle: {
          backgroundColor: "#fff",
          border: "1px solid #e2e8f0",
          borderRadius: "8px",
          boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)"
        }
      }
    ),
    /* @__PURE__ */ jsx(
      Area,
      {
        type: "monotone",
        dataKey: "tenants",
        stroke: "#6366f1",
        strokeWidth: 2,
        fillOpacity: 1,
        fill: "url(#colorTenants)",
        name: "Tenants"
      }
    ),
    /* @__PURE__ */ jsx(
      Area,
      {
        type: "monotone",
        dataKey: "users",
        stroke: "#10b981",
        strokeWidth: 2,
        fillOpacity: 1,
        fill: "url(#colorUsers)",
        name: "Users"
      }
    )
  ] }) });
}
export {
  GrowthChart as default
};
