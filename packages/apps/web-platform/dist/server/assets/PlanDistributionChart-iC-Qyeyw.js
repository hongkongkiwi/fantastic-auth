import { jsx, jsxs } from "react/jsx-runtime";
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from "recharts";
function PlanDistributionChart({ data }) {
  return /* @__PURE__ */ jsx(ResponsiveContainer, { width: "100%", height: "100%", children: /* @__PURE__ */ jsxs(PieChart, { children: [
    /* @__PURE__ */ jsx(
      Pie,
      {
        data,
        cx: "50%",
        cy: "50%",
        innerRadius: 60,
        outerRadius: 80,
        paddingAngle: 5,
        dataKey: "value",
        children: data.map((entry, index) => /* @__PURE__ */ jsx(Cell, { fill: entry.color }, `cell-${index}`))
      }
    ),
    /* @__PURE__ */ jsx(Tooltip, {})
  ] }) });
}
export {
  PlanDistributionChart as default
};
