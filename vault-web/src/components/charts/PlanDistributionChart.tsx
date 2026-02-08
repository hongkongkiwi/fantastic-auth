import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'

type PlanSlice = {
  name: string
  value: number
  color: string
}

type PlanDistributionChartProps = {
  data: PlanSlice[]
}

export default function PlanDistributionChart({ data }: PlanDistributionChartProps) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={60}
          outerRadius={80}
          paddingAngle={5}
          dataKey="value"
        >
          {data.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={entry.color} />
          ))}
        </Pie>
        <Tooltip />
      </PieChart>
    </ResponsiveContainer>
  )
}
