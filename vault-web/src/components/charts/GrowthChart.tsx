import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

type GrowthDatum = {
  month: string
  tenants: number
  users: number
}

type GrowthChartProps = {
  data: GrowthDatum[]
}

export default function GrowthChart({ data }: GrowthChartProps) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data}>
        <defs>
          <linearGradient id="colorTenants" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="colorUsers" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
        <XAxis dataKey="month" stroke="#64748b" fontSize={12} />
        <YAxis stroke="#64748b" fontSize={12} />
        <Tooltip
          contentStyle={{
            backgroundColor: '#fff',
            border: '1px solid #e2e8f0',
            borderRadius: '8px',
            boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
          }}
        />
        <Area
          type="monotone"
          dataKey="tenants"
          stroke="#6366f1"
          strokeWidth={2}
          fillOpacity={1}
          fill="url(#colorTenants)"
          name="Tenants"
        />
        <Area
          type="monotone"
          dataKey="users"
          stroke="#10b981"
          strokeWidth={2}
          fillOpacity={1}
          fill="url(#colorUsers)"
          name="Users"
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}
