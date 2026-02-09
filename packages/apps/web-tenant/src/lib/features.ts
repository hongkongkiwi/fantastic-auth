import { env } from '@/env/client'

const readFlag = (name: string, defaultValue = false): boolean => {
  const raw = env[name as keyof typeof env]
  if (raw === 'true') return true
  if (raw === 'false') return false
  return defaultValue
}

export const features = {
  securityDashboard: readFlag('VITE_FEATURE_SECURITY_DASHBOARD', false),
  selfServiceDevices: readFlag('VITE_FEATURE_SELF_SERVICE_DEVICES', false),
  selfServiceSessions: readFlag('VITE_FEATURE_SELF_SERVICE_SESSIONS', false),
  selfServicePrivacy: readFlag('VITE_FEATURE_SELF_SERVICE_PRIVACY', false),
}
