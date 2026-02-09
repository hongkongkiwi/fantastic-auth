import { env } from '@/env/client'

const readFlag = (name: string, defaultValue = false): boolean => {
  const raw = env[name as keyof typeof env]
  if (raw === 'true') return true
  if (raw === 'false') return false
  return defaultValue
}

export const features = {
  security: readFlag('VITE_FEATURE_USER_SECURITY', false),
  devices: readFlag('VITE_FEATURE_USER_DEVICES', false),
  sessions: readFlag('VITE_FEATURE_USER_SESSIONS', false),
  privacy: readFlag('VITE_FEATURE_USER_PRIVACY', false),
  activity: readFlag('VITE_FEATURE_USER_ACTIVITY', false),
}
