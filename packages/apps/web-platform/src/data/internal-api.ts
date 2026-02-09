import { env } from '../env/client'

const DEFAULT_BASE_URL = 'http://localhost:3000/api/v1/internal'

export const getDefaultBaseUrl = () =>
  env.VITE_INTERNAL_API_BASE_URL ?? DEFAULT_BASE_URL
