import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'
import { env } from '../env/server'
import { serverLogger } from '../lib/server-logger'

// Rate limiter instances
let loginRateLimiter: Ratelimit | null = null
let apiRateLimiter: Ratelimit | null = null
let sensitiveActionRateLimiter: Ratelimit | null = null

const getRedis = () => {
  const url = env.UPSTASH_REDIS_REST_URL
  const token = env.UPSTASH_REDIS_REST_TOKEN
  
  if (!url || !token) {
    serverLogger.warn('Upstash Redis not configured, rate limiting disabled')
    return null
  }
  
  return new Redis({ url, token })
}

// Login rate limiter: 5 attempts per 5 minutes per IP
export const getLoginRateLimiter = (): Ratelimit | null => {
  if (!loginRateLimiter) {
    const redis = getRedis()
    if (!redis) return null
    
    loginRateLimiter = new Ratelimit({
      redis,
      limiter: Ratelimit.slidingWindow(5, '5 m'),
      analytics: true,
      prefix: 'ratelimit:login',
    })
  }
  return loginRateLimiter
}

// API rate limiter: 100 requests per minute per IP
export const getApiRateLimiter = (): Ratelimit | null => {
  if (!apiRateLimiter) {
    const redis = getRedis()
    if (!redis) return null
    
    apiRateLimiter = new Ratelimit({
      redis,
      limiter: Ratelimit.slidingWindow(100, '1 m'),
      analytics: true,
      prefix: 'ratelimit:api',
    })
  }
  return apiRateLimiter
}

// Sensitive action rate limiter: 3 attempts per 10 minutes
export const getSensitiveActionRateLimiter = (): Ratelimit | null => {
  if (!sensitiveActionRateLimiter) {
    const redis = getRedis()
    if (!redis) return null
    
    sensitiveActionRateLimiter = new Ratelimit({
      redis,
      limiter: Ratelimit.slidingWindow(3, '10 m'),
      analytics: true,
      prefix: 'ratelimit:sensitive',
    })
  }
  return sensitiveActionRateLimiter
}

// Get client IP from request
export const getClientIP = (request: Request): string => {
  // Check for forwarded headers (when behind proxy)
  const forwarded = request.headers.get('x-forwarded-for')
  if (forwarded) {
    return forwarded.split(',')[0].trim()
  }
  
  const realIP = request.headers.get('x-real-ip')
  if (realIP) {
    return realIP
  }
  
  // Fallback to a default identifier
  return 'unknown'
}

// Check rate limit and return result
export const checkRateLimit = async (
  limiter: Ratelimit | null,
  identifier: string
): Promise<{ success: boolean; limit: number; remaining: number; reset: number }> => {
  if (!limiter) {
    // Rate limiting disabled
    return { success: true, limit: 0, remaining: 0, reset: 0 }
  }
  
  try {
    const result = await limiter.limit(identifier)
    return {
      success: result.success,
      limit: result.limit,
      remaining: result.remaining,
      reset: result.reset,
    }
  } catch (error) {
    serverLogger.error('Rate limit check failed:', error)
    // Fail open - allow request if rate limiter fails
    return { success: true, limit: 0, remaining: 0, reset: 0 }
  }
}
