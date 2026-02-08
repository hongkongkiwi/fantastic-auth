/**
 * Example: Basic middleware.ts configuration
 * 
 * This file should be placed at the root of your Next.js app (next to package.json)
 */

import { authMiddleware } from '@vault/nextjs/server';

// Simple configuration with public routes
export default authMiddleware({
  // These routes are accessible without authentication
  publicRoutes: [
    '/',
    '/sign-in',
    '/sign-up',
    '/forgot-password',
    '/reset-password',
    '/api/webhooks/(.*)',
  ],
  
  // Where to redirect when authentication is required
  signInUrl: '/sign-in',
  
  // Where to redirect after successful sign-in
  afterSignInUrl: '/dashboard',
  
  // Enable debug logging during development
  debug: process.env.NODE_ENV === 'development',
});

// Match all routes except static files
export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
