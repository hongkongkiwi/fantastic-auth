/**
 * Example: Using protectedRoutes instead of publicRoutes
 * 
 * Use this approach when you have more protected routes than public routes
 */

import { authMiddleware } from '@vault/nextjs/server';

// Only these routes require authentication
// All other routes are public by default
export default authMiddleware({
  protectedRoutes: [
    '/dashboard',
    '/dashboard/(.*)',
    '/settings',
    '/settings/(.*)',
    '/admin',
    '/admin/(.*)',
    '/api/private/(.*)',
  ],
  
  signInUrl: '/sign-in',
  afterSignInUrl: '/dashboard',
});

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
