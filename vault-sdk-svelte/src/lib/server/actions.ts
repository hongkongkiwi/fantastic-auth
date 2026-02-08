/**
 * Server Actions
 * 
 * Form actions for SvelteKit form handling.
 */

import { fail, redirect } from '@sveltejs/kit';
import type { RequestEvent } from '@sveltejs/kit';

interface VaultActionsConfig {
  apiUrl: string;
  tenantId: string;
  signInRedirect?: string;
  signOutRedirect?: string;
}

/**
 * Create Vault form actions
 * 
 * @example
 * ```typescript
 * // +page.server.ts
 * import { vaultActions } from '@vault/svelte/server';
 * 
 * const config = {
 *   apiUrl: 'https://api.vault.dev',
 *   tenantId: 'my-tenant'
 * };
 * 
 * export const actions = vaultActions(config);
 * ```
 * 
 * Then in your form:
 * ```svelte
 * <form method="POST" action="?/signIn">
 *   <input name="email" type="email" required />
 *   <input name="password" type="password" required />
 *   <button type="submit">Sign In</button>
 * </form>
 * ```
 */
export function vaultActions(config: VaultActionsConfig) {
  return {
    /**
     * Sign in action
     */
    signIn: async ({ request, cookies }: RequestEvent) => {
      const formData = await request.formData();
      const email = formData.get('email') as string;
      const password = formData.get('password') as string;
      
      if (!email || !password) {
        return fail(400, { 
          success: false, 
          error: 'Email and password are required' 
        });
      }
      
      try {
        const response = await fetch(`${config.apiUrl}/api/v1/auth/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Tenant-ID': config.tenantId,
          },
          body: JSON.stringify({ email, password }),
        });
        
        if (!response.ok) {
          const error = await response.json().catch(() => ({ message: 'Invalid credentials' }));
          return fail(401, { 
            success: false, 
            error: error.message 
          });
        }
        
        const data = await response.json();
        
        // Set session cookie
        cookies.set('vault_session_token', data.session.accessToken, {
          path: '/',
          httpOnly: true,
          sameSite: 'lax',
          secure: process.env.NODE_ENV === 'production',
          maxAge: 60 * 60 * 24 * 7, // 7 days
        });
        
        if (data.session.refreshToken) {
          cookies.set('vault_refresh_token', data.session.refreshToken, {
            path: '/',
            httpOnly: true,
            sameSite: 'lax',
            secure: process.env.NODE_ENV === 'production',
            maxAge: 60 * 60 * 24 * 30, // 30 days
          });
        }
        
        // Redirect after successful sign in
        const redirectUrl = formData.get('redirect') as string || config.signInRedirect || '/';
        throw redirect(302, redirectUrl);
        
      } catch (error) {
        if (error instanceof Response) throw error;
        
        return fail(500, { 
          success: false, 
          error: 'An error occurred during sign in' 
        });
      }
    },
    
    /**
     * Sign up action
     */
    signUp: async ({ request, cookies }: RequestEvent) => {
      const formData = await request.formData();
      const email = formData.get('email') as string;
      const password = formData.get('password') as string;
      const name = formData.get('name') as string | undefined;
      
      if (!email || !password) {
        return fail(400, { 
          success: false, 
          error: 'Email and password are required' 
        });
      }
      
      try {
        const response = await fetch(`${config.apiUrl}/api/v1/auth/register`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Tenant-ID': config.tenantId,
          },
          body: JSON.stringify({ 
            email, 
            password,
            ...(name && { name })
          }),
        });
        
        if (!response.ok) {
          const error = await response.json().catch(() => ({ message: 'Registration failed' }));
          return fail(400, { 
            success: false, 
            error: error.message 
          });
        }
        
        const data = await response.json();
        
        // Set session cookie
        cookies.set('vault_session_token', data.session.accessToken, {
          path: '/',
          httpOnly: true,
          sameSite: 'lax',
          secure: process.env.NODE_ENV === 'production',
          maxAge: 60 * 60 * 24 * 7,
        });
        
        if (data.session.refreshToken) {
          cookies.set('vault_refresh_token', data.session.refreshToken, {
            path: '/',
            httpOnly: true,
            sameSite: 'lax',
            secure: process.env.NODE_ENV === 'production',
            maxAge: 60 * 60 * 24 * 30,
          });
        }
        
        const redirectUrl = formData.get('redirect') as string || '/';
        throw redirect(302, redirectUrl);
        
      } catch (error) {
        if (error instanceof Response) throw error;
        
        return fail(500, { 
          success: false, 
          error: 'An error occurred during sign up' 
        });
      }
    },
    
    /**
     * Sign out action
     */
    signOut: async ({ cookies, locals }: RequestEvent) => {
      try {
        // Call logout endpoint if we have a token
        if (locals.token) {
          await fetch(`${config.apiUrl}/api/v1/auth/logout`, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${locals.token}`,
              'X-Tenant-ID': config.tenantId,
            },
          });
        }
      } catch {
        // Ignore errors during logout
      }
      
      // Clear cookies
      cookies.delete('vault_session_token', { path: '/' });
      cookies.delete('vault_refresh_token', { path: '/' });
      
      throw redirect(302, config.signOutRedirect || '/sign-in');
    },
    
    /**
     * Forgot password action
     */
    forgotPassword: async ({ request }: RequestEvent) => {
      const formData = await request.formData();
      const email = formData.get('email') as string;
      
      if (!email) {
        return fail(400, { 
          success: false, 
          error: 'Email is required' 
        });
      }
      
      try {
        const response = await fetch(`${config.apiUrl}/api/v1/auth/forgot-password`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Tenant-ID': config.tenantId,
          },
          body: JSON.stringify({ 
            email,
            redirectUrl: formData.get('redirectUrl') as string || undefined
          }),
        });
        
        if (!response.ok) {
          // Don't reveal if email exists
          // Return success regardless
        }
        
        return { 
          success: true, 
          message: 'If an account exists, a password reset email has been sent' 
        };
        
      } catch {
        return { 
          success: true, 
          message: 'If an account exists, a password reset email has been sent' 
        };
      }
    },
    
    /**
     * Reset password action
     */
    resetPassword: async ({ request, cookies }: RequestEvent) => {
      const formData = await request.formData();
      const token = formData.get('token') as string;
      const password = formData.get('password') as string;
      
      if (!token || !password) {
        return fail(400, { 
          success: false, 
          error: 'Token and password are required' 
        });
      }
      
      try {
        const response = await fetch(`${config.apiUrl}/api/v1/auth/reset-password`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Tenant-ID': config.tenantId,
          },
          body: JSON.stringify({ token, password }),
        });
        
        if (!response.ok) {
          const error = await response.json().catch(() => ({ message: 'Password reset failed' }));
          return fail(400, { 
            success: false, 
            error: error.message 
          });
        }
        
        const data = await response.json();
        
        // Set session cookie
        cookies.set('vault_session_token', data.session.accessToken, {
          path: '/',
          httpOnly: true,
          sameSite: 'lax',
          secure: process.env.NODE_ENV === 'production',
          maxAge: 60 * 60 * 24 * 7,
        });
        
        return { success: true };
        
      } catch (error) {
        return fail(500, { 
          success: false, 
          error: 'An error occurred' 
        });
      }
    },
  };
}

/**
 * Individual action exports for selective imports
 */
export const vaultActionSignIn = vaultActions({ apiUrl: '', tenantId: '' }).signIn;
export const vaultActionSignUp = vaultActions({ apiUrl: '', tenantId: '' }).signUp;
export const vaultActionSignOut = vaultActions({ apiUrl: '', tenantId: '' }).signOut;
