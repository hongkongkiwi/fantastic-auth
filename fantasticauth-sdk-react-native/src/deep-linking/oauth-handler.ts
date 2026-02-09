/**
 * OAuth Deep Linking Handler
 * 
 * Handles OAuth callbacks via deep linking for React Native.
 * Supports both Expo and bare React Native workflows.
 */

import { Linking, Platform } from 'react-native';
import { 
  OAuthCallbackData, 
  DeepLinkHandler, 
  UseOAuthDeepLinkReturn,
  VaultConfig 
} from '../types';

// ============================================================================
// Module Loading
// ============================================================================

let InAppBrowser: any = null;
let WebBrowser: any = null;

// Try to load react-native-inappbrowser-reborn
try {
  InAppBrowser = require('react-native-inappbrowser-reborn').default;
} catch {
  // InAppBrowser not available
}

// Try to load Expo WebBrowser
try {
  WebBrowser = require('expo-web-browser');
} catch {
  // Expo WebBrowser not available
}

// ============================================================================
// URL Parsing
// ============================================================================

/**
 * Parse OAuth callback URL
 */
export function parseOAuthCallback(url: string): OAuthCallbackData | null {
  try {
    const urlObj = new URL(url);
    const params = new URLSearchParams(urlObj.search);
    
    const code = params.get('code');
    const state = params.get('state') || undefined;
    const error = params.get('error') || undefined;
    const errorDescription = params.get('error_description') || undefined;
    
    // Extract provider from path if available
    const pathParts = urlObj.pathname.split('/');
    const provider = pathParts[pathParts.length - 1] || params.get('provider') || 'unknown';
    
    if (error) {
      return {
        provider,
        code: '',
        state,
        error,
        errorDescription,
      };
    }
    
    if (code) {
      return {
        provider,
        code,
        state,
      };
    }
    
    return null;
  } catch {
    return null;
  }
}

/**
 * Build OAuth URL with redirect
 */
export function buildOAuthUrl(
  baseUrl: string, 
  provider: string, 
  redirectScheme: string = 'vault',
  state?: string
): string {
  const redirectUri = `${redirectScheme}://oauth/${provider}`;
  const params = new URLSearchParams({
    provider,
    redirect_uri: redirectUri,
    ...(state && { state }),
  });
  
  return `${baseUrl}/api/v1/auth/oauth/${provider}?${params.toString()}`;
}

// ============================================================================
// In-App Browser
// ============================================================================

/**
 * Open OAuth URL in in-app browser
 */
export async function openOAuthInAppBrowser(
  url: string,
  redirectScheme: string = 'vault'
): Promise<void> {
  // Try react-native-inappbrowser-reborn first
  if (InAppBrowser) {
    try {
      const result = await InAppBrowser.isAvailable();
      if (result) {
        await InAppBrowser.openAuth(url, `${redirectScheme}://`, {
          // iOS options
          dismissButtonStyle: 'cancel',
          preferredBarTintColor: '#000000',
          preferredControlTintColor: '#FFFFFF',
          // Android options
          showTitle: true,
          toolbarColor: '#000000',
          secondaryToolbarColor: '#FFFFFF',
          enableUrlBarHiding: true,
          enableDefaultShare: false,
          ephemeralWebSession: false,
        });
        return;
      }
    } catch {
      // Fall through to next option
    }
  }

  // Try Expo WebBrowser
  if (WebBrowser) {
    try {
      const result = await WebBrowser.openAuthSessionAsync(
        url,
        `${redirectScheme}://`
      );
      
      if (result.type === 'success' && result.url) {
        // Handle success
        return;
      }
    } catch {
      // Fall through to Linking
    }
  }

  // Fallback to system browser
  const supported = await Linking.canOpenURL(url);
  if (supported) {
    await Linking.openURL(url);
  } else {
    throw new Error(`Cannot open URL: ${url}`);
  }
}

/**
 * Close in-app browser
 */
export async function closeInAppBrowser(): Promise<void> {
  if (InAppBrowser) {
    try {
      await InAppBrowser.closeAuth();
    } catch {
      // Ignore errors
    }
  }
  
  if (WebBrowser) {
    try {
      await WebBrowser.dismissAuthSession();
    } catch {
      // Ignore errors
    }
  }
}

// ============================================================================
// Deep Link Listener
// ============================================================================

let currentHandler: DeepLinkHandler | null = null;
let linkSubscription: any = null;

/**
 * Add deep link listener for OAuth callbacks
 */
export function addDeepLinkListener(handler: DeepLinkHandler): () => void {
  currentHandler = handler;
  
  // Subscribe to URL events
  linkSubscription = Linking.addEventListener('url', (event: { url: string }) => {
    if (currentHandler) {
      const data = parseOAuthCallback(event.url);
      currentHandler(event.url, data);
    }
  });
  
  // Check for initial URL (app opened via deep link)
  Linking.getInitialURL().then((url) => {
    if (url && currentHandler) {
      const data = parseOAuthCallback(url);
      currentHandler(url, data);
    }
  });
  
  // Return unsubscribe function
  return () => {
    if (linkSubscription) {
      linkSubscription.remove();
      linkSubscription = null;
    }
    currentHandler = null;
  };
}

/**
 * Remove deep link listener
 */
export function removeDeepLinkListener(): void {
  if (linkSubscription) {
    linkSubscription.remove();
    linkSubscription = null;
  }
  currentHandler = null;
}

// ============================================================================
// React Hook
// ============================================================================

import { useState, useEffect, useCallback, useRef } from 'react';

/**
 * Hook for handling OAuth deep linking
 * 
 * @example
 * ```tsx
 * function App() {
 *   const { lastCallback, isOAuthInProgress, startOAuth, completeOAuth } = useOAuthDeepLink({
 *     apiUrl: 'https://api.vault.dev',
 *     tenantId: 'my-tenant',
 *     oauthRedirectScheme: 'myapp'
 *   });
 *   
 *   useEffect(() => {
 *     if (lastCallback?.code) {
 *       // Exchange code for session
 *       completeOAuth(lastCallback).then(() => {
 *         // Navigate to home
 *       });
 *     }
 *   }, [lastCallback]);
 *   
 *   const handleSignInWithGoogle = () => {
 *     startOAuth('https://api.vault.dev/oauth/google');
 *   };
 *   
 *   return (
 *     <View>
 *       <Button onPress={handleSignInWithGoogle}>
 *         Sign in with Google
 *       </Button>
 *     </View>
 *   );
 * }
 * ```
 */
export function useOAuthDeepLink(
  config: Pick<VaultConfig, 'apiUrl' | 'tenantId' | 'oauthRedirectScheme'>
): UseOAuthDeepLinkReturn {
  const [lastCallback, setLastCallback] = useState<OAuthCallbackData | null>(null);
  const [isOAuthInProgress, setIsOAuthInProgress] = useState(false);
  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const unsubscribe = addDeepLinkListener((url, data) => {
      if (data) {
        setLastCallback(data);
        setIsOAuthInProgress(false);
      }
    });

    return () => {
      unsubscribe();
    };
  }, []);

  const startOAuth = useCallback(async (url: string): Promise<void> => {
    setIsOAuthInProgress(true);
    setLastCallback(null);
    
    // Create abort controller for cancellation
    abortControllerRef.current = new AbortController();
    
    try {
      await openOAuthInAppBrowser(url, config.oauthRedirectScheme);
    } catch (error) {
      setIsOAuthInProgress(false);
      throw error;
    }
  }, [config.oauthRedirectScheme]);

  const completeOAuth = useCallback(async (data: OAuthCallbackData): Promise<void> => {
    if (data.error) {
      throw new Error(data.errorDescription || data.error);
    }

    // Exchange code for session via API
    const baseUrl = config.apiUrl.replace(/\/$/, '');
    const response = await fetch(
      `${baseUrl}/api/v1/auth/oauth/${data.provider}/callback`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Tenant-ID': config.tenantId,
        },
        body: JSON.stringify({ 
          code: data.code,
          state: data.state,
        }),
      }
    );

    if (!response.ok) {
      const error = await response.json().catch(() => ({
        message: 'OAuth callback failed',
        code: 'oauth_error',
      }));
      throw new Error(error.message || 'OAuth callback failed');
    }

    return response.json();
  }, [config.apiUrl, config.tenantId]);

  const cancelOAuth = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    closeInAppBrowser();
    setIsOAuthInProgress(false);
    setLastCallback(null);
  }, []);

  return {
    lastCallback,
    isOAuthInProgress,
    startOAuth,
    completeOAuth,
    cancelOAuth,
  };
}

// ============================================================================
// Export Convenience Object
// ============================================================================

export const OAuthHandler = {
  parseCallback: parseOAuthCallback,
  buildUrl: buildOAuthUrl,
  openInAppBrowser: openOAuthInAppBrowser,
  closeInAppBrowser,
  addDeepLinkListener,
  removeDeepLinkListener,
};

export default OAuthHandler;
