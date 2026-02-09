/**
 * Deep Linking Module
 * 
 * OAuth deep link handling for React Native.
 * 
 * @example
 * ```tsx
 * import { useOAuthDeepLink, OAuthHandler } from '@fantasticauth/react-native';
 * 
 * function OAuthScreen() {
 *   const { startOAuth, isOAuthInProgress } = useOAuthDeepLink({
 *     apiUrl: 'https://api.vault.dev',
 *     tenantId: 'my-tenant'
 *   });
 *   
 *   const handleGoogleSignIn = () => {
 *     const url = OAuthHandler.buildUrl(
 *       'https://api.vault.dev',
 *       'google',
 *       'myapp'
 *     );
 *     startOAuth(url);
 *   };
 *   
 *   return (
 *     <Button onPress={handleGoogleSignIn} disabled={isOAuthInProgress}>
 *       Sign in with Google
 *     </Button>
 *   );
 * }
 * ```
 */

export {
  // Core functions
  parseOAuthCallback,
  buildOAuthUrl,
  openOAuthInAppBrowser,
  closeInAppBrowser,
  addDeepLinkListener,
  removeDeepLinkListener,
  OAuthHandler,
} from './oauth-handler';

export {
  // React hook
  useOAuthDeepLink,
} from './oauth-handler';

export type {
  OAuthCallbackData,
  DeepLinkHandler,
  UseOAuthDeepLinkReturn,
} from '../types';
