/**
 * Components Module
 * 
 * Pre-built React Native components for Vault authentication.
 * 
 * @example
 * ```tsx
 * import { SignIn, UserButton, OrganizationSwitcher } from '@fantasticauth/react-native';
 * 
 * function App() {
 *   return (
 *     <View>
 *       <OrganizationSwitcher />
 *       <UserButton onSignOut={() => {}} />
 *       <SignIn oauthProviders={['google', 'apple']} />
 *     </View>
 *   );
 * }
 * ```
 */

// Auth Components
export { SignIn } from './SignIn';
export { SignUp } from './SignUp';
export { UserButton } from './UserButton';
export { UserProfile } from './UserProfile';

// Organization Components
export { OrganizationSwitcher } from './OrganizationSwitcher';

// OAuth
export { OAuthButton } from './OAuthButton';

// Types
export type {
  SignInProps,
  SignUpProps,
  UserButtonProps,
  UserProfileProps,
  OrganizationSwitcherProps,
  OAuthButtonProps,
} from '../types';
