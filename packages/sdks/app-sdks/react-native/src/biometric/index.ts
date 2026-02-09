/**
 * Biometric Authentication Module
 * 
 * Face ID, Touch ID, and Fingerprint authentication for React Native.
 * 
 * @example
 * ```tsx
 * import { useBiometricAuth, BiometricAuth } from '@fantasticauth/react-native';
 * 
 * function SecureScreen() {
 *   const { isAvailable, biometricType, authenticate } = useBiometricAuth();
 *   
 *   const handleSecureAction = async () => {
 *     const result = await authenticate('Confirm secure action');
 *     if (result.success) {
 *       // Proceed with secure action
 *     }
 *   };
 *   
 *   return (
 *     <View>
 *       <Text>Biometric Type: {biometricType}</Text>
 *       {isAvailable && (
 *         <Button onPress={handleSecureAction}>
 *           Authenticate with {biometricType}
 *         </Button>
 *       )}
 *     </View>
 *   );
 * }
 * ```
 */

export {
  // Core functions
  getBiometricType,
  isBiometricAuthAvailable,
  isBiometricEnrolled,
  authenticateWithBiometrics,
  createBiometricSignature,
  BiometricAuth,
} from './biometric-auth';

export {
  // React hook
  useBiometricAuth,
} from './biometric-auth';

export type {
  BiometricType,
  BiometricResult,
  UseBiometricAuthReturn,
} from '../types';
