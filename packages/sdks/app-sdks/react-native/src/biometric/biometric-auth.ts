/**
 * Biometric Authentication Module
 * 
 * Provides Face ID, Touch ID, and Fingerprint authentication for React Native.
 * Supports both Expo and bare React Native workflows.
 */

import { Platform } from 'react-native';
import { BiometricType, BiometricResult, UseBiometricAuthReturn } from '../types';

// ============================================================================
// Module Loading
// ============================================================================

let LocalAuthentication: any = null;
let ReactNativeBiometrics: any = null;

// Try to load Expo LocalAuthentication
try {
  LocalAuthentication = require('@expo/local-authentication');
} catch {
  // Expo LocalAuthentication not available
}

// Try to load react-native-biometrics
try {
  const rnBiometrics = require('react-native-biometrics');
  ReactNativeBiometrics = rnBiometrics.default || rnBiometrics;
} catch {
  // react-native-biometrics not available
}

// ============================================================================
// Biometric Type Detection
// ============================================================================

/**
 * Get the available biometric type on the device
 */
export async function getBiometricType(): Promise<BiometricType> {
  const isAvailable = await isBiometricAuthAvailable();
  
  if (!isAvailable) {
    return 'none';
  }

  // Try Expo LocalAuthentication first
  if (LocalAuthentication) {
    const enrolled = await LocalAuthentication.getEnrolledLevelAsync?.();
    const securityLevel = await LocalAuthentication.getEnrolledLevelAsync?.();
    
    // On iOS, we can determine the specific type
    if (Platform.OS === 'ios') {
      const types = await LocalAuthentication.supportedAuthenticationTypesAsync?.();
      if (types) {
        // FACIAL_RECOGNITION = 2, FINGERPRINT = 1, IRIS = 3
        if (types.includes(2)) return 'FaceID';
        if (types.includes(1)) return 'TouchID';
        if (types.includes(3)) return 'Iris';
      }
    }
    
    // On Android or if specific type not detected
    return 'Fingerprint';
  }

  // Try react-native-biometrics
  if (ReactNativeBiometrics) {
    try {
      const { available, biometryType } = await ReactNativeBiometrics.isSensorAvailable();
      if (available && biometryType) {
        // Map biometry type to our BiometricType
        switch (biometryType) {
          case 'FaceID':
            return 'FaceID';
          case 'TouchID':
            return 'TouchID';
          case 'Biometrics':
            return Platform.OS === 'ios' ? 'FaceID' : 'Fingerprint';
          default:
            return 'Fingerprint';
        }
      }
    } catch {
      // Fall through to none
    }
  }

  return 'none';
}

/**
 * Check if biometric authentication is available
 */
export async function isBiometricAuthAvailable(): Promise<boolean> {
  // Try Expo LocalAuthentication first
  if (LocalAuthentication) {
    try {
      const compatible = await LocalAuthentication.hasHardwareAsync();
      if (!compatible) return false;
      
      const enrolled = await LocalAuthentication.isEnrolledAsync();
      return enrolled;
    } catch {
      // Fall through to next option
    }
  }

  // Try react-native-biometrics
  if (ReactNativeBiometrics) {
    try {
      const { available } = await ReactNativeBiometrics.isSensorAvailable();
      return available;
    } catch {
      // Fall through to false
    }
  }

  return false;
}

/**
 * Check if biometrics is enrolled on the device
 */
export async function isBiometricEnrolled(): Promise<boolean> {
  // Try Expo LocalAuthentication
  if (LocalAuthentication) {
    try {
      return await LocalAuthentication.isEnrolledAsync();
    } catch {
      // Fall through
    }
  }

  // For react-native-biometrics, if sensor is available, it's enrolled
  if (ReactNativeBiometrics) {
    try {
      const { available } = await ReactNativeBiometrics.isSensorAvailable();
      return available;
    } catch {
      // Fall through to false
    }
  }

  return false;
}

// ============================================================================
// Authentication
// ============================================================================

/**
 * Authenticate using biometrics
 * @param promptMessage - Message to display in biometric prompt
 * @param fallbackLabel - Label for fallback button (iOS only)
 */
export async function authenticateWithBiometrics(
  promptMessage: string = 'Verify your identity',
  fallbackLabel: string = 'Use Password'
): Promise<BiometricResult> {
  // Try Expo LocalAuthentication first
  if (LocalAuthentication) {
    try {
      const compatible = await LocalAuthentication.hasHardwareAsync();
      if (!compatible) {
        return { success: false, error: 'Biometric hardware not available' };
      }

      const enrolled = await LocalAuthentication.isEnrolledAsync();
      if (!enrolled) {
        return { success: false, error: 'Biometric not enrolled' };
      }

      const result = await LocalAuthentication.authenticateAsync({
        promptMessage,
        fallbackLabel,
        disableDeviceFallback: false,
        cancelLabel: 'Cancel',
      });

      if (result.success) {
        return { success: true };
      } else {
        return { 
          success: false, 
          error: result.error || 'Authentication failed' 
        };
      }
    } catch (error: any) {
      return { success: false, error: error?.message || 'Authentication error' };
    }
  }

  // Try react-native-biometrics
  if (ReactNativeBiometrics) {
    try {
      const { available } = await ReactNativeBiometrics.isSensorAvailable();
      if (!available) {
        return { success: false, error: 'Biometric not available' };
      }

      const { success } = await ReactNativeBiometrics.simplePrompt({
        promptMessage,
      });

      return { success };
    } catch (error: any) {
      return { success: false, error: error?.message || 'Authentication error' };
    }
  }

  return { success: false, error: 'No biometric module available' };
}

/**
 * Create signature using biometric authentication
 * Useful for high-security operations
 */
export async function createBiometricSignature(
  payload: string,
  promptMessage: string = 'Confirm transaction'
): Promise<BiometricResult & { signature?: string }> {
  // Only react-native-biometrics supports signatures
  if (ReactNativeBiometrics) {
    try {
      const { available, biometryType } = await ReactNativeBiometrics.isSensorAvailable();
      if (!available) {
        return { success: false, error: 'Biometric not available' };
      }

      // Create keys if they don't exist
      const { keysExist } = await ReactNativeBiometrics.biometricKeysExist();
      if (!keysExist) {
        await ReactNativeBiometrics.createKeys();
      }

      const { success, signature } = await ReactNativeBiometrics.createSignature({
        promptMessage,
        payload,
      });

      return { success, signature };
    } catch (error: any) {
      return { success: false, error: error?.message || 'Signature creation failed' };
    }
  }

  return { success: false, error: 'Biometric signatures not supported' };
}

// ============================================================================
// React Hook
// ============================================================================

import { useState, useEffect, useCallback } from 'react';

/**
 * Hook for biometric authentication
 * 
 * @example
 * ```tsx
 * function App() {
 *   const { isAvailable, biometricType, authenticate } = useBiometricAuth();
 *   
 *   const handleUnlock = async () => {
 *     const result = await authenticate('Unlock the app');
 *     if (result.success) {
 *       // App unlocked
 *     }
 *   };
 *   
 *   return (
 *     <View>
 *       {isAvailable && (
 *         <Button onPress={handleUnlock}>
 *           Unlock with {biometricType}
 *         </Button>
 *       )}
 *     </View>
 *   );
 * }
 * ```
 */
export function useBiometricAuth(): UseBiometricAuthReturn {
  const [isAvailable, setIsAvailable] = useState(false);
  const [biometricType, setBiometricType] = useState<BiometricType>('none');
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    checkBiometricStatus();
  }, []);

  const checkBiometricStatus = async () => {
    const available = await isBiometricAuthAvailable();
    setIsAvailable(available);
    
    if (available) {
      const type = await getBiometricType();
      setBiometricType(type);
    }
  };

  const authenticate = useCallback(async (
    promptMessage?: string
  ): Promise<BiometricResult> => {
    setIsLoading(true);
    try {
      const result = await authenticateWithBiometrics(promptMessage);
      return result;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const checkEnrollment = useCallback(async (): Promise<boolean> => {
    return isBiometricEnrolled();
  }, []);

  return {
    isAvailable,
    biometricType,
    isLoading,
    authenticate,
    checkEnrollment,
  };
}

// ============================================================================
// Export Convenience Object
// ============================================================================

export const BiometricAuth = {
  getBiometricType,
  isAvailable: isBiometricAuthAvailable,
  isEnrolled: isBiometricEnrolled,
  authenticate: authenticateWithBiometrics,
  createSignature: createBiometricSignature,
};

export default BiometricAuth;
