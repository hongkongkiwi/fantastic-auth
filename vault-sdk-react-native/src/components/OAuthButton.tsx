/**
 * OAuthButton Component
 * 
 * Button for OAuth provider authentication.
 * Opens in-app browser for OAuth flow.
 * 
 * @example
 * ```tsx
 * <OAuthButton 
 *   provider="google"
 *   onSuccess={() => navigation.navigate('Home')}
 *   onError={(error) => console.error(error)}
 * />
 * ```
 */

import React from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
} from 'react-native';
import { OAuthButtonProps } from '../types';
import { useSignIn } from '../hooks/useSignIn';

const providerConfig: Record<string, { name: string; color: string; textColor: string }> = {
  google: {
    name: 'Google',
    color: '#fff',
    textColor: '#333',
  },
  apple: {
    name: 'Apple',
    color: '#000',
    textColor: '#fff',
  },
  microsoft: {
    name: 'Microsoft',
    color: '#2f2f2f',
    textColor: '#fff',
  },
  github: {
    name: 'GitHub',
    color: '#24292e',
    textColor: '#fff',
  },
};

export function OAuthButton({
  provider,
  variant = 'default',
  text,
  onSuccess,
  onError,
  style,
  testID,
}: OAuthButtonProps) {
  const { signInWithOAuth, isLoading, error } = useSignIn();
  
  const config = providerConfig[provider] || {
    name: provider.charAt(0).toUpperCase() + provider.slice(1),
    color: '#fff',
    textColor: '#333',
  };
  
  const buttonText = text || `Continue with ${config.name}`;
  
  React.useEffect(() => {
    if (error && onError) {
      onError(error);
    }
  }, [error, onError]);
  
  const handlePress = async () => {
    try {
      await signInWithOAuth({ provider });
      // Note: onSuccess will be called after OAuth callback is handled
      // This happens in the VaultProvider via deep link listener
      if (onSuccess) {
        onSuccess();
      }
    } catch {
      // Error is handled by the hook
    }
  };
  
  if (variant === 'icon-only') {
    return (
      <TouchableOpacity
        style={[
          styles.iconButton,
          { backgroundColor: config.color },
          style,
        ]}
        onPress={handlePress}
        disabled={isLoading}
        testID={testID}
      >
        {isLoading ? (
          <ActivityIndicator color={config.textColor} />
        ) : (
          <Text style={[styles.iconButtonText, { color: config.textColor }]}>
            {config.name[0]}
          </Text>
        )}
      </TouchableOpacity>
    );
  }
  
  return (
    <TouchableOpacity
      style={[
        styles.button,
        { backgroundColor: config.color, borderColor: config.color },
        style,
      ]}
      onPress={handlePress}
      disabled={isLoading}
      testID={testID}
    >
      {isLoading ? (
        <ActivityIndicator color={config.textColor} />
      ) : (
        <Text style={[styles.buttonText, { color: config.textColor }]}>
          {buttonText}
        </Text>
      )}
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  button: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 14,
    borderRadius: 8,
    borderWidth: 1,
    marginBottom: 12,
  },
  buttonText: {
    fontSize: 16,
    fontWeight: '600',
  },
  iconButton: {
    width: 50,
    height: 50,
    borderRadius: 25,
    alignItems: 'center',
    justifyContent: 'center',
    marginHorizontal: 8,
    borderWidth: 1,
  },
  iconButtonText: {
    fontSize: 20,
    fontWeight: 'bold',
  },
});
