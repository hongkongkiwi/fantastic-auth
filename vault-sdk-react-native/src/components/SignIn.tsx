/**
 * SignIn Component
 * 
 * Pre-built sign-in screen for React Native.
 * 
 * @example
 * ```tsx
 * function SignInScreen() {
 *   return (
 *     <SignIn
 *       oauthProviders={['google', 'apple']}
 *       showBiometricOption={true}
 *       showMagicLink={true}
 *       onSignIn={() => navigation.navigate('Home')}
 *       onError={(error) => console.error(error)}
 *     />
 *   );
 * }
 * ```
 */

import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  ScrollView,
} from 'react-native';
import { SignInProps } from '../types';
import { useSignIn } from '../hooks/useSignIn';
import { useAuth } from '../hooks/useAuth';
import { OAuthButton } from './OAuthButton';

export function SignIn({
  oauthProviders = [],
  showMagicLink = false,
  showBiometricOption = false,
  showForgotPassword = true,
  onSignIn,
  onError,
  style,
  testID,
}: SignInProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [magicLinkSent, setMagicLinkSent] = useState(false);
  
  const { signIn, signInWithMagicLink, signInWithBiometrics, isLoading, error } = useSignIn();
  const { isSignedIn } = useAuth();
  
  // Call onSignIn when authentication is successful
  React.useEffect(() => {
    if (isSignedIn && onSignIn) {
      onSignIn();
    }
  }, [isSignedIn, onSignIn]);
  
  // Call onError when there's an error
  React.useEffect(() => {
    if (error && onError) {
      onError(error);
    }
  }, [error, onError]);
  
  const handleSignIn = async () => {
    if (!email || !password) {
      return;
    }
    
    try {
      await signIn({ email, password });
    } catch {
      // Error is handled by the hook
    }
  };
  
  const handleMagicLink = async () => {
    if (!email) {
      return;
    }
    
    try {
      await signInWithMagicLink({ email });
      setMagicLinkSent(true);
    } catch {
      // Error is handled by the hook
    }
  };
  
  const handleBiometricSignIn = async () => {
    try {
      await signInWithBiometrics();
    } catch {
      // Error is handled by the hook
    }
  };
  
  return (
    <ScrollView style={[styles.container, style]} testID={testID}>
      <Text style={styles.title}>Sign In</Text>
      
      {error && (
        <View style={styles.errorContainer}>
          <Text style={styles.errorText}>{error.message}</Text>
        </View>
      )}
      
      {magicLinkSent ? (
        <View style={styles.successContainer}>
          <Text style={styles.successText}>
            Magic link sent! Check your email to sign in.
          </Text>
          <TouchableOpacity onPress={() => setMagicLinkSent(false)}>
            <Text style={styles.linkText}>Back to sign in</Text>
          </TouchableOpacity>
        </View>
      ) : (
        <>
          <View style={styles.inputContainer}>
            <Text style={styles.label}>Email</Text>
            <TextInput
              style={styles.input}
              value={email}
              onChangeText={setEmail}
              placeholder="your@email.com"
              keyboardType="email-address"
              autoCapitalize="none"
              autoCorrect={false}
              editable={!isLoading}
            />
          </View>
          
          <View style={styles.inputContainer}>
            <Text style={styles.label}>Password</Text>
            <TextInput
              style={styles.input}
              value={password}
              onChangeText={setPassword}
              placeholder="Your password"
              secureTextEntry={!showPassword}
              autoCapitalize="none"
              editable={!isLoading}
            />
          </View>
          
          <TouchableOpacity
            style={[styles.button, styles.primaryButton, isLoading && styles.disabledButton]}
            onPress={handleSignIn}
            disabled={isLoading}
          >
            {isLoading ? (
              <ActivityIndicator color="#fff" />
            ) : (
              <Text style={styles.buttonText}>Sign In</Text>
            )}
          </TouchableOpacity>
          
          {showForgotPassword && (
            <TouchableOpacity style={styles.linkButton}>
              <Text style={styles.linkText}>Forgot password?</Text>
            </TouchableOpacity>
          )}
          
          {showMagicLink && (
            <TouchableOpacity
              style={[styles.button, styles.secondaryButton, isLoading && styles.disabledButton]}
              onPress={handleMagicLink}
              disabled={isLoading}
            >
              <Text style={styles.secondaryButtonText}>Send Magic Link</Text>
            </TouchableOpacity>
          )}
          
          {showBiometricOption && (
            <TouchableOpacity
              style={[styles.button, styles.secondaryButton]}
              onPress={handleBiometricSignIn}
            >
              <Text style={styles.secondaryButtonText}>
                Sign in with Biometrics
              </Text>
            </TouchableOpacity>
          )}
          
          {oauthProviders.length > 0 && (
            <View style={styles.dividerContainer}>
              <View style={styles.divider} />
              <Text style={styles.dividerText}>or continue with</Text>
              <View style={styles.divider} />
            </View>
          )}
          
          {oauthProviders.map((provider) => (
            <OAuthButton
              key={provider}
              provider={provider}
              onSuccess={onSignIn}
              onError={onError}
            />
          ))}
        </>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    backgroundColor: '#fff',
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    marginBottom: 24,
    textAlign: 'center',
  },
  inputContainer: {
    marginBottom: 16,
  },
  label: {
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 8,
    color: '#333',
  },
  input: {
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    padding: 12,
    fontSize: 16,
    backgroundColor: '#fafafa',
  },
  button: {
    padding: 16,
    borderRadius: 8,
    alignItems: 'center',
    marginTop: 8,
  },
  primaryButton: {
    backgroundColor: '#000',
  },
  secondaryButton: {
    backgroundColor: '#f5f5f5',
    borderWidth: 1,
    borderColor: '#ddd',
  },
  disabledButton: {
    opacity: 0.6,
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  secondaryButtonText: {
    color: '#333',
    fontSize: 16,
    fontWeight: '600',
  },
  linkButton: {
    alignItems: 'center',
    marginTop: 16,
  },
  linkText: {
    color: '#0066cc',
    fontSize: 14,
  },
  errorContainer: {
    backgroundColor: '#ffebee',
    padding: 12,
    borderRadius: 8,
    marginBottom: 16,
  },
  errorText: {
    color: '#c62828',
    fontSize: 14,
  },
  successContainer: {
    backgroundColor: '#e8f5e9',
    padding: 16,
    borderRadius: 8,
    alignItems: 'center',
  },
  successText: {
    color: '#2e7d32',
    fontSize: 14,
    textAlign: 'center',
    marginBottom: 12,
  },
  dividerContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginVertical: 24,
  },
  divider: {
    flex: 1,
    height: 1,
    backgroundColor: '#ddd',
  },
  dividerText: {
    marginHorizontal: 12,
    color: '#666',
    fontSize: 14,
  },
});
