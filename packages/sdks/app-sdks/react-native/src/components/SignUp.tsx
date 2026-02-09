/**
 * SignUp Component
 * 
 * Pre-built sign-up screen for React Native.
 * 
 * @example
 * ```tsx
 * function SignUpScreen() {
 *   return (
 *     <SignUp
 *       oauthProviders={['google', 'apple']}
 *       requireName={true}
 *       onSignUp={() => navigation.navigate('Home')}
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
import { SignUpProps } from '../types';
import { useSignUp } from '../hooks/useSignUp';
import { useAuth } from '../hooks/useAuth';
import { OAuthButton } from './OAuthButton';

export function SignUp({
  oauthProviders = [],
  requireName = false,
  onSignUp,
  onError,
  style,
  testID,
}: SignUpProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [name, setName] = useState('');
  const [passwordError, setPasswordError] = useState<string | null>(null);
  
  const { signUp, isLoading, error } = useSignUp();
  const { isSignedIn } = useAuth();
  
  // Call onSignUp when authentication is successful
  React.useEffect(() => {
    if (isSignedIn && onSignUp) {
      onSignUp();
    }
  }, [isSignedIn, onSignUp]);
  
  // Call onError when there's an error
  React.useEffect(() => {
    if (error && onError) {
      onError(error);
    }
  }, [error, onError]);
  
  const validatePassword = () => {
    if (password !== confirmPassword) {
      setPasswordError('Passwords do not match');
      return false;
    }
    if (password.length < 8) {
      setPasswordError('Password must be at least 8 characters');
      return false;
    }
    setPasswordError(null);
    return true;
  };
  
  const handleSignUp = async () => {
    if (!email || !password) {
      return;
    }
    
    if (!validatePassword()) {
      return;
    }
    
    try {
      const signUpData: any = { email, password };
      if (requireName && name) {
        signUpData.name = name;
      }
      await signUp(signUpData);
    } catch {
      // Error is handled by the hook
    }
  };
  
  return (
    <ScrollView style={[styles.container, style]} testID={testID}>
      <Text style={styles.title}>Create Account</Text>
      
      {error && (
        <View style={styles.errorContainer}>
          <Text style={styles.errorText}>{error.message}</Text>
        </View>
      )}
      
      {passwordError && (
        <View style={styles.errorContainer}>
          <Text style={styles.errorText}>{passwordError}</Text>
        </View>
      )}
      
      {requireName && (
        <View style={styles.inputContainer}>
          <Text style={styles.label}>Full Name</Text>
          <TextInput
            style={styles.input}
            value={name}
            onChangeText={setName}
            placeholder="John Doe"
            autoCapitalize="words"
            editable={!isLoading}
          />
        </View>
      )}
      
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
          placeholder="Create a password"
          secureTextEntry
          autoCapitalize="none"
          editable={!isLoading}
        />
      </View>
      
      <View style={styles.inputContainer}>
        <Text style={styles.label}>Confirm Password</Text>
        <TextInput
          style={styles.input}
          value={confirmPassword}
          onChangeText={setConfirmPassword}
          placeholder="Confirm your password"
          secureTextEntry
          autoCapitalize="none"
          editable={!isLoading}
        />
      </View>
      
      <TouchableOpacity
        style={[styles.button, styles.primaryButton, isLoading && styles.disabledButton]}
        onPress={handleSignUp}
        disabled={isLoading}
      >
        {isLoading ? (
          <ActivityIndicator color="#fff" />
        ) : (
          <Text style={styles.buttonText}>Create Account</Text>
        )}
      </TouchableOpacity>
      
      {oauthProviders.length > 0 && (
        <View style={styles.dividerContainer}>
          <View style={styles.divider} />
          <Text style={styles.dividerText}>or sign up with</Text>
          <View style={styles.divider} />
        </View>
      )}
      
      {oauthProviders.map((provider) => (
        <OAuthButton
          key={provider}
          provider={provider}
          text={`Continue with ${provider.charAt(0).toUpperCase() + provider.slice(1)}`}
          onSuccess={onSignUp}
          onError={onError}
        />
      ))}
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
  disabledButton: {
    opacity: 0.6,
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
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
