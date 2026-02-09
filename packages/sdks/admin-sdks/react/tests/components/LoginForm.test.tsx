/**
 * LoginForm Component Tests
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { LoginForm } from '../../src/components/LoginForm';
import { VaultAuthProvider } from '../../src/context/VaultAuthContext';

// Mock the @vault/react hooks
jest.mock('@vault/react', () => ({
  useVaultAuth: () => ({
    signIn: jest.fn(),
    signInWithMagicLink: jest.fn(),
    signInWithOAuth: jest.fn(),
  }),
  useSignIn: () => ({
    isLoading: false,
    error: null,
    resetError: jest.fn(),
  }),
  VaultProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useVault: () => ({
    isLoaded: true,
    isSignedIn: false,
    user: null,
  }),
}));

const Wrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <VaultAuthProvider apiKey="test-key" baseUrl="https://test.vault.dev">
    {children}
  </VaultAuthProvider>
);

describe('LoginForm', () => {
  it('renders the login form with title', () => {
    render(<LoginForm />, { wrapper: Wrapper });
    
    expect(screen.getByText('Sign in to your account')).toBeInTheDocument();
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
  });

  it('shows email validation error for invalid email', async () => {
    render(<LoginForm />, { wrapper: Wrapper });
    
    const emailInput = screen.getByLabelText('Email');
    const submitButton = screen.getByRole('button', { name: /sign in/i });
    
    fireEvent.change(emailInput, { target: { value: 'invalid-email' } });
    fireEvent.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('Please enter a valid email')).toBeInTheDocument();
    });
  });

  it('shows required field errors when submitting empty form', async () => {
    render(<LoginForm />, { wrapper: Wrapper });
    
    const submitButton = screen.getByRole('button', { name: /sign in/i });
    fireEvent.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('Email is required')).toBeInTheDocument();
      expect(screen.getByText('Password is required')).toBeInTheDocument();
    });
  });

  it('toggles to magic link view when magic link is enabled', () => {
    render(<LoginForm enableMagicLink />, { wrapper: Wrapper });
    
    const toggleButton = screen.getByText('Sign in with magic link instead');
    fireEvent.click(toggleButton);
    
    expect(screen.getByRole('button', { name: /send magic link/i })).toBeInTheDocument();
  });

  it('renders social login buttons when providers are specified', () => {
    render(<LoginForm socialProviders={['google', 'github']} />, { wrapper: Wrapper });
    
    expect(screen.getByRole('button', { name: /continue with google/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /continue with github/i })).toBeInTheDocument();
  });

  it('shows forgot password link when enabled', () => {
    render(<LoginForm showForgotPassword />, { wrapper: Wrapper });
    
    expect(screen.getByText('Forgot password?')).toBeInTheDocument();
  });

  it('shows signup link when enabled', () => {
    render(<LoginForm showSignupLink />, { wrapper: Wrapper });
    
    expect(screen.getByText("Don't have an account?")).toBeInTheDocument();
    expect(screen.getByText('Sign up')).toBeInTheDocument();
  });
});
