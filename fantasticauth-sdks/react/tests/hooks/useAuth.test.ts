/**
 * useAuth Hook Tests
 */

import { renderHook } from '@testing-library/react';
import { useAuth } from '../../src/hooks/useAuth';
import { VaultAuthProvider } from '../../src/context/VaultAuthContext';
import React from 'react';

// Mock the context
jest.mock('../../src/context/VaultAuthContext', () => ({
  ...jest.requireActual('../../src/context/VaultAuthContext'),
  useVaultAuthContext: () => ({
    user: null,
    isLoading: false,
    isAuthenticated: false,
    login: jest.fn(),
    logout: jest.fn(),
    signup: jest.fn(),
    resetPassword: jest.fn(),
    completePasswordReset: jest.fn(),
    error: null,
    clearError: jest.fn(),
  }),
}));

const wrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <VaultAuthProvider apiKey="test-key" baseUrl="https://test.vault.dev">
    {children}
  </VaultAuthProvider>
);

describe('useAuth', () => {
  it('returns authentication state', () => {
    const { result } = renderHook(() => useAuth(), { wrapper });
    
    expect(result.current.user).toBeNull();
    expect(result.current.isLoading).toBe(false);
    expect(result.current.isAuthenticated).toBe(false);
  });

  it('exposes login function', () => {
    const { result } = renderHook(() => useAuth(), { wrapper });
    
    expect(typeof result.current.login).toBe('function');
  });

  it('exposes logout function', () => {
    const { result } = renderHook(() => useAuth(), { wrapper });
    
    expect(typeof result.current.logout).toBe('function');
  });

  it('exposes signup function', () => {
    const { result } = renderHook(() => useAuth(), { wrapper });
    
    expect(typeof result.current.signup).toBe('function');
  });

  it('exposes resetPassword function', () => {
    const { result } = renderHook(() => useAuth(), { wrapper });
    
    expect(typeof result.current.resetPassword).toBe('function');
  });
});
