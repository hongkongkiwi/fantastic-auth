import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, act, waitFor, cleanup } from '@testing-library/react'
import { AuthProvider, useAuth } from './useAuth'

const loginUiMock = vi.fn()
const logoutUiMock = vi.fn()
const getUiSessionStatusMock = vi.fn()

vi.mock('@tanstack/react-router', () => ({
  useNavigate: () => () => {},
  useLocation: () => ({ pathname: '/', search: '' }),
}))

vi.mock('@tanstack/react-start', () => ({
  useServerFn: (fn: unknown) => fn,
}))

vi.mock('../server/internal-api', () => ({
  loginUi: (...args: unknown[]) => loginUiMock(...args),
  logoutUi: (...args: unknown[]) => logoutUiMock(...args),
  getUiSessionStatus: (...args: unknown[]) => getUiSessionStatusMock(...args),
}))

const setup = async () => {
  const authRef: { current: ReturnType<typeof useAuth> | null } = { current: null }

  function TestComponent() {
    const auth = useAuth()
    authRef.current = auth
    return null
  }

  render(
    <AuthProvider>
      <TestComponent />
    </AuthProvider>
  )
  await act(async () => {})

  return authRef
}

describe('useAuth', () => {
  beforeEach(() => {
    cleanup()
    sessionStorage.clear()
    loginUiMock.mockReset()
    logoutUiMock.mockReset()
    getUiSessionStatusMock.mockReset()
    getUiSessionStatusMock.mockRejectedValue(new Error('Unauthorized'))
    loginUiMock.mockImplementation(({ data }: { data: { password: string } }) => {
      if (data.password === 'admin') return Promise.resolve({ ok: true })
      return Promise.reject(new Error('Invalid UI password'))
    })
    logoutUiMock.mockResolvedValue({ ok: true })
  })

  it('initializes with no user', async () => {
    const authRef = await setup()
    expect(authRef.current?.user).toBeNull()
    expect(authRef.current?.isAuthenticated).toBe(false)
    expect(authRef.current?.isLoading).toBe(false)
  })

  it('login succeeds with correct credentials', async () => {
    const authRef = await setup()
    expect(authRef.current).not.toBeNull()
    
    await act(async () => {
      await authRef.current?.login('admin@vault.local', 'admin')
    })
    
    await waitFor(() => {
      expect(authRef.current?.isAuthenticated).toBe(true)
      expect(authRef.current?.user).not.toBeNull()
      expect(authRef.current?.user?.email).toBe('admin@vault.local')
    })
  })

  it('login fails with incorrect credentials', async () => {
    const authRef = await setup()
    expect(authRef.current).not.toBeNull()
    
    await expect(
      act(async () => {
        await authRef.current?.login('wrong@email.com', 'wrong')
      })
    ).rejects.toThrow()
    
    expect(authRef.current?.isAuthenticated).toBe(false)
  })

  it.skip('logout clears user state', async () => {
    const authRef = await setup()
    expect(authRef.current).not.toBeNull()
    
    // First login
    await act(async () => {
      await authRef.current?.login('admin@vault.local', 'admin')
    })
    
    await waitFor(() => {
      expect(authRef.current?.isAuthenticated).toBe(true)
    })
    
    // Then logout
    await act(async () => {
      await authRef.current?.logout()
    })
    
    await waitFor(() => {
      expect(authRef.current?.isAuthenticated).toBe(false)
      expect(authRef.current?.user).toBeNull()
    })
  })

  it.skip('checkAuth returns correct state', async () => {
    const authRef = await setup()
    expect(authRef.current).not.toBeNull()
    
    // Initially not authenticated
    let isAuth = await authRef.current?.checkAuth()
    expect(isAuth).toBe(false)
    
    // Login
    await act(async () => {
      await authRef.current?.login('admin@vault.local', 'admin')
    })
    await waitFor(() => {
      expect(authRef.current?.isAuthenticated).toBe(true)
    })

    // Now authenticated
    isAuth = await authRef.current?.checkAuth()
    expect(isAuth).toBe(true)
  })
})
