import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, act, waitFor, cleanup, screen } from '@testing-library/react'
import { AuthProvider, ProtectedRoute, useAuth } from './useAuth'

const loginUiMock = vi.fn()
const logoutUiMock = vi.fn()
const getUiSessionStatusMock = vi.fn()
const toastMock = vi.hoisted(() => ({
  success: vi.fn(),
  error: vi.fn(),
  warning: vi.fn(),
  info: vi.fn(),
  loading: vi.fn(),
  promise: vi.fn(),
}))
const navigateMock = vi.hoisted(() => vi.fn())
const locationRef = vi.hoisted(() => ({ current: { pathname: '/', search: '' } }))

vi.mock('@tanstack/react-router', () => ({
  useNavigate: () => navigateMock,
  useLocation: () => locationRef.current,
}))

vi.mock('@tanstack/react-start', () => ({
  useServerFn: (fn: unknown) => fn,
}))

vi.mock('../components/ui/Toaster', () => ({
  toast: toastMock,
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
    navigateMock.mockReset()
    locationRef.current = { pathname: '/', search: '' }
    Object.values(toastMock).forEach((mock) => mock.mockReset())
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

  it('logout clears user state', async () => {
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

  it('checkAuth returns correct state', async () => {
    getUiSessionStatusMock.mockReset()
    getUiSessionStatusMock
      .mockRejectedValueOnce(new Error('Unauthorized'))
      .mockRejectedValueOnce(new Error('Unauthorized'))
      .mockResolvedValueOnce({ ok: true })

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

  it('keeps session user when server session is valid', async () => {
    const storedUser = { id: 'ui', email: 'admin@vault.local', name: 'Admin' }
    sessionStorage.setItem('vault_ui_user', JSON.stringify(storedUser))
    getUiSessionStatusMock.mockResolvedValueOnce({ ok: true })

    const authRef = await setup()

    await waitFor(() => {
      expect(authRef.current?.user?.email).toBe('admin@vault.local')
      expect(authRef.current?.isAuthenticated).toBe(true)
    })
  })

  it('creates a default user when session is valid without stored user', async () => {
    getUiSessionStatusMock.mockResolvedValueOnce({ ok: true })
    const authRef = await setup()

    await waitFor(() => {
      expect(authRef.current?.user?.email).toBe('admin')
      expect(authRef.current?.isAuthenticated).toBe(true)
    })
  })

  it('clears invalid stored user', async () => {
    sessionStorage.setItem('vault_ui_user', '{invalid json')
    const authRef = await setup()

    await waitFor(() => {
      expect(authRef.current?.user).toBeNull()
      expect(sessionStorage.getItem('vault_ui_user')).toBeNull()
    })
  })

  it('navigates to redirect after login', async () => {
    locationRef.current = { pathname: '/login', search: '?redirect=%2Fsettings' }
    const authRef = await setup()
    await act(async () => {
      await authRef.current?.login('admin@vault.local', 'admin')
    })
    await waitFor(() => {
      expect(navigateMock).toHaveBeenCalledWith({ to: '/settings' })
    })
  })

  it('keeps user when logout fails', async () => {
    logoutUiMock.mockRejectedValueOnce(new Error('Server error'))
    const authRef = await setup()
    await act(async () => {
      await authRef.current?.login('admin@vault.local', 'admin')
    })

    await act(async () => {
      await authRef.current?.logout()
    })

    await waitFor(() => {
      expect(authRef.current?.isAuthenticated).toBe(true)
      expect(authRef.current?.user).not.toBeNull()
    })
  })

  it('renders loading state in ProtectedRoute', async () => {
    getUiSessionStatusMock.mockImplementationOnce(() => new Promise(() => {}))
    render(
      <AuthProvider>
        <ProtectedRoute>
          <div>Protected</div>
        </ProtectedRoute>
      </AuthProvider>
    )

    expect(await screen.findByText('Loading…')).toBeInTheDocument()
  })

  it('renders children when authenticated in ProtectedRoute', async () => {
    sessionStorage.setItem('vault_ui_user', JSON.stringify({ id: 'ui', email: 'admin@vault.local' }))
    getUiSessionStatusMock.mockResolvedValueOnce({ ok: true })

    render(
      <AuthProvider>
        <ProtectedRoute>
          <div>Protected</div>
        </ProtectedRoute>
      </AuthProvider>
    )

    expect(await screen.findByText('Protected')).toBeInTheDocument()
  })
})
