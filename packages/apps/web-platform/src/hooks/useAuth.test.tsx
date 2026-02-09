import type { ReactNode } from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { AuthProvider, useAuth } from './useAuth'

const mockNavigate = vi.fn()

vi.mock('@tanstack/react-router', () => ({
  useNavigate: () => mockNavigate,
}))

const wrapper = ({ children }: { children: ReactNode }) => <AuthProvider>{children}</AuthProvider>

const jsonResponse = (status: number, body: unknown) =>
  Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  )

describe('useAuth', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    Object.defineProperty(document, 'cookie', {
      writable: true,
      value: '',
    })
    vi.stubGlobal('fetch', vi.fn())
  })

  it('initializes unauthenticated when no UI session exists', async () => {
    const { result } = renderHook(() => useAuth(), { wrapper })

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    expect(result.current.isAuthenticated).toBe(false)
    expect(result.current.user).toBeNull()
    expect(fetch).not.toHaveBeenCalled()
  })

  it('logs in and persists user session state', async () => {
    const fetchMock = vi.mocked(fetch)
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          user: { id: 'u_1', email: 'test@example.com', name: 'Test User', role: 'admin' },
          csrfToken: 'csrf_token_1',
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      ),
    )

    const { result } = renderHook(() => useAuth(), { wrapper })

    await act(async () => {
      await result.current.login('test@example.com', 'password123')
    })

    expect(result.current.isAuthenticated).toBe(true)
    expect(result.current.user?.email).toBe('test@example.com')
    expect(mockNavigate).toHaveBeenCalledWith({ to: '/' })
  })

  it('exposes and clears login errors', async () => {
    const fetchMock = vi.mocked(fetch)
    fetchMock.mockImplementation(() => jsonResponse(401, { message: 'Invalid credentials' }))

    const { result } = renderHook(() => useAuth(), { wrapper })

    await act(async () => {
      await expect(result.current.login('test@example.com', 'bad-password')).rejects.toThrow(
        'Invalid credentials',
      )
    })

    expect(result.current.error).toBe('Invalid credentials')

    act(() => {
      result.current.clearError()
    })

    expect(result.current.error).toBeNull()
  })

  it('logs out and clears authenticated state', async () => {
    const fetchMock = vi.mocked(fetch)
    fetchMock
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            user: { id: 'u_1', email: 'test@example.com', name: 'Test User', role: 'admin' },
            csrfToken: 'csrf_token_1',
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        ),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }))

    const { result } = renderHook(() => useAuth(), { wrapper })

    await act(async () => {
      await result.current.login('test@example.com', 'password123')
    })

    await act(async () => {
      await result.current.logout()
    })

    expect(result.current.isAuthenticated).toBe(false)
    expect(result.current.user).toBeNull()
    expect(mockNavigate).toHaveBeenCalledWith({ to: '/login' })
  })
})
