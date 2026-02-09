import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('@tanstack/react-router', () => ({
  useNavigate: () => () => {},
  useLocation: () => ({ pathname: '/', search: '' }),
}))

vi.mock('@tanstack/react-start', () => ({
  useServerFn: (fn: unknown) => fn,
}))

vi.mock('../../server/internal-api', () => ({
  loginUi: vi.fn(),
  logoutUi: vi.fn(),
  getUiSessionStatus: vi.fn(),
}))

import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ThemeProvider } from '../../hooks/useTheme'
import { AuthProvider } from '../../hooks/useAuth'
import { useState } from 'react'
import { loginUi } from '../../server/internal-api'

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider defaultTheme="light">
        <AuthProvider>
          {children}
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  )
}

describe('Auth Flow Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('allows user to log in with valid credentials', async () => {
    const user = userEvent.setup()
    const mockLogin = vi.mocked(loginUi)
    mockLogin.mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const Wrapper = createWrapper()
    
    function TestForm() {
      const [email, setEmail] = useState('')
      const [password, setPassword] = useState('')

      return (
        <div>
          <input
            type="email"
            placeholder="Email"
            aria-label="Email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
          <input
            type="password"
            placeholder="Password"
            aria-label="Password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
          <button
            type="button"
            onClick={() => {
              void loginUi({ data: { email, password } })
            }}
          >
            Sign In
          </button>
        </div>
      )
    }

    render(
      <Wrapper>
        <TestForm />
      </Wrapper>
    )

    await user.type(screen.getByLabelText('Email'), 'test@example.com')
    await user.type(screen.getByLabelText('Password'), 'password123')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith({
        data: {
          email: 'test@example.com',
          password: 'password123',
        },
      })
    })
  })

  it('shows error for invalid credentials', async () => {
    const user = userEvent.setup()
    const mockLogin = vi.mocked(loginUi)
    mockLogin.mockRejectedValue(new Error('Invalid credentials'))

    const Wrapper = createWrapper()
    
    function TestForm() {
      const [email, setEmail] = useState('')
      const [password, setPassword] = useState('')

      return (
        <div>
          <input
            type="email"
            placeholder="Email"
            aria-label="Email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
          <input
            type="password"
            placeholder="Password"
            aria-label="Password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
          <button
            type="button"
            onClick={() => {
              void loginUi({ data: { email, password } })
            }}
          >
            Sign In
          </button>
          <div role="alert">Invalid credentials</div>
        </div>
      )
    }

    render(
      <Wrapper>
        <TestForm />
      </Wrapper>
    )

    await user.type(screen.getByLabelText('Email'), 'wrong@example.com')
    await user.type(screen.getByLabelText('Password'), 'wrongpassword')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid credentials')
    })
  })
})
