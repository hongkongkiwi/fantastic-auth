import * as React from 'react'
import { render as rtlRender, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ThemeProvider } from '../hooks/useTheme'

// Create a custom render function that includes providers
export function render(ui: React.ReactElement, options = {}) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })

  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <ThemeProvider defaultTheme="light">
          {children}
        </ThemeProvider>
      </QueryClientProvider>
    )
  }

  return {
    ...rtlRender(ui, { wrapper: Wrapper, ...options }),
    user: userEvent.setup(),
  }
}

// Re-export everything from testing-library
export { screen, waitFor, within }

// Accessibility testing helpers
export async function testA11y(container: HTMLElement) {
  // This would use jest-axe in a real setup
  // For now, we'll do basic checks
  const interactiveElements = container.querySelectorAll(
    'button, a, input, select, textarea, [tabindex]:not([tabindex="-1"])'
  )
  
  for (const el of interactiveElements) {
    // Check for accessible name
    const hasAccessibleName = 
      el.hasAttribute('aria-label') ||
      el.hasAttribute('aria-labelledby') ||
      el.textContent?.trim() ||
      (el as HTMLInputElement).placeholder
    
    if (!hasAccessibleName) {
      console.warn('Interactive element missing accessible name:', el)
    }
  }
}

// Mock data generators
export function createMockUser(overrides = {}) {
  return {
    id: 'user-1',
    email: 'test@example.com',
    name: 'Test User',
    status: 'active',
    ...overrides,
  }
}

export function createMockTenant(overrides = {}) {
  return {
    id: 'tenant-1',
    name: 'Test Tenant',
    slug: 'test-tenant',
    status: 'active',
    plan: 'pro',
    ...overrides,
  }
}

// Form testing helpers
export async function fillFormField(
  user: ReturnType<typeof userEvent.setup>,
  labelText: string,
  value: string
) {
  const field = screen.getByLabelText(labelText)
  await user.clear(field)
  await user.type(field, value)
}

export async function selectOption(
  user: ReturnType<typeof userEvent.setup>,
  labelText: string,
  optionText: string
) {
  const select = screen.getByLabelText(labelText)
  await user.click(select)
  const option = screen.getByText(optionText)
  await user.click(option)
}

// Async testing helpers
export function createDeferred<T>() {
  let resolve: (value: T) => void
  let reject: (error: Error) => void
  
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  
  return { promise, resolve: resolve!, reject: reject! }
}
