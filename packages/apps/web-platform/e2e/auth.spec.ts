import { test, expect } from '@playwright/test'

test.describe('Authentication', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login')
  })

  test('should display login form', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /sign in/i })).toBeVisible()
    await expect(page.getByLabel(/email/i)).toBeVisible()
    await expect(page.getByLabel(/password/i)).toBeVisible()
    await expect(page.getByRole('button', { name: /sign in/i })).toBeVisible()
  })

  test('should show error for invalid credentials', async ({ page }) => {
    await page.getByLabel(/email/i).fill('invalid@example.com')
    await page.getByLabel(/password/i).fill('wrongpassword')
    await page.getByRole('button', { name: /sign in/i }).click()

    await expect(page.getByText(/invalid credentials/i)).toBeVisible()
  })

  test('should redirect to dashboard after successful login', async ({ page }) => {
    // This would need proper test credentials
    await page.getByLabel(/email/i).fill('admin@example.com')
    await page.getByLabel(/password/i).fill('correctpassword')
    await page.getByRole('button', { name: /sign in/i }).click()

    await expect(page).toHaveURL('/')
    await expect(page.getByText(/dashboard/i)).toBeVisible()
  })

  test('should have accessible form elements', async ({ page }) => {
    // Check for proper labels
    const emailInput = page.getByLabel(/email/i)
    const passwordInput = page.getByLabel(/password/i)
    
    await expect(emailInput).toHaveAttribute('type', 'email')
    await expect(passwordInput).toHaveAttribute('type', 'password')
    
    // Check form can be submitted via keyboard
    await emailInput.focus()
    await page.keyboard.press('Tab')
    await expect(passwordInput).toBeFocused()
  })

  test('should have CSRF protection', async ({ page }) => {
    // Check for CSRF token in meta tag or cookie
    const csrfToken = await page.locator('meta[name="csrf-token"]').getAttribute('content')
    expect(csrfToken).toBeTruthy()
  })

  test('should have security headers', async ({ page }) => {
    const response = await page.goto('/login')
    const headers = response?.headers()
    
    expect(headers?.['x-content-type-options']).toBe('nosniff')
    expect(headers?.['x-frame-options']).toBe('DENY')
  })
})

test.describe('Protected Routes', () => {
  test('should redirect to login when accessing protected route unauthenticated', async ({ page }) => {
    await page.goto('/tenants')
    await expect(page).toHaveURL('/login?redirect=%2Ftenants')
  })

  test('should redirect to original URL after login', async ({ page }) => {
    await page.goto('/users')
    await expect(page).toHaveURL(/.*redirect=.*/)
    
    // After login, should redirect to /users
    await page.getByLabel(/email/i).fill('admin@example.com')
    await page.getByLabel(/password/i).fill('correctpassword')
    await page.getByRole('button', { name: /sign in/i }).click()
    
    await expect(page).toHaveURL('/users')
  })
})

test.describe('Logout', () => {
  test('should logout successfully', async ({ page }) => {
    // Login first
    await page.goto('/login')
    await page.getByLabel(/email/i).fill('admin@example.com')
    await page.getByLabel(/password/i).fill('correctpassword')
    await page.getByRole('button', { name: /sign in/i }).click()
    
    await expect(page).toHaveURL('/')
    
    // Logout
    await page.getByRole('button', { name: /log out/i }).click()
    
    await expect(page).toHaveURL('/login')
    await expect(page.getByRole('heading', { name: /sign in/i })).toBeVisible()
  })
})
