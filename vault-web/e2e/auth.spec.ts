import { test, expect } from '@playwright/test'

test.describe('Authentication', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login')
  })

  test('user can log in with valid credentials', async ({ page }) => {
    // Fill in login form
    await page.getByLabel('Email').fill('admin@vault.local')
    await page.getByLabel('Password').fill('admin')
    
    // Click sign in
    await page.getByRole('button', { name: 'Sign In' }).click()
    
    // Should redirect to dashboard
    await expect(page).toHaveURL('/')
    
    // Should see dashboard content
    await expect(page.getByText('Dashboard')).toBeVisible()
  })

  test('shows error for invalid credentials', async ({ page }) => {
    await page.getByLabel('Email').fill('wrong@example.com')
    await page.getByLabel('Password').fill('wrongpassword')
    await page.getByRole('button', { name: 'Sign In' }).click()
    
    // Should show error message
    await expect(page.getByRole('alert')).toContainText('Invalid')
  })

  test('password visibility toggle works', async ({ page }) => {
    const passwordInput = page.getByLabel('Password')
    
    // Type password
    await passwordInput.fill('secret123')
    
    // Should be password type by default
    await expect(passwordInput).toHaveAttribute('type', 'password')
    
    // Click show password button
    await page.getByRole('button', { name: 'Show password' }).click()
    
    // Should be text type now
    await expect(passwordInput).toHaveAttribute('type', 'text')
  })

  test('magic link tab works', async ({ page }) => {
    // Click magic link tab
    await page.getByRole('tab', { name: 'Magic Link' }).click()
    
    // Should see email input for magic link
    await expect(page.getByPlaceholder('Enter your email')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Send Magic Link' })).toBeVisible()
  })

  test('keyboard navigation works', async ({ page }) => {
    // Tab through form fields
    await page.keyboard.press('Tab')
    await expect(page.getByLabel('Email')).toBeFocused()
    
    await page.keyboard.press('Tab')
    await expect(page.getByLabel('Password')).toBeFocused()
    
    await page.keyboard.press('Tab')
    await expect(page.getByRole('button', { name: 'Sign In' })).toBeFocused()
  })
})
