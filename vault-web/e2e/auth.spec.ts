import { test, expect } from '@playwright/test'

test.describe('Authentication', () => {
  test('should redirect to login when not authenticated', async ({ page }) => {
    await page.goto('/')
    await expect(page).toHaveURL('/login')
  })

  test('should login with correct credentials', async ({ page }) => {
    await page.goto('/login')
    
    await page.fill('input[type="email"]', 'admin@vault.local')
    await page.fill('input[type="password"]', 'admin')
    await page.click('button[type="submit"]')
    
    await expect(page).toHaveURL('/')
    await expect(page.locator('text=Dashboard')).toBeVisible()
  })

  test('should show error with incorrect credentials', async ({ page }) => {
    await page.goto('/login')
    
    await page.fill('input[type="email"]', 'wrong@email.com')
    await page.fill('input[type="password"]', 'wrong')
    await page.click('button[type="submit"]')
    
    await expect(page.locator('text=Invalid credentials')).toBeVisible()
  })

  test('should logout successfully', async ({ page }) => {
    // Login first
    await page.goto('/login')
    await page.fill('input[type="email"]', 'admin@vault.local')
    await page.fill('input[type="password"]', 'admin')
    await page.click('button[type="submit"]')
    
    // Then logout
    await page.click('text=Logout')
    await expect(page).toHaveURL('/login')
  })
})

test.describe('Navigation', () => {
  test.beforeEach(async ({ page }) => {
    // Login before each test
    await page.goto('/login')
    await page.fill('input[type="email"]', 'admin@vault.local')
    await page.fill('input[type="password"]', 'admin')
    await page.click('button[type="submit"]')
  })

  test('should navigate to tenants page', async ({ page }) => {
    await page.click('text=Tenants')
    await expect(page).toHaveURL('/tenants')
    await expect(page.locator('text=Tenants')).toBeVisible()
  })

  test('should navigate to users page', async ({ page }) => {
    await page.click('text=Users')
    await expect(page).toHaveURL('/users')
    await expect(page.locator('text=Users')).toBeVisible()
  })

  test('should navigate to billing page', async ({ page }) => {
    await page.click('text=Billing')
    await expect(page).toHaveURL('/billing')
    await expect(page.locator('text=Billing')).toBeVisible()
  })

  test('should open global search with Cmd+K', async ({ page }) => {
    await page.keyboard.press('Control+k')
    await expect(page.locator('text=Search commands, pages, or actions')).toBeVisible()
  })
})

test.describe('Responsive Design', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login')
    await page.fill('input[type="email"]', 'admin@vault.local')
    await page.fill('input[type="password"]', 'admin')
    await page.click('button[type="submit"]')
  })

  test('should show mobile navigation on small screens', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 })
    await expect(page.locator('nav.fixed.bottom-0')).toBeVisible()
  })

  test('should hide sidebar on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 })
    await expect(page.locator('aside.fixed.left-0')).not.toBeVisible()
  })
})
