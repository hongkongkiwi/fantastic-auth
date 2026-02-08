import { test, expect } from '@playwright/test'

test.describe('Navigation', () => {
  test.beforeEach(async ({ page }) => {
    // Login first
    await page.goto('/login')
    await page.getByLabel('Email').fill('admin@vault.local')
    await page.getByLabel('Password').fill('admin')
    await page.getByRole('button', { name: 'Sign In' }).click()
    await page.waitForURL('/')
  })

  test('can navigate to all main pages', async ({ page }) => {
    // Dashboard
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()

    // Tenants
    await page.getByRole('link', { name: 'Tenants' }).click()
    await expect(page).toHaveURL('/tenants')
    await expect(page.getByRole('heading', { name: 'Tenants' })).toBeVisible()

    // Users
    await page.getByRole('link', { name: 'Users' }).click()
    await expect(page).toHaveURL('/users')
    await expect(page.getByRole('heading', { name: 'Users' })).toBeVisible()

    // Settings
    await page.getByRole('link', { name: 'Settings' }).click()
    await expect(page).toHaveURL('/settings')
    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible()
  })

  test('command palette works', async ({ page }) => {
    // Open command palette
    await page.keyboard.press('Control+k')
    
    // Should see command palette
    await expect(page.getByPlaceholder('Type a command or search...')).toBeVisible()
    
    // Type to search
    await page.getByPlaceholder('Type a command or search...').fill('tenants')
    
    // Should see tenants option
    await expect(page.getByText('Tenants').first()).toBeVisible()
    
    // Press enter to navigate
    await page.keyboard.press('Enter')
    await expect(page).toHaveURL('/tenants')
  })

  test('sidebar collapse works', async ({ page }) => {
    // Find and click collapse button
    const collapseButton = page.getByRole('button', { name: 'Collapse sidebar' })
    await collapseButton.click()
    
    // Sidebar should be collapsed (check for specific class or width)
    await expect(page.locator('aside')).toHaveClass(/w-\[80px\]/)
  })

  test('mobile navigation works', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 })
    
    // Open mobile menu
    await page.getByRole('button', { name: 'Open navigation menu' }).click()
    
    // Should see mobile nav
    await expect(page.getByRole('navigation')).toBeVisible()
    
    // Click a link
    await page.getByRole('link', { name: 'Tenants' }).click()
    await expect(page).toHaveURL('/tenants')
  })
})
