import { test, expect } from '@playwright/test'

test.describe('Settings', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel('Email').fill('admin@vault.local')
    await page.getByLabel('Password').fill('admin')
    await page.getByRole('button', { name: 'Sign In' }).click()
    await page.waitForURL('/')
    await page.goto('/settings')
  })

  test('can search for settings', async ({ page }) => {
    await page.getByPlaceholder('Search settings...').fill('email')
    
    // Should filter to show email-related settings
    await expect(page.getByText('Email')).toBeVisible()
  })

  test('can navigate through settings categories', async ({ page }) => {
    // Click on Security category
    await page.getByRole('button', { name: 'Security', exact: false }).click()
    
    // Should show security settings
    await expect(page.getByText('Authentication')).toBeVisible()
    await expect(page.getByText('Require MFA')).toBeVisible()
  })

  test('toggle settings work', async ({ page }) => {
    // Navigate to notifications
    await page.getByRole('button', { name: 'Notifications' }).click()
    
    // Find and click a toggle
    const emailToggle = page.locator('[role="switch"]').first()
    const initialState = await emailToggle.getAttribute('aria-checked')
    
    await emailToggle.click()
    
    // Should show save indicator
    await expect(page.getByText('You have unsaved changes')).toBeVisible()
  })

  test('slider settings work', async ({ page }) => {
    await page.getByRole('button', { name: 'Authentication' }).click()
    
    // Find slider and change value
    const slider = page.locator('[role="slider"]').first()
    await slider.fill('48')
    
    // Should show save indicator
    await expect(page.getByText('You have unsaved changes')).toBeVisible()
  })

  test('can save settings', async ({ page }) => {
    // Make a change
    await page.getByRole('button', { name: 'Notifications' }).click()
    await page.locator('[role="switch"]').first().click()
    
    // Click save
    await page.getByRole('button', { name: 'Save Changes' }).click()
    
    // Should show success message
    await expect(page.getByText('Settings saved successfully')).toBeVisible()
  })
})
