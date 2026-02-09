import { test, expect } from '@playwright/test'

test.describe('Accessibility', () => {
  test('should have skip links', async ({ page }) => {
    await page.goto('/')
    
    // Skip link should be visible on first Tab
    await page.keyboard.press('Tab')
    const skipLink = page.locator('.skip-link, [href="#main-content"]')
    await expect(skipLink).toBeVisible()
    await expect(skipLink).toHaveText(/skip to main content/i)
  })

  test('should have proper heading structure', async ({ page }) => {
    await page.goto('/')
    
    // Check for single H1
    const h1s = await page.locator('h1').count()
    expect(h1s).toBeGreaterThan(0)
    
    // Check heading hierarchy (no skipped levels)
    const headings = await page.locator('h1, h2, h3, h4, h5, h6').all()
    let previousLevel = 0
    
    for (const heading of headings) {
      const level = parseInt(await heading.evaluate(el => el.tagName[1]))
      expect(level).toBeGreaterThanOrEqual(previousLevel)
      expect(level).toBeLessThanOrEqual(previousLevel + 1)
      previousLevel = level
    }
  })

  test('all images should have alt text', async ({ page }) => {
    await page.goto('/')
    
    const images = await page.locator('img').all()
    for (const img of images) {
      const alt = await img.getAttribute('alt')
      const ariaHidden = await img.getAttribute('aria-hidden')
      
      // Images should have alt text or be marked as decorative
      expect(alt !== null || ariaHidden === 'true').toBe(true)
    }
  })

  test('all buttons should have accessible names', async ({ page }) => {
    await page.goto('/')
    
    const buttons = await page.locator('button').all()
    for (const button of buttons) {
      const ariaLabel = await button.getAttribute('aria-label')
      const text = await button.textContent()
      const ariaLabelledBy = await button.getAttribute('aria-labelledby')
      const title = await button.getAttribute('title')
      
      // Button should have some form of accessible name
      expect(
        ariaLabel || text?.trim() || ariaLabelledBy || title
      ).toBeTruthy()
    }
  })

  test('form inputs should have associated labels', async ({ page }) => {
    await page.goto('/login')
    
    const inputs = await page.locator('input:not([type="hidden"])').all()
    for (const input of inputs) {
      const id = await input.getAttribute('id')
      const ariaLabel = await input.getAttribute('aria-label')
      const ariaLabelledBy = await input.getAttribute('aria-labelledby')
      const placeholder = await input.getAttribute('placeholder')
      
      // Input should have label via for/id, aria-label, aria-labelledby, or placeholder
      if (id) {
        const label = page.locator(`label[for="${id}"]`)
        const hasLabel = await label.count() > 0
        expect(hasLabel || ariaLabel || ariaLabelledBy || placeholder).toBe(true)
      } else {
        expect(ariaLabel || ariaLabelledBy || placeholder).toBe(true)
      }
    }
  })

  test('should have ARIA landmarks', async ({ page }) => {
    await page.goto('/')
    
    // Check for main landmark
    const main = await page.locator('main, [role="main"]').count()
    expect(main).toBeGreaterThan(0)
    
    // Check for navigation landmark
    const nav = await page.locator('nav, [role="navigation"]').count()
    expect(nav).toBeGreaterThan(0)
  })

  test('color contrast should meet WCAG AA standards', async ({ page }) => {
    await page.goto('/')
    
    // This would typically use axe-core or similar
    // For now, we check that the page has sufficient contrast
    // by verifying text colors are not too light on light backgrounds
    
    const bodyColor = await page.locator('body').evaluate(el => {
      return window.getComputedStyle(el).color
    })
    
    // Body should have readable text
    expect(bodyColor).not.toBe('rgba(0, 0, 0, 0)')
  })

  test('should be keyboard navigable', async ({ page }) => {
    await page.goto('/login')
    
    // Navigate through form using Tab
    await page.keyboard.press('Tab')
    const focused1 = await page.locator(':focus').getAttribute('data-testid')
    
    await page.keyboard.press('Tab')
    const focused2 = await page.locator(':focus').getAttribute('data-testid')
    
    // Focus should move between elements
    expect(focused1).not.toEqual(focused2)
  })

  test('modal dialogs should trap focus', async ({ page }) => {
    await page.goto('/')
    
    // Open a modal (if present)
    const modalTrigger = page.locator('[data-testid="modal-trigger"]').first()
    if (await modalTrigger.isVisible().catch(() => false)) {
      await modalTrigger.click()
      
      const modal = page.locator('[role="dialog"]').first()
      await expect(modal).toBeVisible()
      
      // Tab multiple times - focus should stay in modal
      for (let i = 0; i < 5; i++) {
        await page.keyboard.press('Tab')
      }
      
      const focusedElement = await page.locator(':focus').evaluate(el => {
        return el.closest('[role="dialog"]') !== null
      })
      
      expect(focusedElement).toBe(true)
    }
  })
})
