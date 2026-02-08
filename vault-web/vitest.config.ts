import { defineConfig, configDefaults } from 'vitest/config'
import { fileURLToPath, URL } from 'url'

export default defineConfig({
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['src/test/setup.ts'],
    include: [
      'src/**/*.{test,spec}.?(c|m)[jt]s?(x)',
      'src/**/__tests__/**/*.{test,spec}.?(c|m)[jt]s?(x)',
    ],
    exclude: [...configDefaults.exclude, 'e2e/**', '**/e2e/**'],
  },
})
