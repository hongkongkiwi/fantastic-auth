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
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: [
        'src/components/ui/Alert.tsx',
        'src/components/ui/Badge.tsx',
        'src/components/ui/Button.tsx',
        'src/components/ui/Card.tsx',
        'src/components/ui/Checkbox.tsx',
        'src/components/ui/Input.tsx',
        'src/components/ui/Label.tsx',
        'src/components/ui/RadioGroup.tsx',
        'src/components/ui/Select.tsx',
        'src/components/ui/Skeleton.tsx',
        'src/components/ui/Slider.tsx',
        'src/components/ui/Switch.tsx',
        'src/components/ui/Tabs.tsx',
        'src/components/ui/Textarea.tsx',
        'src/components/ui/Toaster.tsx',
        'src/hooks/useAuth.tsx',
        'src/lib/utils.ts',
        'src/server/auth-middleware.ts',
        'src/server/internal-client.ts',
        'src/server/session.ts',
      ],
      exclude: [
        'src/test/**',
        'src/**/*.test.*',
        'src/**/*.spec.*',
        'src/**/__tests__/**',
      ],
      thresholds: {
        lines: 95,
        statements: 95,
        functions: 95,
        branches: 90,
      },
    },
  },
})
