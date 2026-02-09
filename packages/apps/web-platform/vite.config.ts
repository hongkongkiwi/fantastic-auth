import { defineConfig, loadEnv } from 'vite'
import { devtools } from '@tanstack/devtools-vite'
import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import viteReact from '@vitejs/plugin-react'
import viteTsConfigPaths from 'vite-tsconfig-paths'
import { fileURLToPath, URL } from 'url'
import { sentryVitePlugin } from '@sentry/vite-plugin'

const config = defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const hasSentryConfig = Boolean(
    env.SENTRY_AUTH_TOKEN && env.SENTRY_ORG && env.SENTRY_PROJECT,
  )

  const plugins = [
    devtools(),
    viteTsConfigPaths({
      projects: ['./tsconfig.json'],
    }),
    tanstackStart(),
    viteReact(),
  ]

  if (hasSentryConfig) {
    plugins.push(
      sentryVitePlugin({
        authToken: env.SENTRY_AUTH_TOKEN,
        org: env.SENTRY_ORG,
        project: env.SENTRY_PROJECT,
      }),
    )
  }

  return {
    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url)),
      },
    },
    build: {
      sourcemap: hasSentryConfig,
      chunkSizeWarningLimit: 1200,
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (!id.includes('node_modules')) return
            if (id.includes('@sentry')) return 'vendor-sentry'
            if (id.includes('@tanstack')) return 'vendor-tanstack'
            if (id.includes('recharts') || id.includes('d3-')) return 'vendor-charts'
            if (id.includes('sonner')) return 'vendor-sonner'
            if (id.includes('framer-motion')) return 'vendor-motion'
            return 'vendor'
          },
        },
        onwarn(warning, warn) {
          if (
            (warning.code === 'UNUSED_EXTERNAL_IMPORT' &&
              typeof warning.id === 'string' &&
              warning.id.includes('node_modules/@tanstack/start-')) ||
            warning.message.includes('node_modules/@tanstack/start-')
          ) {
            return
          }
          warn(warning)
        },
      },
    },
    plugins,
  }
})

export default config
