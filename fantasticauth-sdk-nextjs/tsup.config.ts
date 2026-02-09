import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'server/index': 'src/server/index.ts',
    'client/index': 'src/client/index.ts',
    'api/index': 'src/api/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  external: ['next', 'react', 'react-dom', 'next/headers', 'next/server'],
  esbuildOptions(options) {
    // Ensure proper handling of 'use client' directives
    options.banner = {
      js: '"use client";',
    };
  },
  // Override banner for server-only files
  async onSuccess() {
    // Remove 'use client' from server files
    const fs = await import('fs');
    const path = await import('path');
    const serverDir = path.join(process.cwd(), 'dist', 'server');
    
    if (fs.existsSync(serverDir)) {
      const files = fs.readdirSync(serverDir);
      for (const file of files) {
        if (file.endsWith('.js') || file.endsWith('.mjs')) {
          const filePath = path.join(serverDir, file);
          let content = fs.readFileSync(filePath, 'utf-8');
          content = content.replace(/^"use client";\s*/m, '');
          fs.writeFileSync(filePath, content);
        }
      }
    }

    // Remove 'use client' from api files
    const apiDir = path.join(process.cwd(), 'dist', 'api');
    if (fs.existsSync(apiDir)) {
      const files = fs.readdirSync(apiDir);
      for (const file of files) {
        if (file.endsWith('.js') || file.endsWith('.mjs')) {
          const filePath = path.join(apiDir, file);
          let content = fs.readFileSync(filePath, 'utf-8');
          content = content.replace(/^"use client";\s*/m, '');
          fs.writeFileSync(filePath, content);
        }
      }
    }
  },
});
