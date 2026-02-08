import adapter from '@sveltejs/adapter-auto';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter(),
    alias: {
      '$lib': './src/lib',
      '$lib/*': './src/lib/*'
    }
  },
  compilerOptions: {
    // Enable runes mode for Svelte 5
    runes: true
  }
};

export default config;
