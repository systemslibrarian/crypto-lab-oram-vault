import { defineConfig } from 'vitest/config';

// Tests exercise the pure client/server protocol modules. They depend only on
// the Web Crypto API (crypto.subtle / crypto.getRandomValues), which is a Node
// global from v20 onward — so the lightweight 'node' environment is enough and
// no DOM/jsdom is required.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/client/**', 'src/server/**'],
      reporter: ['text', 'html'],
    },
  },
});
