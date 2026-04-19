import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-oram-vault/',
  worker: {
    format: 'es',
  },
  build: {
    target: 'es2022',
  },
});
