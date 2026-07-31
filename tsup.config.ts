import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2020',
  platform: 'neutral',
  // The browser entry must not contain bare package imports. Consumers can
  // import the published package through a bundler, but the static demo is
  // loaded directly by the browser.
  noExternal: [/@noble\/.*/, 'json-canonicalize'],
});
