import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['demo/app.js'],
  format: ['esm'],
  outDir: 'demo/dist',
  platform: 'browser',
  target: 'es2020',
  clean: true,
  noExternal: ['qrcode', 'html5-qrcode'],
});
