import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: ['src/cli.ts'],
    format: ['esm'],
    target: 'node20',
    clean: true,
    dts: false,
    sourcemap: true,
    splitting: false,
    external: ['commander', 'chalk', 'ts-morph', '@ts-morph/common', '@modelcontextprotocol/sdk'],
  },
  {
    entry: ['src/index.ts'],
    format: ['esm'],
    target: 'node20',
    dts: true,
    sourcemap: true,
    splitting: false,
    external: ['commander', 'chalk', 'ts-morph', '@ts-morph/common', '@modelcontextprotocol/sdk'],
  },
]);
