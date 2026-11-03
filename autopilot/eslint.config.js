import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default defineConfig(
  js.configs.recommended,
  tseslint.configs.recommendedTypeChecked,
  { languageOptions: { globals: globals.node, parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname } } },
  // node:test runs a test() it was not awaited for, and reports its failure.
  {
    rules: {
      '@typescript-eslint/no-floating-promises': ['error', { allowForKnownSafeCalls: [{ from: 'package', name: 'test', package: 'node:test' }] }],
    },
  },
  // This file is in no tsconfig, so it gets no type-aware rules.
  { files: ['**/*.js'], extends: [tseslint.configs.disableTypeChecked] },
);
