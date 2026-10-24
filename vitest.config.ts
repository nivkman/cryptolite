import { defineConfig } from 'vitest/config';

// Two projects:
// - unit:    test/compat, test/modern and any other test/** suite; runs against src/ directly.
// - package: test/package; runs against the BUILT package (dist/, the packed tarball, a temp
//            install), so `npm run build` must have run first. `npm test` and
//            `npm run test:package` do that.
export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          include: ['test/**/*.test.ts'],
          exclude: ['test/package/**', '**/node_modules/**'],
          environment: 'node',
        },
      },
      {
        test: {
          name: 'package',
          include: ['test/package/**/*.test.ts'],
          environment: 'node',
          globalSetup: ['test/package/global-setup.ts'],
          // These tests spawn node, tsc, and npm pack/install; they are slow by nature.
          testTimeout: 180_000,
          hookTimeout: 180_000,
          // Each file works in its own temp dirs; running them in parallel is safe.
          fileParallelism: true,
        },
      },
    ],
  },
});
