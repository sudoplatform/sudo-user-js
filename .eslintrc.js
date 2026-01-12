module.exports = {
  root: true,
  overrides: [
    {
      files: ['*.js'],
      extends: 'eslint:recommended',
      parserOptions: { ecmaVersion: 2018 },
      env: { node: true },
    },
    {
      files: ['src/**/*.ts'],
      parser: '@typescript-eslint/parser',
      parserOptions: {
        projectService: true,
      },
      excludedFiles: ['test/**/*.spec.ts'],
      plugins: ['@typescript-eslint', 'prettier', 'tree-shaking'],
      extends: ['plugin:@typescript-eslint/recommended', 'prettier', 'plugin:prettier/recommended'],
      rules: {
        "@typescript-eslint/no-floating-promises": "error",
        '@typescript-eslint/explicit-function-return-type': 'off',
        '@typescript-eslint/no-explicit-any': 'off',
        '@typescript-eslint/array-type': 'off',
        '@typescript-eslint/no-parameter-properties': 'off',
        '@typescript-eslint/no-use-before-define': 'off',
        'tree-shaking/no-side-effects-in-initialization': 2,
        quotes: [
          'error',
          'single',
          {
            avoidEscape: true,
          },
        ],
      },
    },
    {
      files: ['**/*.d.ts'],
      rules: {
        '@typescript-eslint/no-explicit-any': 'off',
      },
    },
    {
      files: [
        'test/**/*.spec.ts',
      ],
      parser: '@typescript-eslint/parser',
      parserOptions: {
        project: './tsconfig.test.json',
      },
      rules: {
        "@typescript-eslint/no-floating-promises": "error",
        '@typescript-eslint/no-explicit-any': 'off',
        '@typescript-eslint/no-non-null-assertion': 'off',
      },
    }
  ]
}