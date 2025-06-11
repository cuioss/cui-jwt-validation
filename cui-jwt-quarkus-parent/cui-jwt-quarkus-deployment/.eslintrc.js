/**
 * ESLint configuration for CUI JWT DevUI components
 * 
 * This configuration provides comprehensive linting for JavaScript files
 * including Lit components, Jest tests, and general JavaScript code.
 */

module.exports = {
  extends: [
    'airbnb-base',
    'plugin:jest/recommended',
    'plugin:lit/recommended',
    'plugin:wc/recommended',
    'plugin:jsdoc/recommended',
    'plugin:unicorn/recommended',
    'plugin:prettier/recommended',
  ],
  
  env: {
    browser: true,
    es6: true,
    jest: true,
    node: true,
  },
  
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
  
  plugins: ['lit', 'wc', 'jsdoc', 'unicorn', 'prettier'],
  
  rules: {
    // Import/export rules
    'import/no-unresolved': 'off',
    'import/extensions': 'off',
    'import/prefer-default-export': 'off',
    'import/no-extraneous-dependencies': ['error', { devDependencies: true }],
    
    // General JavaScript rules
    'class-methods-use-this': 'off',
    'no-console': 'warn',
    'no-debugger': 'error',
    'no-unused-vars': 'error',
    'no-underscore-dangle': 'off', // Allow underscore for private properties in Lit components
    'no-param-reassign': 'off', // Allow for test setups
    'no-promise-executor-return': 'off', // Allow for test utilities
    'prefer-const': 'error',
    'no-var': 'error',
    'arrow-spacing': 'error',
    'object-shorthand': 'error',
    'prefer-template': 'error',
    'template-curly-spacing': 'error',
    
    // Code style rules (disabled in favor of Prettier)
    quotes: 'off', // Handled by Prettier
    semi: 'off', // Handled by Prettier
    indent: 'off', // Handled by Prettier
    'max-len': ['warn', { code: 120, ignoreComments: true, ignoreUrls: true }],
    'comma-dangle': 'off', // Handled by Prettier
    'object-curly-spacing': 'off', // Handled by Prettier
    'array-bracket-spacing': 'off', // Handled by Prettier
    
    // Function rules
    'function-paren-newline': 'off',
    'arrow-parens': ['error', 'always'],
    'prefer-arrow-callback': 'error',
    
    // Lit-specific rules
    'lit/no-legacy-template-syntax': 'error',
    'lit/no-invalid-html': 'error',
    'lit/no-value-attribute': 'error',
    'lit/attribute-value-entities': 'error',
    'lit/binding-positions': 'error',
    'lit/no-property-change-update': 'error',
    'lit/lifecycle-super': 'error',
    'lit/no-native-attributes': 'warn',
    
    // Web Components rules
    'wc/no-constructor-attributes': 'error',
    'wc/no-invalid-element-name': 'error',
    'wc/no-self-class': 'error',
    'wc/require-listener-teardown': 'error',
    'wc/guard-super-call': 'off', // Allow for Lit components
    
    // JSDoc rules
    'jsdoc/require-description': 'warn',
    'jsdoc/require-param-description': 'warn',
    'jsdoc/require-returns-description': 'warn',
    'jsdoc/check-alignment': 'error',
    'jsdoc/check-indentation': 'error',
    'jsdoc/check-tag-names': 'error',
    'jsdoc/check-types': 'error',
    'jsdoc/require-hyphen-before-param-description': 'error',
    
    // Unicorn rules (additional best practices)
    'unicorn/filename-case': 'off', // Allow kebab-case for web components
    'unicorn/prevent-abbreviations': 'off',
    'unicorn/no-null': 'off',
    'unicorn/prefer-dom-node-text-content': 'off',
    'unicorn/prefer-query-selector': 'error',
    'unicorn/prefer-modern-dom-apis': 'error',
    'unicorn/no-array-for-each': 'off', // Allow forEach for readability
    'unicorn/consistent-function-scoping': 'warn',
    
    // Prettier integration
    'prettier/prettier': 'error',
  },
  
  overrides: [
    {
      // Rules specific to test files
      files: ['src/test/js/**/*.js'],
      rules: {
        'jsdoc/require-jsdoc': 'off',
        'jsdoc/require-description': 'off',
        'jsdoc/require-param-description': 'off',
        'jsdoc/require-returns-description': 'off',
        'jsdoc/require-param-type': 'off',
        'jsdoc/require-returns': 'off',
        'unicorn/consistent-function-scoping': 'off',
        'lit/no-legacy-template-syntax': 'off',
        'max-len': 'off',
        'no-unused-expressions': 'off',
        'no-unused-vars': 'warn',
        'no-undef': 'off', // Jest globals handled by environment
        'jest/expect-expect': [
          'error',
          {
            assertFunctionNames: ['expect', 'assert*', 'should*'],
          },
        ],
        'jest/no-disabled-tests': 'warn',
        'jest/no-focused-tests': 'error',
        'jest/prefer-to-have-length': 'error',
        'jest/valid-expect': 'error',
      },
    },
    {
      // Rules specific to DevUI components
      files: ['src/main/resources/dev-ui/**/*.js'],
      rules: {
        'jsdoc/require-jsdoc': 'error',
        'jsdoc/require-description': 'error',
        'max-len': ['warn', { code: 120 }],
        'complexity': ['warn', { max: 15 }],
        'max-depth': ['error', { max: 4 }],
        'max-lines-per-function': ['warn', { max: 100 }],
      },
    },
    {
      // Rules specific to mock files
      files: ['src/test/js/mocks/**/*.js'],
      rules: {
        'jsdoc/require-jsdoc': 'off',
        'unicorn/consistent-function-scoping': 'off',
        'unicorn/no-array-reduce': 'off',
        'unicorn/prefer-logical-operator-over-ternary': 'off',
        'no-restricted-syntax': 'off',
        'no-plusplus': 'off',
        'class-methods-use-this': 'off',
        'no-unused-vars': 'off',
        'max-lines-per-function': 'off',
      },
    },
  ],
};