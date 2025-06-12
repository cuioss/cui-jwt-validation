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
    'plugin:security/recommended',
    'plugin:promise/recommended',
    'plugin:sonarjs/recommended',
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
  
  plugins: ['lit', 'wc', 'jsdoc', 'unicorn', 'security', 'promise', 'sonarjs', 'prettier'],
  
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
    
    // Security rules
    'security/detect-object-injection': 'warn',
    'security/detect-eval-with-expression': 'error',
    'security/detect-unsafe-regex': 'error',
    'security/detect-buffer-noassert': 'error',
    'security/detect-child-process': 'error',
    
    // Promise rules
    'promise/always-return': 'error',
    'promise/catch-or-return': 'error',
    'promise/no-return-wrap': 'error',
    'promise/param-names': 'error',
    'promise/no-nesting': 'warn',
    'promise/prefer-await-to-then': 'warn',
    'promise/prefer-await-to-callbacks': 'warn',
    
    // SonarJS rules - using recommended defaults
    
    // Modern JavaScript features
    'prefer-destructuring': ['error', { array: false, object: true }],
    'prefer-rest-params': 'error',
    'prefer-spread': 'error',
    'symbol-description': 'error',
    'no-useless-computed-key': 'error',
    'no-useless-rename': 'error',
    'no-useless-return': 'error',
    'no-void': 'error',
    'no-with': 'error',
    
    // ES6+ features
    'prefer-numeric-literals': 'error',
    'prefer-object-spread': 'error',
    'prefer-exponentiation-operator': 'error',
    'prefer-regex-literals': 'error',
    'prefer-promise-reject-errors': 'error',
    
    // Error handling
    'no-throw-literal': 'error',
    'no-return-await': 'error',
    'require-await': 'warn',
    'no-async-promise-executor': 'error',
    'no-await-in-loop': 'warn',
    'no-promise-executor-return': 'error',
    
    // Performance
    'no-loop-func': 'error',
    'no-extend-native': 'error',
    'no-iterator': 'error',
    'no-proto': 'error',
    'no-script-url': 'error',
    
    // Maintainability
    'complexity': ['warn', { max: 10 }],
    'max-statements': ['warn', { max: 20 }],
    'max-params': ['warn', { max: 5 }],
    'max-nested-callbacks': ['error', { max: 4 }],
    'no-magic-numbers': ['warn', { 
      ignore: [-1, 0, 1, 2, 100, 200, 404, 500, 1000, 30000],
      ignoreArrayIndexes: true,
      ignoreDefaultValues: true 
    }],
    
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
        // Relaxed SonarJS rules for test files
        'sonarjs/cognitive-complexity': 'off',
        'sonarjs/no-duplicate-string': 'off',
        'complexity': 'off',
        'max-statements': 'off',
        'max-params': 'off',
        'require-await': 'off',
        'no-magic-numbers': 'off',
        'security/detect-object-injection': 'off',
        'promise/prefer-await-to-then': 'off',
        'promise/always-return': 'off',
        'no-promise-executor-return': 'off',
        'arrow-parens': 'off', // Let Prettier handle this for test files
        // Jest-specific rules
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
        // Additional relaxed SonarJS rules for mock files
        'sonarjs/no-identical-functions': 'off',
        'sonarjs/cognitive-complexity': 'off',
        'security/detect-object-injection': 'off',
        'promise/prefer-await-to-then': 'off',
        'promise/always-return': 'off',
        'no-promise-executor-return': 'off',
        'complexity': 'off',
        'max-statements': 'off',
        'arrow-parens': 'off', // Let Prettier handle this for mock files
      },
    },
  ],
};