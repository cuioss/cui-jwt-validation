/**
 * Stylelint configuration for CSS-in-JS in Lit components
 * 
 * This configuration ensures consistent CSS styling within
 * Lit component template literals and CSS-in-JS constructs.
 */

module.exports = {
  extends: ['stylelint-config-standard'],
  
  plugins: ['stylelint-order'],
  
  // Custom syntax for CSS-in-JS
  customSyntax: 'postcss-lit',
  
  rules: {
    // Indentation and formatting
    // Note: indentation, string-quotes, color-hex-case are deprecated in newer versions
    'color-hex-length': 'short',
    
    // Property ordering
    'order/properties-alphabetical-order': true,
    
    // CSS Custom Properties (CSS Variables) - relaxed for Lumo theme
    'custom-property-pattern': null, // Allow Lumo theme variables like --lumo-primary-color
    'custom-property-empty-line-before': 'never',
    
    // Class naming patterns for Lit components
    'selector-class-pattern': '^[a-z][a-z0-9]*(-[a-z0-9]+)*$',
    'selector-id-pattern': '^[a-z][a-z0-9]*(-[a-z0-9]+)*$',
    
    // Box model and layout
    'declaration-property-unit-allowed-list': {
      'font-size': ['rem', 'em', 'px'],
      'line-height': ['rem', 'em', 'px', ''],
      'margin': ['rem', 'em', 'px', '%'],
      'padding': ['rem', 'em', 'px', '%'],
      'width': ['rem', 'em', 'px', '%', 'vw', 'vh'],
      'height': ['rem', 'em', 'px', '%', 'vw', 'vh'],
    },
    
    // Color and theming
    'color-named': 'never',
    'color-no-hex': null,
    
    // CSS Grid and Flexbox
    'property-no-vendor-prefix': [
      true,
      {
        ignoreProperties: ['appearance', 'mask'],
      },
    ],
    
    // Lit-specific CSS patterns
    'selector-pseudo-class-no-unknown': [
      true,
      {
        ignorePseudoClasses: ['host', 'host-context'],
      },
    ],
    
    // Performance and best practices
    'no-duplicate-selectors': true,
    'no-descending-specificity': null, // Disabled for CSS-in-JS components
    'declaration-block-no-redundant-longhand-properties': true,
    
    // CSS Custom Properties for Vaadin/Lumo theming
    'property-no-unknown': [
      true,
      {
        ignoreProperties: [
          // Vaadin/Lumo theme properties
          '/^--lumo-.+/',
          // Custom component properties
          '/^--component-.+/',
        ],
      },
    ],
    
    // Disable rules that conflict with CSS-in-JS
    'no-empty-source': null,
    'value-keyword-case': null, // Allows CSS-in-JS template literals
  },
  
  overrides: [
    {
      files: ['src/main/resources/dev-ui/**/*.js'],
      rules: {
        // Stricter rules for production components
        'max-nesting-depth': 3,
        'selector-max-compound-selectors': 4,
        'selector-max-specificity': '0,4,0',
      },
    },
    {
      files: ['src/test/js/**/*.js'],
      rules: {
        // Relaxed rules for test files
        'selector-class-pattern': null,
        'custom-property-pattern': null,
        'max-nesting-depth': null,
      },
    },
  ],
  
  // Ignore patterns
  ignoreFiles: [
    'node_modules/**/*',
    'coverage/**/*',
    'dist/**/*',
    'build/**/*',
    '**/*.min.js',
  ],
};