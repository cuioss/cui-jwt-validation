/**
 * Prettier configuration for CUI JWT DevUI components
 * 
 * This configuration ensures consistent code formatting across
 * JavaScript (including CSS-in-JS), JSON, and Markdown files.
 * Follows CUI CSS and JavaScript formatting standards.
 */

module.exports = {
  // Basic formatting options
  printWidth: 120,
  tabWidth: 2,
  useTabs: false,
  semi: true,
  singleQuote: true,
  quoteProps: 'as-needed',
  
  // Object and array formatting
  trailingComma: 'es5',
  bracketSpacing: true,
  bracketSameLine: false,
  
  // Arrow function parentheses
  arrowParens: 'always',
  
  // Prose formatting
  proseWrap: 'preserve',
  
  // HTML formatting
  htmlWhitespaceSensitivity: 'css',
  
  // End of line
  endOfLine: 'lf',
  
  // Embedded language formatting
  embeddedLanguageFormatting: 'auto',
  
  // File-specific overrides
  overrides: [
    {
      files: ['*.js', '*.mjs'],
      options: {
        printWidth: 120,
        singleQuote: true,
        trailingComma: 'es5',
        // Enhanced JavaScript formatting
        arrowParens: 'always',
        bracketSpacing: true,
        bracketSameLine: false,
        // CSS-in-JS specific formatting
        htmlWhitespaceSensitivity: 'css',
        embeddedLanguageFormatting: 'auto',
      },
    },
    {
      files: 'src/main/resources/dev-ui/**/*.js',
      options: {
        printWidth: 120,
        singleQuote: true,
        trailingComma: 'es5',
        // Enhanced formatting for production components with CSS-in-JS
        bracketSameLine: false,
        singleAttributePerLine: false,
        // Modern JavaScript features
        arrowParens: 'always',
        bracketSpacing: true,
      },
    },
    {
      files: 'src/test/js/**/*.js',
      options: {
        printWidth: 100,
        singleQuote: true,
        trailingComma: 'es5',
        // Test-specific formatting
        arrowParens: 'avoid',
        bracketSpacing: true,
      },
    },
    {
      files: ['*.json', '*.jsonc'],
      options: {
        printWidth: 80,
        tabWidth: 2,
        singleQuote: false,
        trailingComma: 'none',
      },
    },
    {
      files: ['*.md', '*.mdx'],
      options: {
        printWidth: 80,
        proseWrap: 'always',
        singleQuote: false,
        trailingComma: 'none',
      },
    },
    {
      files: ['*.css', '*.scss'],
      options: {
        parser: 'css',
        printWidth: 80,
        singleQuote: false, // Use double quotes in CSS
        tabWidth: 2,
      },
    },
    {
      files: ['*.yml', '*.yaml'],
      options: {
        printWidth: 80,
        singleQuote: true,
        tabWidth: 2,
      },
    },
  ],
};