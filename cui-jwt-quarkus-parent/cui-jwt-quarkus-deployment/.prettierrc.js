/**
 * Prettier configuration for CUI JWT DevUI components
 * 
 * This configuration ensures consistent code formatting across
 * JavaScript, JSON, and Markdown files.
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
      files: '*.json',
      options: {
        printWidth: 80,
        tabWidth: 2,
      },
    },
    {
      files: '*.md',
      options: {
        printWidth: 80,
        proseWrap: 'always',
        tabWidth: 2,
      },
    },
    {
      files: '*.js',
      options: {
        printWidth: 120,
        singleQuote: true,
        trailingComma: 'es5',
      },
    },
    {
      files: 'src/test/js/**/*.js',
      options: {
        printWidth: 100,
        singleQuote: true,
      },
    },
  ],
};