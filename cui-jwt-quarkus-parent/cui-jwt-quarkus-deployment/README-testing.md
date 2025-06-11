# JavaScript Testing for JWT DevUI Components

This document describes the JavaScript unit testing structure for the CUI JWT Quarkus DevUI components.

## Overview

The testing setup provides comprehensive unit tests for all JavaScript DevUI components using Jest and modern testing practices. The structure is inspired by the NiFi extensions testing framework and adapted for Quarkus DevUI components.

## Test Structure

```
src/test/js/
├── setup/              # Jest configuration and setup files
│   ├── jest.setup.js   # Global test environment setup
│   └── jest.setup-dom.js # DOM-specific setup and custom matchers
├── mocks/              # Mock implementations for external dependencies
│   ├── lit.js          # Mock Lit library implementation
│   ├── devui.js        # Mock Quarkus DevUI functionality
│   └── lit-directives.js # Mock Lit directives (unsafeHTML, etc.)
├── components/         # Component-specific test files
│   ├── qwc-jwt-validation-status.test.js
│   ├── qwc-jwks-endpoints.test.js
│   ├── qwc-jwt-debugger.test.js
│   └── qwc-jwt-config.test.js
└── utils/              # Test utility functions (if needed)
```

## Testing Framework

### Core Technologies

- **Jest**: Test runner and assertion library
- **@testing-library/jest-dom**: Enhanced DOM matchers
- **jsdom**: Browser environment simulation for web components
- **Lit**: Web component framework (mocked for testing)

### Key Features

- **Comprehensive Mocking**: All external dependencies are properly mocked
- **Custom Matchers**: Enhanced assertions for web component testing
- **Coverage Reporting**: 80% threshold with HTML and LCOV reports
- **Build-time Testing**: Tests simulate DevUI build-time behavior
- **CI/CD Ready**: Optimized scripts for continuous integration

## Running Tests

### Available Commands

```bash
# Run tests once
npm test

# Run tests in watch mode (for development)
npm run test:watch

# Generate coverage report
npm run test:coverage

# Run tests optimized for CI/CD
npm run test:ci

# Lint JavaScript code
npm run lint

# Auto-fix linting issues
npm run lint:fix
```

### Installation

First, install the dependencies:

```bash
cd cui-jwt-quarkus-deployment
npm install
```

## Test Patterns

### Component Testing Pattern

Each component test follows this structure:

```javascript
describe('ComponentName', () => {
  let component;
  let container;

  beforeEach(async () => {
    // Reset mocks and setup component
    resetDevUIMocks();
    container = document.createElement('div');
    document.body.appendChild(container);
    component = new ComponentClass();
    container.appendChild(component);
    await waitForComponentUpdate(component);
  });

  afterEach(() => {
    // Cleanup
    // Remove components and clear intervals
  });

  describe('Component Initialization', () => {
    // Test component creation and properties
  });

  describe('Loading State', () => {
    // Test loading behavior
  });

  describe('Error Handling', () => {
    // Test error scenarios
  });

  // Additional test suites for specific functionality
});
```

### Custom Matchers

The testing setup includes custom Jest matchers for web component testing:

```javascript
// Check if element is defined as custom element
expect('qwc-jwt-validation-status').toBeDefinedAsCustomElement();

// Check if component has rendered specific content
expect(component).toHaveRenderedContent('Expected text');

// Check if component has CSS class in shadow DOM
expect(component).toHaveShadowClass('expected-class');
```

### Mock Scenarios

The DevUI mock provides predefined scenarios for different testing conditions:

```javascript
// Runtime environment with active JWT validation
mockScenarios.runtimeActive();

// Runtime environment with issues
mockScenarios.runtimeWithIssues();

// Network error scenario
mockScenarios.networkError();
```

## Component Test Coverage

### QwcJwtValidationStatus
- Component initialization and properties
- Loading states and error handling
- Build-time vs runtime status display
- Auto-refresh functionality
- Security events display
- Status indicator rendering

### QwcJwksEndpoints
- JWKS endpoint status monitoring
- Issuer configuration display
- Loader status indicators
- Error handling and retry functionality
- Status classification (NO_ISSUERS, CONFIGURED)

### QwcJwtDebugger
- JWT token input handling
- Token validation functionality
- Clipboard operations
- Validation result display
- Error states and user feedback
- Button state management

### QwcJwtConfig
- Configuration loading and display
- Parser configuration section
- Health check configuration
- Issuer configuration grid
- Build-time vs runtime configuration
- Refresh functionality

## Mock Implementation Details

### Lit Library Mock

Provides essential Lit functionality for testing:
- `html` template literal function
- `css` template literal function
- `LitElement` base class with lifecycle methods
- Property system simulation
- Shadow DOM rendering simulation

### DevUI Mock

Simulates Quarkus DevUI functionality:
- JSON-RPC service calls with realistic responses
- Notification system
- Theme and router utilities
- Storage utilities
- WebSocket functionality (mocked)

### Build-time Behavior

Tests simulate the build-time nature of DevUI components:
- Services return build-time appropriate responses
- No actual JWT validation occurs
- Configuration shows build-time status
- Error messages indicate build-time limitations

## Coverage Requirements

The test suite maintains high coverage standards:

- **Branches**: 80% minimum
- **Functions**: 80% minimum
- **Lines**: 80% minimum
- **Statements**: 80% minimum

Coverage reports are generated in:
- `coverage/html/index.html` - HTML report
- `coverage/lcov.info` - LCOV format for CI/CD

## Best Practices

### Test Organization
- Group related tests using `describe` blocks
- Use descriptive test names that explain the expected behavior
- Follow Arrange-Act-Assert pattern in test methods

### Component Testing
- Always wait for component updates using `waitForComponentUpdate()`
- Clean up components and intervals in `afterEach()`
- Test both positive and negative scenarios

### Mock Management
- Reset mocks before each test using `resetDevUIMocks()`
- Use predefined mock scenarios when appropriate
- Verify mock function calls with appropriate matchers

### Error Testing
- Test network errors and service failures
- Verify error messages and user feedback
- Ensure graceful degradation

## Integration with Maven Build

The JavaScript tests can be integrated with the Maven build process by adding the `frontend-maven-plugin` to run npm commands during the build lifecycle.

## Troubleshooting

### Common Issues

1. **Component not updating**: Ensure `waitForComponentUpdate()` is called after state changes
2. **Mock not working**: Verify mocks are reset in `beforeEach()`
3. **Custom elements**: Check that custom element names are unique per test
4. **Memory leaks**: Ensure proper cleanup in `afterEach()`

### Debug Tips

- Use `console.log()` in tests (will be mocked by default)
- Check shadow DOM content using browser dev tools
- Verify mock function calls with Jest's `.toHaveBeenCalled()` matchers
- Use Jest's `--verbose` flag for detailed test output

## Future Enhancements

Potential improvements to the testing setup:

1. **Visual Regression Testing**: Add screenshot testing for UI components
2. **Integration Tests**: Test component interactions and data flow
3. **Performance Testing**: Measure component rendering performance
4. **Accessibility Testing**: Verify ARIA attributes and keyboard navigation
5. **E2E Testing**: Full user workflow testing with tools like Playwright

This testing framework provides a solid foundation for maintaining high-quality JavaScript components in the JWT DevUI extension.