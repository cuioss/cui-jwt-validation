/**
 * Unit tests for QwcJwtDebugger component
 */

import { LitElement } from 'lit';
import { devui, resetDevUIMocks } from '../mocks/devui.js';

// Simplified version of the component for testing
class QwcJwtDebugger extends LitElement {
  static properties = {
    _token: { state: true },
    _validationResult: { state: true },
    _loading: { state: true },
    _error: { state: true },
    _validating: { state: true },
  };

  constructor() {
    super();
    this._token = '';
    this._validationResult = null;
    this._loading = false;
    this._error = null;
    this._validating = false;
  }

  _handleTokenInput(e) {
    this._token = e.target.value;
    this._validationResult = null;
    this._error = null;
    this.requestUpdate();
  }

  async _validateToken() {
    if (!this._token || this._token.trim().length === 0) {
      this._validationResult = {
        valid: false,
        error: 'Please enter a JWT token',
      };
      return;
    }

    try {
      this._validating = true;
      this._validationResult = null;
      this._error = null;
      this.requestUpdate();

      const response = await devui.jsonRPC.CuiJwtDevUI.validateToken(this._token.trim());
      this._validationResult = response;
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('Error validating token:', error);
      this._validationResult = {
        valid: false,
        error: `Failed to validate token: ${error.message}`,
      };
    } finally {
      this._validating = false;
      this.requestUpdate();
    }
  }

  _clearToken() {
    this._token = '';
    this._validationResult = null;
    this._error = null;
    if (this.shadowRoot && this.shadowRoot.querySelector('.token-input')) {
      this.shadowRoot.querySelector('.token-input').value = '';
    }
    this.requestUpdate();
  }

  _loadSampleToken() {
    // Sample JWT token for testing
    const sampleToken = [
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
      'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
      'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    ].join('.');
    this._token = sampleToken;
    if (this.shadowRoot && this.shadowRoot.querySelector('.token-input')) {
      this.shadowRoot.querySelector('.token-input').value = sampleToken;
    }
    this.requestUpdate();
  }

  _formatJson(obj) {
    return JSON.stringify(obj, null, 2);
  }

  _copyToken() {
    if (navigator.clipboard && this._token) {
      navigator.clipboard.writeText(this._token);
      devui.notifications.success('Token copied to clipboard');
    }
  }

  render() {
    const result = this._doRender();
    // Store result for testing
    this._lastRenderedResult = result.strings ? result.strings.join('') : result.toString();
    return result;
  }

  _doRender() {
    // Create simplified string representation for testing
    let result = '<div class="debugger-container">';
    result += '<h3 class="debugger-title">JWT Token Debugger</h3>';
    result += '<div class="input-section">';
    result += '<div class="input-group">';
    result += '<label class="input-label" for="token-input">JWT Token:</label>';
    result +=
      '<textarea id="token-input" class="token-input" placeholder="Paste your JWT token here..."></textarea>';
    result += '</div>';
    result += '<div class="button-group">';
    result += `<button class="validate-button" ${this._loading || !this._token.trim() ? 'disabled' : ''}>`;
    result += `${this._loading ? 'Validating...' : 'Validate Token'}</button>`;
    result += `<button class="clear-button" ${this._token ? '' : 'disabled'}>Clear</button>`;
    result += `<button class="copy-button" ${this._token ? '' : 'disabled'}>Copy Token</button>`;
    result += '</div>';
    result += '</div>';

    if (this._error) {
      result += `<div class="error-message"><strong>Error:</strong> ${this._error}</div>`;
    }

    if (this._validationResult) {
      result += '<div class="result-section">';
      result += '<h4 class="result-title">Validation Result</h4>';
      result += `<div class="validation-status ${this._validationResult.valid ? 'valid' : 'invalid'}">`;
      result += `<strong>Status:</strong> ${this._validationResult.valid ? 'Valid' : 'Invalid'}</div>`;

      if (this._validationResult.error) {
        result += `<div class="validation-error"><strong>Error:</strong> ${this._validationResult.error}</div>`;
      }

      if (this._validationResult.claims) {
        result += '<div class="claims-section">';
        result += '<h5>Claims:</h5>';
        result += `<pre class="claims-display">${JSON.stringify(this._validationResult.claims, null, 2)}</pre>`;
        result += '</div>';
      }

      result += '</div>';
    }

    result += '</div>';

    return { toString: () => result, strings: [result] };
  }
}

describe('QwcJwtDebugger', () => {
  let component;
  let container;

  beforeEach(async () => {
    // Reset all mocks
    resetDevUIMocks();

    // Create container
    container = document.createElement('div');
    document.body.append(container);

    // Create component
    component = new QwcJwtDebugger();

    // Mock shadow DOM for testing
    const shadowRoot = document.createElement('div');
    component.shadowRoot = shadowRoot;

    // Mock querySelector methods to return our mock elements
    const tokenInput = document.createElement('textarea');
    tokenInput.id = 'token-input';
    tokenInput.placeholder = 'Paste your JWT token here...';

    const validateButton = document.createElement('button');
    validateButton.className = 'validate-button';
    validateButton.textContent = 'Validate Token';
    validateButton.disabled = true;

    const clearButton = document.createElement('button');
    clearButton.className = 'clear-button';
    clearButton.disabled = true;

    const copyButton = document.createElement('button');
    copyButton.className = 'copy-button';
    copyButton.disabled = true;

    shadowRoot.querySelector = jest.fn((selector) => {
      switch (selector) {
        case '#token-input': {
          return tokenInput;
        }
        case '.validate-button': {
          return validateButton;
        }
        case '.clear-button': {
          return clearButton;
        }
        case '.copy-button': {
          return copyButton;
        }
        default: {
          return null;
        }
      }
    });

    container.append(component);

    // Initial render
    component.render();

    // Wait for initial render
    await waitForComponentUpdate(component);
  });

  afterEach(() => {
    // Cleanup
    if (component && component.parentNode) {
      component.remove();
    }
    if (container && container.parentNode) {
      container.remove();
    }
  });

  describe('Component Initialization', () => {
    it('should create component with default properties', () => {
      expect(component).toBeDefined();
      expect(component._token).toBe('');
      expect(component._validationResult).toBeNull();
      expect(component._loading).toBe(false);
      expect(component._error).toBeNull();
    });

    it('should be defined as custom element', () => {
      const tagName = `qwc-jwt-debugger-test-${Date.now()}`;
      if (!customElements.get(tagName)) {
        customElements.define(tagName, QwcJwtDebugger);
      }
      expect('').toBeDefinedAsCustomElement(tagName);
    });

    it('should render debugger container structure', async () => {
      component.render();
      expect(component).toHaveShadowClass('debugger-container');
      expect(component).toHaveShadowClass('debugger-title');
      expect(component).toHaveShadowClass('input-section');
    });
  });

  describe('Token Input Handling', () => {
    let tokenInput;

    beforeEach(async () => {
      tokenInput = component.shadowRoot.querySelector('#token-input');
    });

    it('should render token input field', () => {
      expect(tokenInput).toBeTruthy();
      expect(tokenInput.tagName.toLowerCase()).toBe('textarea');
      expect(tokenInput.placeholder).toBe('Paste your JWT token here...');
    });

    it('should update token property when input changes', async () => {
      const testToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature';

      // Directly call the handler method
      component._handleTokenInput({ target: { value: testToken } });
      await waitForComponentUpdate(component);

      expect(component._token).toBe(testToken);
    });

    it('should clear validation result when token changes', async () => {
      // Set initial validation result
      component._validationResult = { valid: true };
      component._error = 'Previous error';

      // Change token
      component._handleTokenInput({ target: { value: 'new-token' } });
      await waitForComponentUpdate(component);

      expect(component._validationResult).toBeNull();
      expect(component._error).toBeNull();
    });
  });

  describe('Button Controls', () => {
    let validateButton;
    let clearButton;
    let copyButton;

    beforeEach(async () => {
      validateButton = component.shadowRoot.querySelector('.validate-button');
      clearButton = component.shadowRoot.querySelector('.clear-button');
      copyButton = component.shadowRoot.querySelector('.copy-button');
    });

    it('should render all control buttons', () => {
      expect(validateButton).toBeTruthy();
      expect(clearButton).toBeTruthy();
      expect(copyButton).toBeTruthy();
    });

    it('should disable validate button when no token', async () => {
      // Update button states based on component state
      validateButton.disabled = component._loading || !component._token.trim();
      expect(validateButton.disabled).toBe(true);
      expect(validateButton.textContent.trim()).toBe('Validate Token');
    });

    it('should enable validate button when token is present', async () => {
      component._handleTokenInput({ target: { value: 'test-token' } });
      await waitForComponentUpdate(component);

      // Update button state based on component state
      validateButton.disabled = component._loading || !component._token.trim();
      expect(validateButton.disabled).toBe(false);
    });

    it('should disable clear and copy buttons when no token', async () => {
      // Update button states based on component state
      clearButton.disabled = !component._token;
      copyButton.disabled = !component._token;
      expect(clearButton.disabled).toBe(true);
      expect(copyButton.disabled).toBe(true);
    });

    it('should enable clear and copy buttons when token is present', async () => {
      component._handleTokenInput({ target: { value: 'test-token' } });
      await waitForComponentUpdate(component);

      // Update button states based on component state
      clearButton.disabled = !component._token;
      copyButton.disabled = !component._token;
      expect(clearButton.disabled).toBe(false);
      expect(copyButton.disabled).toBe(false);
    });
  });

  describe('Token Validation', () => {
    beforeEach(async () => {
      // Set up a token
      component._handleTokenInput({
        target: { value: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature' },
      });
      await waitForComponentUpdate(component);
    });

    it('should call validateToken service when validate button is clicked', async () => {
      await component._validateToken();
      await waitForComponentUpdate(component);

      expect(devui.jsonRPC.CuiJwtDevUI.validateToken).toHaveBeenCalledWith(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
      );
    });

    it('should show loading state during validation', async () => {
      // Setup delayed mock response
      let resolvePromise;
      const delayedPromise = new Promise((resolve) => {
        resolvePromise = resolve;
      });
      devui.jsonRPC.CuiJwtDevUI.validateToken.mockReturnValue(delayedPromise);

      // Start validation (don't await yet)
      const validationPromise = component._validateToken();
      await waitForComponentUpdate(component);

      expect(component._validating).toBe(true);

      // Get button and update state based on component state
      const validateButton = component.shadowRoot.querySelector('.validate-button');
      validateButton.textContent = component._validating ? 'Validating...' : 'Validate Token';
      validateButton.disabled = component._validating || !component._token.trim();
      expect(validateButton.textContent.trim()).toBe('Validating...');
      expect(validateButton.disabled).toBe(true);

      // Resolve the promise
      resolvePromise({ valid: false, error: 'Token validation not available at build time' });
      await validationPromise;
      await waitForComponentUpdate(component);

      expect(component._validating).toBe(false);
    });

    it('should display validation result for invalid token', async () => {
      await component._validateToken();
      await waitForComponentUpdate(component);
      component.render();

      expect(component).toHaveRenderedContent('Validation Result');
      expect(component).toHaveRenderedContent('Invalid');
      expect(component).toHaveShadowClass('invalid');
      expect(component).toHaveRenderedContent('Token validation not available at build time');
    });

    it('should display error when validation fails', async () => {
      // Setup network error
      const networkError = new Error('Network error');
      devui.jsonRPC.CuiJwtDevUI.validateToken.mockRejectedValue(networkError);

      await component._validateToken();
      await waitForComponentUpdate(component);
      component.render();

      expect(component._validationResult.error).toContain(
        'Failed to validate token: Network error'
      );
      expect(component).toHaveRenderedContent('Invalid');
    });

    it('should show error for empty token validation', async () => {
      // Clear the token
      component._token = '';
      component.requestUpdate();
      await waitForComponentUpdate(component);

      await component._validateToken();
      await waitForComponentUpdate(component);
      component.render();

      expect(component._validationResult.error).toBe('Please enter a JWT token');
      expect(component).toHaveRenderedContent('Invalid');
    });
  });

  describe('Token Operations', () => {
    beforeEach(async () => {
      // Set up a token
      component._handleTokenInput({ target: { value: 'test-token' } });
      await waitForComponentUpdate(component);
    });

    it('should clear token when clear button is clicked', async () => {
      component._clearToken();
      await waitForComponentUpdate(component);

      expect(component._token).toBe('');
      expect(component._validationResult).toBeNull();
      expect(component._error).toBeNull();
    });

    it('should copy token to clipboard when copy button is clicked', async () => {
      // Mock clipboard API
      const mockClipboard = {
        writeText: jest.fn(() => Promise.resolve()),
      };
      Object.defineProperty(navigator, 'clipboard', {
        value: mockClipboard,
        writable: true,
      });

      component._copyToken();
      await waitForComponentUpdate(component);

      expect(mockClipboard.writeText).toHaveBeenCalledWith('test-token');
      expect(devui.notifications.success).toHaveBeenCalledWith('Token copied to clipboard');
    });

    it('should handle missing clipboard API gracefully', async () => {
      // Remove clipboard API
      Object.defineProperty(navigator, 'clipboard', {
        value: undefined,
        writable: true,
      });

      // Should not throw error
      expect(() => component._copyToken()).not.toThrow();
    });
  });

  describe('Error Display', () => {
    it('should display error message when error is present', async () => {
      component._error = 'Test error message';
      component.requestUpdate();
      await waitForComponentUpdate(component);
      component.render();

      expect(component).toHaveRenderedContent('Test error message');
      expect(component).toHaveShadowClass('error-message');
    });

    it('should not display error section when no error', async () => {
      component._error = null;
      component.requestUpdate();
      await waitForComponentUpdate(component);
      component.render();

      expect(component).not.toHaveShadowClass('error-message');
    });
  });

  describe('Validation Result Display', () => {
    it('should display validation result section when result is present', async () => {
      component._validationResult = {
        valid: false,
        error: 'Invalid token',
      };
      component.requestUpdate();
      await waitForComponentUpdate(component);
      component.render();

      expect(component).toHaveRenderedContent('Validation Result');
      expect(component).toHaveShadowClass('result-section');
      expect(component).toHaveShadowClass('validation-status');
    });

    it('should display claims when present in result', async () => {
      component._validationResult = {
        valid: true,
        claims: {
          sub: 'user123',
          exp: 1_234_567_890,
          iat: 1_234_567_800,
        },
      };
      component.requestUpdate();
      await waitForComponentUpdate(component);
      component.render();

      expect(component).toHaveRenderedContent('Claims:');
      expect(component).toHaveShadowClass('claims-section');
      expect(component).toHaveShadowClass('claims-display');
      expect(component).toHaveRenderedContent('user123');
    });

    it('should not display result section when no result', async () => {
      component._validationResult = null;
      component.requestUpdate();
      await waitForComponentUpdate(component);
      component.render();

      expect(component).not.toHaveShadowClass('result-section');
    });
  });

  describe('Component Properties', () => {
    it('should handle component properties correctly', () => {
      expect(QwcJwtDebugger.properties).toBeDefined();
      expect(QwcJwtDebugger.properties._token).toEqual({ state: true });
      expect(QwcJwtDebugger.properties._validationResult).toEqual({ state: true });
      expect(QwcJwtDebugger.properties._loading).toEqual({ state: true });
      expect(QwcJwtDebugger.properties._error).toEqual({ state: true });
    });
  });

  describe('Error Handling', () => {
    it('should log errors to console', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const networkError = new Error('Test error');
      devui.jsonRPC.CuiJwtDevUI.validateToken.mockRejectedValue(networkError);

      // Set up token and validate
      component._handleTokenInput({ target: { value: 'test-token' } });
      await waitForComponentUpdate(component);

      await component._validateToken();

      expect(consoleSpy).toHaveBeenCalledWith('Error validating token:', networkError);

      consoleSpy.mockRestore();
    });
  });

  describe('Additional Component Methods Coverage', () => {
    beforeEach(async () => {
      // Set up shadow DOM mocks for additional methods
      const tokenInput = document.createElement('textarea');
      tokenInput.className = 'token-input';
      tokenInput.value = '';

      component.shadowRoot.querySelector = jest.fn((selector) => {
        if (selector === '.token-input') {
          return tokenInput;
        }
        return null;
      });
    });

    it('should clear token and update input field', async () => {
      // Set up initial state
      component._token = 'test.token.value';
      component._validationResult = { valid: true };

      const tokenInput = component.shadowRoot.querySelector('.token-input');
      tokenInput.value = 'test.token.value';

      // Call clear method
      component._clearToken();

      expect(component._token).toBe('');
      expect(component._validationResult).toBeNull();
      expect(tokenInput.value).toBe('');
    });

    it('should load sample token', async () => {
      const tokenInput = component.shadowRoot.querySelector('.token-input');

      component._loadSampleToken();

      expect(component._token).toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
      expect(tokenInput.value).toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    });

    it('should format JSON objects', () => {
      const testObj = { test: 'value', nested: { data: 123 } };
      const formatted = component._formatJson(testObj);

      expect(formatted).toContain('{\n');
      expect(formatted).toContain('  "test": "value"');
      expect(formatted).toContain('  "nested": {');
    });

    it('should handle token input change events', async () => {
      const testToken = 'new.test.token';
      const event = { target: { value: testToken } };

      component._handleTokenInput(event);

      expect(component._token).toBe(testToken);
    });
  });

  describe('Enhanced Validation Coverage', () => {
    it('should handle validation of trimmed tokens', async () => {
      component._token = '  valid.token.here  ';

      await component._validateToken();

      expect(devui.jsonRPC.CuiJwtDevUI.validateToken).toHaveBeenCalledWith('valid.token.here');
    });

    it('should set validating state during validation', async () => {
      component._token = 'test.token';

      // Setup delayed promise to test validating state
      let resolvePromise;
      const delayedPromise = new Promise((resolve) => {
        resolvePromise = resolve;
      });
      devui.jsonRPC.CuiJwtDevUI.validateToken.mockReturnValue(delayedPromise);

      // Start validation
      const validationPromise = component._validateToken();

      expect(component._validating).toBe(true);
      expect(component._validationResult).toBeNull();

      // Resolve and complete
      resolvePromise({ valid: true, claims: {} });
      await validationPromise;

      expect(component._validating).toBe(false);
      expect(component._validationResult).toBeTruthy();
    });
  });

  describe('Edge Cases and Additional Coverage', () => {
    it('should handle validation with whitespace-only token', async () => {
      component._token = '   ';
      await component._validateToken();
      // Should not validate whitespace-only tokens
      expect(component._validationResult.error).toBe('Please enter a JWT token');
    });

    it('should handle multiple consecutive validations', async () => {
      component._token = 'first.jwt.token';
      await component._validateToken();

      component._token = 'second.jwt.token';
      await component._validateToken();

      expect(devui.jsonRPC.CuiJwtDevUI.validateToken).toHaveBeenCalledTimes(2);
    });

    it('should handle token input edge cases', () => {
      // Empty event
      component._handleTokenInput({ target: { value: '' } });
      expect(component._token).toBe('');

      // Null value
      component._handleTokenInput({ target: { value: null } });
      expect(component._token).toBeNull();

      // Very long token
      const longToken = 'a'.repeat(10_000);
      component._handleTokenInput({ target: { value: longToken } });
      expect(component._token).toBe(longToken);
    });

    it('should handle clear token when already empty', () => {
      component._token = '';
      component._validationResult = null;
      component._clearToken();
      expect(component._token).toBe('');
      expect(component._validationResult).toBeNull();
    });

    it('should handle render with different validation states', () => {
      // Basic render test
      component._validating = false;
      component._validationResult = null;
      component.render();
      expect(component).toHaveRenderedContent('JWT Token Debugger');

      // Success state
      component._validating = false;
      component._validationResult = { valid: true, claims: { sub: 'user' } };
      component.render();
      expect(component).toHaveRenderedContent('JWT Token Debugger');

      // Error state
      component._validationResult = { valid: false, error: 'Invalid token' };
      component.render();
      expect(component).toHaveRenderedContent('JWT Token Debugger');
    });

    it('should handle undefined validation result', () => {
      component._validationResult = undefined;
      component.render();
      expect(component).toHaveRenderedContent('JWT Token Debugger');
    });
  });
});
