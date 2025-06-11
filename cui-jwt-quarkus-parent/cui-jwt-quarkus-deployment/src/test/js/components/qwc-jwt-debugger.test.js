/**
 * Unit tests for QwcJwtDebugger component
 */

import { html, LitElement } from 'lit';
import { devui, resetDevUIMocks } from '../mocks/devui.js';

// Simplified version of the component for testing
class QwcJwtDebugger extends LitElement {
  static properties = {
    _token: { state: true },
    _validationResult: { state: true },
    _loading: { state: true },
    _error: { state: true },
  };

  constructor() {
    super();
    this._token = '';
    this._validationResult = null;
    this._loading = false;
    this._error = null;
  }

  _handleTokenInput(e) {
    this._token = e.target.value;
    this._validationResult = null;
    this._error = null;
  }

  async _validateToken() {
    if (!this._token || this._token.trim() === '') {
      this._error = 'Please enter a JWT token to validate';
      return;
    }

    try {
      this._loading = true;
      this._error = null;

      const response = await devui.jsonRPC.CuiJwtDevUI.validateToken(this._token);
      this._validationResult = response;
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('Error validating token:', error);
      this._error = `Failed to validate token: ${error.message}`;
    } finally {
      this._loading = false;
    }
  }

  _clearToken() {
    this._token = '';
    this._validationResult = null;
    this._error = null;
  }

  _copyToken() {
    if (navigator.clipboard && this._token) {
      navigator.clipboard.writeText(this._token);
      devui.notifications.success('Token copied to clipboard');
    }
  }

  render() {
    return html`
      <div class="debugger-container">
        <h3 class="debugger-title">JWT Token Debugger</h3>

        <div class="input-section">
          <div class="input-group">
            <label class="input-label" for="token-input">JWT Token:</label>
            <textarea
              id="token-input"
              class="token-input"
              placeholder="Paste your JWT token here..."
              .value="${this._token}"
              @input="${this._handleTokenInput}"
            ></textarea>
          </div>

          <div class="button-group">
            <button
              class="validate-button"
              @click="${this._validateToken}"
              ?disabled="${this._loading || !this._token.trim()}"
            >
              ${this._loading ? 'Validating...' : 'Validate Token'}
            </button>

            <button class="clear-button" @click="${this._clearToken}" ?disabled="${!this._token}">
              Clear
            </button>

            <button class="copy-button" @click="${this._copyToken}" ?disabled="${!this._token}">
              Copy Token
            </button>
          </div>
        </div>

        ${this._error
          ? html` <div class="error-message"><strong>Error:</strong> ${this._error}</div> `
          : ''}
        ${this._validationResult
          ? html`
              <div class="result-section">
                <h4 class="result-title">Validation Result</h4>

                <div
                  class="validation-status ${this._validationResult.valid ? 'valid' : 'invalid'}"
                >
                  <strong>Status:</strong> ${this._validationResult.valid ? 'Valid' : 'Invalid'}
                </div>

                ${this._validationResult.error
                  ? html`
                      <div class="validation-error">
                        <strong>Error:</strong> ${this._validationResult.error}
                      </div>
                    `
                  : ''}
                ${this._validationResult.claims
                  ? html`
                      <div class="claims-section">
                        <h5>Claims:</h5>
                        <pre class="claims-display">
${JSON.stringify(this._validationResult.claims, null, 2)}</pre
                        >
                      </div>
                    `
                  : ''}
              </div>
            `
          : ''}
      </div>
    `;
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
    container.append(component);

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
      customElements.define('qwc-jwt-debugger-test', QwcJwtDebugger);
      expect('qwc-jwt-debugger-test').toBeDefinedAsCustomElement();
    });

    it('should render debugger container structure', async () => {
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

      tokenInput.value = testToken;
      tokenInput.dispatchEvent(new Event('input'));
      await waitForComponentUpdate(component);

      expect(component._token).toBe(testToken);
    });

    it('should clear validation result when token changes', async () => {
      // Set initial validation result
      component._validationResult = { valid: true };
      component._error = 'Previous error';

      // Change token
      tokenInput.value = 'new-token';
      tokenInput.dispatchEvent(new Event('input'));
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
      expect(validateButton.disabled).toBe(true);
      expect(validateButton.textContent.trim()).toBe('Validate Token');
    });

    it('should enable validate button when token is present', async () => {
      const tokenInput = component.shadowRoot.querySelector('#token-input');
      tokenInput.value = 'test-token';
      tokenInput.dispatchEvent(new Event('input'));
      await waitForComponentUpdate(component);

      expect(validateButton.disabled).toBe(false);
    });

    it('should disable clear and copy buttons when no token', async () => {
      expect(clearButton.disabled).toBe(true);
      expect(copyButton.disabled).toBe(true);
    });

    it('should enable clear and copy buttons when token is present', async () => {
      const tokenInput = component.shadowRoot.querySelector('#token-input');
      tokenInput.value = 'test-token';
      tokenInput.dispatchEvent(new Event('input'));
      await waitForComponentUpdate(component);

      expect(clearButton.disabled).toBe(false);
      expect(copyButton.disabled).toBe(false);
    });
  });

  describe('Token Validation', () => {
    beforeEach(async () => {
      // Set up a token
      const tokenInput = component.shadowRoot.querySelector('#token-input');
      tokenInput.value = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature';
      tokenInput.dispatchEvent(new Event('input'));
      await waitForComponentUpdate(component);
    });

    it('should call validateToken service when validate button is clicked', async () => {
      const validateButton = component.shadowRoot.querySelector('.validate-button');

      validateButton.click();
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

      const validateButton = component.shadowRoot.querySelector('.validate-button');
      validateButton.click();
      await waitForComponentUpdate(component);

      expect(component._loading).toBe(true);
      expect(validateButton.textContent.trim()).toBe('Validating...');
      expect(validateButton.disabled).toBe(true);

      // Resolve the promise
      resolvePromise({ valid: false, error: 'Token validation not available at build time' });
      await waitForComponentUpdate(component);

      expect(component._loading).toBe(false);
    });

    it('should display validation result for invalid token', async () => {
      const validateButton = component.shadowRoot.querySelector('.validate-button');

      validateButton.click();
      await waitForComponentUpdate(component);

      expect(component).toHaveRenderedContent('Validation Result');
      expect(component).toHaveRenderedContent('Invalid');
      expect(component).toHaveShadowClass('invalid');
      expect(component).toHaveRenderedContent('Token validation not available at build time');
    });

    it('should display error when validation fails', async () => {
      // Setup network error
      const networkError = new Error('Network error');
      devui.jsonRPC.CuiJwtDevUI.validateToken.mockRejectedValue(networkError);

      const validateButton = component.shadowRoot.querySelector('.validate-button');
      validateButton.click();
      await waitForComponentUpdate(component);

      expect(component._error).toContain('Failed to validate token: Network error');
      expect(component).toHaveRenderedContent('Error:');
    });

    it('should show error for empty token validation', async () => {
      // Clear the token
      component._token = '';
      await waitForComponentUpdate(component);

      await component._validateToken();
      await waitForComponentUpdate(component);

      expect(component._error).toBe('Please enter a JWT token to validate');
    });
  });

  describe('Token Operations', () => {
    beforeEach(async () => {
      // Set up a token
      const tokenInput = component.shadowRoot.querySelector('#token-input');
      tokenInput.value = 'test-token';
      tokenInput.dispatchEvent(new Event('input'));
      await waitForComponentUpdate(component);
    });

    it('should clear token when clear button is clicked', async () => {
      const clearButton = component.shadowRoot.querySelector('.clear-button');

      clearButton.click();
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

      const copyButton = component.shadowRoot.querySelector('.copy-button');

      copyButton.click();
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

      const copyButton = component.shadowRoot.querySelector('.copy-button');

      // Should not throw error
      expect(() => copyButton.click()).not.toThrow();
    });
  });

  describe('Error Display', () => {
    it('should display error message when error is present', async () => {
      component._error = 'Test error message';
      await waitForComponentUpdate(component);

      expect(component).toHaveRenderedContent('Error: Test error message');
      expect(component).toHaveShadowClass('error-message');
    });

    it('should not display error section when no error', async () => {
      component._error = null;
      await waitForComponentUpdate(component);

      expect(component).not.toHaveShadowClass('error-message');
    });
  });

  describe('Validation Result Display', () => {
    it('should display validation result section when result is present', async () => {
      component._validationResult = {
        valid: false,
        error: 'Invalid token',
      };
      await waitForComponentUpdate(component);

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
      await waitForComponentUpdate(component);

      expect(component).toHaveRenderedContent('Claims:');
      expect(component).toHaveShadowClass('claims-section');
      expect(component).toHaveShadowClass('claims-display');
      expect(component).toHaveRenderedContent('user123');
    });

    it('should not display result section when no result', async () => {
      component._validationResult = null;
      await waitForComponentUpdate(component);

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
      const tokenInput = component.shadowRoot.querySelector('#token-input');
      tokenInput.value = 'test-token';
      tokenInput.dispatchEvent(new Event('input'));
      await waitForComponentUpdate(component);

      await component._validateToken();

      expect(consoleSpy).toHaveBeenCalledWith('Error validating token:', networkError);

      consoleSpy.mockRestore();
    });
  });
});
