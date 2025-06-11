import { html, css, LitElement } from 'lit';
import { devui } from 'devui';

export class QwcJwtDebugger extends LitElement {
  static styles = css`
    .debugger-container {
      max-width: 1200px;
      padding: 1rem;
    }

    .debugger-title {
      font-size: 1.2rem;
      font-weight: 600;
      margin-bottom: 1rem;
    }

    .input-section {
      margin-bottom: 2rem;
    }

    .input-group {
      margin-bottom: 1rem;
    }

    .input-label {
      color: var(--lumo-primary-text-color);
      display: block;
      font-weight: 500;
      margin-bottom: 0.5rem;
    }

    .token-input {
      background-color: var(--lumo-base-color);
      border: 1px solid var(--lumo-contrast-20pct);
      border-radius: 6px;
      color: var(--lumo-primary-text-color);
      font-family: Monaco, Menlo, 'Ubuntu Mono', monospace;
      font-size: 0.875rem;
      min-height: 120px;
      padding: 0.75rem;
      resize: vertical;
      width: 100%;
    }

    .token-input:focus {
      border-color: var(--lumo-primary-color);
      box-shadow: 0 0 0 2px var(--lumo-primary-color-10pct);
      outline: none;
    }

    .button-group {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 1rem;
    }

    .action-button {
      border: none;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.875rem;
      font-weight: 500;
      padding: 0.75rem 1.5rem;
    }

    .validate-button {
      background-color: var(--lumo-primary-color);
      color: var(--lumo-primary-contrast-color);
    }

    .validate-button:hover {
      background-color: var(--lumo-primary-color-50pct);
    }

    .validate-button:disabled {
      background-color: var(--lumo-contrast-20pct);
      color: var(--lumo-disabled-text-color);
      cursor: not-allowed;
    }

    .clear-button {
      background-color: var(--lumo-contrast-10pct);
      border: 1px solid var(--lumo-contrast-20pct);
      color: var(--lumo-primary-text-color);
    }

    .clear-button:hover {
      background-color: var(--lumo-contrast-20pct);
    }

    .sample-button {
      background-color: var(--lumo-success-color);
      color: var(--lumo-success-contrast-color);
    }

    .sample-button:hover {
      background-color: var(--lumo-success-color-50pct);
    }

    .results-section {
      margin-top: 2rem;
    }

    .result-card {
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 8px;
      margin-bottom: 1rem;
      padding: 1rem;
    }

    .result-success {
      background-color: var(--lumo-success-color-10pct);
      border-color: var(--lumo-success-color-50pct);
    }

    .result-error {
      background-color: var(--lumo-error-color-10pct);
      border-color: var(--lumo-error-color-50pct);
    }

    .result-header {
      align-items: center;
      display: flex;
      margin-bottom: 1rem;
    }

    .result-icon {
      border-radius: 50%;
      height: 20px;
      margin-right: 0.5rem;
      width: 20px;
    }

    .icon-success {
      background-color: var(--lumo-success-color);
    }

    .icon-error {
      background-color: var(--lumo-error-color);
    }

    .result-title {
      font-size: 1.1rem;
      font-weight: 600;
      margin: 0;
    }

    .result-title-success {
      color: var(--lumo-success-text-color);
    }

    .result-title-error {
      color: var(--lumo-error-text-color);
    }

    .claims-section {
      margin-top: 1rem;
    }

    .claims-title {
      font-weight: 600;
      margin-bottom: 0.5rem;
    }

    .claims-container {
      background-color: var(--lumo-contrast-5pct);
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 6px;
      padding: 1rem;
    }

    .claims-json {
      color: var(--lumo-primary-text-color);
      font-family: Monaco, Menlo, 'Ubuntu Mono', monospace;
      font-size: 0.875rem;
      margin: 0;
      white-space: pre-wrap;
      word-break: break-all;
    }

    .error-message {
      color: var(--lumo-error-text-color);
      font-weight: 500;
    }

    .token-info {
      display: grid;
      gap: 1rem;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      margin-bottom: 1rem;
    }

    .info-item {
      background-color: var(--lumo-contrast-5pct);
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 6px;
      padding: 0.75rem;
    }

    .info-label {
      color: var(--lumo-secondary-text-color);
      font-size: 0.875rem;
      margin-bottom: 0.25rem;
    }

    .info-value {
      color: var(--lumo-primary-text-color);
      font-weight: 600;
    }

    .loading {
      align-items: center;
      color: var(--lumo-secondary-text-color);
      display: flex;
      gap: 0.5rem;
    }

    .spinner {
      animation: spin 1s linear infinite;
      border: 2px solid var(--lumo-contrast-20pct);
      border-radius: 50%;
      border-top: 2px solid var(--lumo-primary-color);
      height: 16px;
      width: 16px;
    }

    @keyframes spin {
      0% {
        transform: rotate(0deg);
      }

      100% {
        transform: rotate(360deg);
      }
    }
  `;

  static properties = {
    _token: { state: true },
    _validationResult: { state: true },
    _validating: { state: true },
  };

  constructor() {
    super();
    this._token = '';
    this._validationResult = null;
    this._validating = false;
  }

  _handleTokenInput(e) {
    this._token = e.target.value;
  }

  _clearToken() {
    this._token = '';
    this._validationResult = null;
    this.shadowRoot.querySelector('.token-input').value = '';
  }

  _loadSampleToken() {
    // Sample JWT token for testing (this would be generated by the backend in a real scenario)
    const sampleToken = [
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
      'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
      'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    ].join('.');
    this._token = sampleToken;
    this.shadowRoot.querySelector('.token-input').value = sampleToken;
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

      const result = await devui.jsonrpc.CuiJwtDevUI.validateToken(this._token.trim());
      this._validationResult = result;
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('Error validating token:', error);
      this._validationResult = {
        valid: false,
        error: `Failed to validate token: ${error.message}`,
      };
    } finally {
      this._validating = false;
    }
  }

  _formatJson(obj) {
    return JSON.stringify(obj, null, 2);
  }

  render() {
    return html`
      <div class="debugger-container">
        <h3 class="debugger-title">JWT Token Debugger</h3>

        <div class="input-section">
          <div class="input-group">
            <label class="input-label">JWT Token</label>
            <textarea
              class="token-input"
              placeholder="Paste your JWT token here..."
              @input="${this._handleTokenInput}"
            ></textarea>
          </div>

          <div class="button-group">
            <button
              class="action-button validate-button"
              ?disabled="${this._validating}"
              @click="${this._validateToken}"
            >
              ${this._validating
                ? html`
                    <span class="loading">
                      <div class="spinner"></div>
                      Validating...
                    </span>
                  `
                : 'Validate Token'}
            </button>

            <button class="action-button clear-button" @click="${this._clearToken}">Clear</button>

            <button class="action-button sample-button" @click="${this._loadSampleToken}">Load Sample</button>
          </div>
        </div>

        ${this._validationResult
          ? html`
              <div class="results-section">
                <div class="result-card ${this._validationResult.valid ? 'result-success' : 'result-error'}">
                  <div class="result-header">
                    <div class="result-icon ${this._validationResult.valid ? 'icon-success' : 'icon-error'}"></div>
                    <h4
                      class="result-title ${this._validationResult.valid
                        ? 'result-title-success'
                        : 'result-title-error'}"
                    >
                      ${this._validationResult.valid ? 'Token is Valid' : 'Token is Invalid'}
                    </h4>
                  </div>

                  ${this._validationResult.valid
                    ? html`
                        <div class="token-info">
                          <div class="info-item">
                            <div class="info-label">Token Type</div>
                            <div class="info-value">${this._validationResult.tokenType || 'Unknown'}</div>
                          </div>
                        </div>

                        ${this._validationResult.claims
                          ? html`
                              <div class="claims-section">
                                <div class="claims-title">Token Claims</div>
                                <div class="claims-container">
                                  <pre class="claims-json">${this._formatJson(this._validationResult.claims)}</pre>
                                </div>
                              </div>
                            `
                          : ''}
                      `
                    : html`
                        <div class="error-message">${this._validationResult.error || 'Token validation failed'}</div>

                        ${this._validationResult.details
                          ? html`
                              <div
                                style="margin-top: 1rem; color: var(--lumo-secondary-text-color); font-size: 0.875rem;"
                              >
                                ${this._validationResult.details}
                              </div>
                            `
                          : ''}
                      `}
                </div>
              </div>
            `
          : ''}
      </div>
    `;
  }
}

customElements.define('qwc-jwt-debugger', QwcJwtDebugger);
