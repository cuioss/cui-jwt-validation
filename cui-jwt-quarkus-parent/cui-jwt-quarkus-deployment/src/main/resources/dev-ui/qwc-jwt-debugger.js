import { html, css, LitElement } from 'lit';
import { devui } from 'devui';

export class QwcJwtDebugger extends LitElement {
  static styles = css`
    .debugger-container {
      padding: 1rem;
      max-width: 1200px;
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
      display: block;
      font-weight: 500;
      margin-bottom: 0.5rem;
      color: var(--lumo-primary-text-color);
    }

    .token-input {
      width: 100%;
      min-height: 120px;
      padding: 0.75rem;
      border: 1px solid var(--lumo-contrast-20pct);
      border-radius: 6px;
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      font-size: 0.875rem;
      resize: vertical;
      background-color: var(--lumo-base-color);
      color: var(--lumo-primary-text-color);
    }

    .token-input:focus {
      outline: none;
      border-color: var(--lumo-primary-color);
      box-shadow: 0 0 0 2px var(--lumo-primary-color-10pct);
    }

    .button-group {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 1rem;
    }

    .action-button {
      padding: 0.75rem 1.5rem;
      border: none;
      border-radius: 6px;
      font-size: 0.875rem;
      cursor: pointer;
      font-weight: 500;
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
      color: var(--lumo-primary-text-color);
      border: 1px solid var(--lumo-contrast-20pct);
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
      padding: 1rem;
      border-radius: 8px;
      border: 1px solid var(--lumo-contrast-10pct);
      margin-bottom: 1rem;
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
      display: flex;
      align-items: center;
      margin-bottom: 1rem;
    }

    .result-icon {
      width: 20px;
      height: 20px;
      margin-right: 0.5rem;
      border-radius: 50%;
    }

    .icon-success {
      background-color: var(--lumo-success-color);
    }

    .icon-error {
      background-color: var(--lumo-error-color);
    }

    .result-title {
      font-weight: 600;
      font-size: 1.1rem;
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
      border-radius: 6px;
      padding: 1rem;
      border: 1px solid var(--lumo-contrast-10pct);
    }

    .claims-json {
      font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      font-size: 0.875rem;
      white-space: pre-wrap;
      word-break: break-all;
      margin: 0;
      color: var(--lumo-primary-text-color);
    }

    .error-message {
      color: var(--lumo-error-text-color);
      font-weight: 500;
    }

    .token-info {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 1rem;
    }

    .info-item {
      padding: 0.75rem;
      background-color: var(--lumo-contrast-5pct);
      border-radius: 6px;
      border: 1px solid var(--lumo-contrast-10pct);
    }

    .info-label {
      font-size: 0.875rem;
      color: var(--lumo-secondary-text-color);
      margin-bottom: 0.25rem;
    }

    .info-value {
      font-weight: 600;
      color: var(--lumo-primary-text-color);
    }

    .loading {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      color: var(--lumo-secondary-text-color);
    }

    .spinner {
      width: 16px;
      height: 16px;
      border: 2px solid var(--lumo-contrast-20pct);
      border-top: 2px solid var(--lumo-primary-color);
      border-radius: 50%;
      animation: spin 1s linear infinite;
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
    const sampleToken =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
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
