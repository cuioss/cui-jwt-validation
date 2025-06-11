import { html, css, LitElement } from 'lit';
import { devui } from 'devui';

export class QwcJwksEndpoints extends LitElement {
  static styles = css`
    .jwks-container {
      padding: 1rem;
    }

    .jwks-header {
      align-items: center;
      display: flex;
      justify-content: space-between;
      margin-bottom: 1rem;
    }

    .jwks-title {
      font-size: 1.2rem;
      font-weight: 600;
      margin: 0;
    }

    .refresh-button {
      background-color: var(--lumo-primary-color);
      border: none;
      border-radius: 4px;
      color: var(--lumo-primary-contrast-color);
      cursor: pointer;
      font-size: 0.875rem;
      padding: 0.5rem 1rem;
    }

    .refresh-button:hover {
      background-color: var(--lumo-primary-color-50pct);
    }

    .jwks-status {
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 6px;
      margin-bottom: 1rem;
      padding: 1rem;
    }

    .status-no-issuers {
      background-color: var(--lumo-error-color-10pct);
      border-color: var(--lumo-error-color-50pct);
      color: var(--lumo-error-text-color);
    }

    .status-configured {
      background-color: var(--lumo-success-color-10pct);
      border-color: var(--lumo-success-color-50pct);
      color: var(--lumo-success-text-color);
    }

    .issuers-grid {
      display: grid;
      gap: 1rem;
    }

    .issuer-card {
      background-color: var(--lumo-base-color);
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 8px;
      padding: 1rem;
    }

    .issuer-name {
      color: var(--lumo-primary-text-color);
      font-size: 1.1rem;
      font-weight: 600;
      margin-bottom: 0.5rem;
    }

    .issuer-details {
      display: grid;
      gap: 0.75rem;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    }

    .detail-item {
      background-color: var(--lumo-contrast-5pct);
      border-radius: 4px;
      padding: 0.5rem;
    }

    .detail-label {
      color: var(--lumo-secondary-text-color);
      font-size: 0.875rem;
      margin-bottom: 0.25rem;
    }

    .detail-value {
      color: var(--lumo-primary-text-color);
      font-family: monospace;
      font-size: 0.875rem;
      word-break: break-all;
    }

    .detail-value.not-configured {
      color: var(--lumo-error-text-color);
      font-style: italic;
    }

    .loader-status {
      align-items: center;
      display: flex;
      gap: 0.5rem;
    }

    .status-indicator {
      border-radius: 50%;
      height: 12px;
      width: 12px;
    }

    .status-unknown {
      background-color: var(--lumo-contrast-30pct);
    }

    .status-active {
      background-color: var(--lumo-success-color);
    }

    .status-error {
      background-color: var(--lumo-error-color);
    }

    .loading {
      color: var(--lumo-secondary-text-color);
      padding: 2rem;
      text-align: center;
    }

    .error {
      background-color: var(--lumo-error-color-10pct);
      border: 1px solid var(--lumo-error-color-50pct);
      border-radius: 6px;
      color: var(--lumo-error-text-color);
      padding: 1rem;
    }
  `;

  static properties = {
    _jwksStatus: { state: true },
    _loading: { state: true },
    _error: { state: true },
  };

  constructor() {
    super();
    this._jwksStatus = null;
    this._loading = true;
    this._error = null;
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadJwksStatus();
  }

  async _loadJwksStatus() {
    try {
      this._loading = true;
      this._error = null;

      const response = await devui.jsonrpc.CuiJwtDevUI.getJwksStatus();
      this._jwksStatus = response;
    } catch (error) {
      console.error('Error loading JWKS status:', error);
      this._error = `Failed to load JWKS status: ${error.message}`;
    } finally {
      this._loading = false;
    }
  }

  _refreshStatus() {
    this._loadJwksStatus();
  }

  _getStatusClass(status) {
    switch (status) {
      case 'NO_ISSUERS': {
        return 'status-no-issuers';
      }
      case 'CONFIGURED': {
        return 'status-configured';
      }
      default: {
        return '';
      }
    }
  }

  _getStatusMessage(status) {
    switch (status) {
      case 'NO_ISSUERS': {
        return 'No issuers are configured for JWT validation';
      }
      case 'CONFIGURED': {
        return 'JWKS endpoints are configured and available';
      }
      default: {
        return 'Unknown status';
      }
    }
  }

  render() {
    if (this._loading && !this._jwksStatus) {
      return html`<div class="loading">Loading JWKS endpoint status...</div>`;
    }

    if (this._error) {
      return html`
        <div class="error">
          ${this._error}
          <button class="refresh-button" @click="${this._refreshStatus}">Retry</button>
        </div>
      `;
    }

    if (!this._jwksStatus) {
      return html`<div class="loading">No JWKS status data available</div>`;
    }

    const status = this._jwksStatus;

    return html`
      <div class="jwks-container">
        <div class="jwks-header">
          <h3 class="jwks-title">JWKS Endpoints Status</h3>
          <button class="refresh-button" @click="${this._refreshStatus}">Refresh</button>
        </div>

        <div class="jwks-status ${this._getStatusClass(status.status)}">${this._getStatusMessage(status.status)}</div>

        ${status.issuers && status.issuers.length > 0
          ? html`
              <div class="issuers-grid">
                ${status.issuers.map(
                  (issuer) => html`
                    <div class="issuer-card">
                      <div class="issuer-name">${issuer.name}</div>

                      <div class="issuer-details">
                        <div class="detail-item">
                          <div class="detail-label">Issuer URI</div>
                          <div class="detail-value ${issuer.issuerUri === 'not configured' ? 'not-configured' : ''}">
                            ${issuer.issuerUri}
                          </div>
                        </div>

                        <div class="detail-item">
                          <div class="detail-label">JWKS URI</div>
                          <div class="detail-value ${issuer.jwksUri === 'not configured' ? 'not-configured' : ''}">
                            ${issuer.jwksUri}
                          </div>
                        </div>

                        <div class="detail-item">
                          <div class="detail-label">Loader Status</div>
                          <div class="loader-status">
                            <div class="status-indicator status-${issuer.loaderStatus.toLowerCase()}"></div>
                            <span class="detail-value">${issuer.loaderStatus}</span>
                          </div>
                        </div>

                        <div class="detail-item">
                          <div class="detail-label">Last Refresh</div>
                          <div class="detail-value">${issuer.lastRefresh}</div>
                        </div>
                      </div>
                    </div>
                  `
                )}
              </div>
            `
          : html` <div class="loading">No issuer configurations found</div> `}
      </div>
    `;
  }
}

customElements.define('qwc-jwks-endpoints', QwcJwksEndpoints);
