import { html, css, LitElement } from 'lit';
import { devui } from 'devui';

export class QwcJwtValidationStatus extends LitElement {
  static styles = css`
    .status-card {
      padding: 1rem;
      border-radius: 8px;
      background-color: var(--lumo-base-color);
      border: 1px solid var(--lumo-contrast-10pct);
      margin-bottom: 1rem;
    }

    .status-header {
      display: flex;
      align-items: center;
      margin-bottom: 1rem;
    }

    .status-indicator {
      width: 16px;
      height: 16px;
      border-radius: 50%;
      margin-right: 0.5rem;
      display: inline-block;
    }

    .status-active {
      background-color: var(--lumo-success-color);
      box-shadow: 0 0 8px var(--lumo-success-color);
    }

    .status-inactive {
      background-color: var(--lumo-error-color);
      box-shadow: 0 0 8px var(--lumo-error-color);
    }

    .status-title {
      font-weight: 600;
      font-size: 1.1rem;
      margin: 0;
    }

    .status-message {
      color: var(--lumo-secondary-text-color);
      margin-bottom: 1rem;
    }

    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
    }

    .metric-card {
      padding: 0.75rem;
      border-radius: 6px;
      background-color: var(--lumo-contrast-5pct);
      border: 1px solid var(--lumo-contrast-10pct);
    }

    .metric-label {
      font-size: 0.875rem;
      color: var(--lumo-secondary-text-color);
      margin-bottom: 0.25rem;
    }

    .metric-value {
      font-size: 1.25rem;
      font-weight: 600;
      color: var(--lumo-primary-text-color);
    }

    .loading {
      text-align: center;
      padding: 2rem;
      color: var(--lumo-secondary-text-color);
    }

    .error {
      color: var(--lumo-error-text-color);
      background-color: var(--lumo-error-color-10pct);
      padding: 1rem;
      border-radius: 6px;
      border: 1px solid var(--lumo-error-color-50pct);
    }

    .refresh-button {
      margin-top: 1rem;
      padding: 0.5rem 1rem;
      border: none;
      border-radius: 4px;
      background-color: var(--lumo-primary-color);
      color: var(--lumo-primary-contrast-color);
      cursor: pointer;
      font-size: 0.875rem;
    }

    .refresh-button:hover {
      background-color: var(--lumo-primary-color-50pct);
    }
  `;

  static properties = {
    _validationStatus: { state: true },
    _loading: { state: true },
    _error: { state: true },
  };

  constructor() {
    super();
    this._validationStatus = null;
    this._loading = true;
    this._error = null;
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadValidationStatus();
    // Auto-refresh every 30 seconds
    this._refreshInterval = setInterval(() => this._loadValidationStatus(), 30_000);
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    if (this._refreshInterval) {
      clearInterval(this._refreshInterval);
    }
  }

  async _loadValidationStatus() {
    try {
      this._loading = true;
      this._error = null;

      const response = await devui.jsonrpc.CuiJwtDevUI.getValidationStatus();
      this._validationStatus = response;
    } catch (error) {
      console.error('Error loading JWT validation status:', error);
      this._error = `Failed to load validation status: ${error.message}`;
    } finally {
      this._loading = false;
    }
  }

  _refreshStatus() {
    this._loadValidationStatus();
  }

  render() {
    if (this._loading && !this._validationStatus) {
      return html`<div class="loading">Loading JWT validation status...</div>`;
    }

    if (this._error) {
      return html`
        <div class="error">
          ${this._error}
          <button class="refresh-button" @click="${this._refreshStatus}">Retry</button>
        </div>
      `;
    }

    if (!this._validationStatus) {
      return html`<div class="loading">No status data available</div>`;
    }

    const status = this._validationStatus;
    const isActive = status.status === 'ACTIVE';

    return html`
      <div class="status-card">
        <div class="status-header">
          <div class="status-indicator ${isActive ? 'status-active' : 'status-inactive'}"></div>
          <h3 class="status-title">JWT Validation Status</h3>
        </div>

        <div class="status-message">${status.statusMessage || 'No status message available'}</div>

        <div class="metrics-grid">
          <div class="metric-card">
            <div class="metric-label">Validation Enabled</div>
            <div class="metric-value">${status.enabled ? 'Yes' : 'No'}</div>
          </div>

          <div class="metric-card">
            <div class="metric-label">Validator Available</div>
            <div class="metric-value">${status.validatorPresent ? 'Yes' : 'No'}</div>
          </div>

          <div class="metric-card">
            <div class="metric-label">Overall Status</div>
            <div class="metric-value">${status.status}</div>
          </div>

          ${status.securityEvents
            ? html`
                <div class="metric-card">
                  <div class="metric-label">Total Security Events</div>
                  <div class="metric-value">${status.securityEvents.totalEvents}</div>
                </div>

                <div class="metric-card">
                  <div class="metric-label">Error Events</div>
                  <div class="metric-value">${status.securityEvents.errorEvents}</div>
                </div>

                <div class="metric-card">
                  <div class="metric-label">Warning Events</div>
                  <div class="metric-value">${status.securityEvents.warningEvents}</div>
                </div>
              `
            : ''}
        </div>

        <button class="refresh-button" @click="${this._refreshStatus}">Refresh Status</button>
      </div>
    `;
  }
}

customElements.define('qwc-jwt-validation-status', QwcJwtValidationStatus);
