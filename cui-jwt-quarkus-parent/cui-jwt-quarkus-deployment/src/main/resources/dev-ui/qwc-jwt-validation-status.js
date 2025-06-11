import { html, css, LitElement } from 'lit';
import { devui } from 'devui';

export class QwcJwtValidationStatus extends LitElement {
  static styles = css`
    .status-card {
      background-color: var(--lumo-base-color);
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 8px;
      margin-bottom: 1rem;
      padding: 1rem;
    }

    .status-header {
      align-items: center;
      display: flex;
      margin-bottom: 1rem;
    }

    .status-indicator {
      border-radius: 50%;
      display: inline-block;
      height: 16px;
      margin-right: 0.5rem;
      width: 16px;
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
      font-size: 1.1rem;
      font-weight: 600;
      margin: 0;
    }

    .status-message {
      color: var(--lumo-secondary-text-color);
      margin-bottom: 1rem;
    }

    .metrics-grid {
      display: grid;
      gap: 1rem;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    }

    .metric-card {
      background-color: var(--lumo-contrast-5pct);
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 6px;
      padding: 0.75rem;
    }

    .metric-label {
      color: var(--lumo-secondary-text-color);
      font-size: 0.875rem;
      margin-bottom: 0.25rem;
    }

    .metric-value {
      color: var(--lumo-primary-text-color);
      font-size: 1.25rem;
      font-weight: 600;
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

    .refresh-button {
      background-color: var(--lumo-primary-color);
      border: none;
      border-radius: 4px;
      color: var(--lumo-primary-contrast-color);
      cursor: pointer;
      font-size: 0.875rem;
      margin-top: 1rem;
      padding: 0.5rem 1rem;
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
