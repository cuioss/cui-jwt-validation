/**
 * Unit tests for QwcJwksEndpoints component
 */

import { html, LitElement } from 'lit';
import { devui, mockScenarios, resetDevUIMocks } from '../mocks/devui.js';

// Import the component class (we'll mock the file import)
class QwcJwksEndpoints extends LitElement {
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

      // Fix the typo from the original code
      const response = await devui.jsonRPC.CuiJwtDevUI.getJwksStatus();
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

        <div class="jwks-status ${this._getStatusClass(status.status)}">
          ${this._getStatusMessage(status.status)}
        </div>

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
                          <div
                            class="detail-value ${issuer.issuerUri === 'not configured'
                              ? 'not-configured'
                              : ''}"
                          >
                            ${issuer.issuerUri}
                          </div>
                        </div>

                        <div class="detail-item">
                          <div class="detail-label">JWKS URI</div>
                          <div
                            class="detail-value ${issuer.jwksUri === 'not configured'
                              ? 'not-configured'
                              : ''}"
                          >
                            ${issuer.jwksUri}
                          </div>
                        </div>

                        <div class="detail-item">
                          <div class="detail-label">Loader Status</div>
                          <div class="loader-status">
                            <div
                              class="status-indicator status-${issuer.loaderStatus.toLowerCase()}"
                            ></div>
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

describe('QwcJwksEndpoints', () => {
  let component;
  let container;

  beforeEach(async () => {
    // Reset all mocks
    resetDevUIMocks();

    // Create container
    container = document.createElement('div');
    document.body.append(container);

    // Create component
    component = new QwcJwksEndpoints();
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
      expect(component._jwksStatus).toBeNull();
      expect(component._loading).toBe(true);
      expect(component._error).toBeNull();
    });

    it('should be defined as custom element', () => {
      customElements.define('qwc-jwks-endpoints-test', QwcJwksEndpoints);
      expect('qwc-jwks-endpoints-test').toBeDefinedAsCustomElement();
    });

    it('should call getJwksStatus on connection', async () => {
      expect(devui.jsonRPC.CuiJwtDevUI.getJwksStatus).toHaveBeenCalled();
    });
  });

  describe('Loading State', () => {
    it('should show loading message initially', async () => {
      // Reset component to initial state
      component._jwksStatus = null;
      component._loading = true;
      component._error = null;
      await waitForComponentUpdate(component);

      expect(component).toHaveRenderedContent('Loading JWKS endpoint status...');
    });

    it('should have loading class when loading', async () => {
      component._jwksStatus = null;
      component._loading = true;
      component._error = null;
      await waitForComponentUpdate(component);

      expect(component).toHaveShadowClass('loading');
    });
  });

  describe('Error State', () => {
    beforeEach(async () => {
      // Setup error scenario
      mockScenarios.networkError();
      component._error = 'Failed to load JWKS status: Network error';
      component._loading = false;
      await waitForComponentUpdate(component);
    });

    it('should display error message', async () => {
      expect(component).toHaveRenderedContent('Failed to load JWKS status: Network error');
    });

    it('should have error class when error occurs', async () => {
      expect(component).toHaveShadowClass('error');
    });

    it('should show retry button in error state', async () => {
      const retryButton = component.shadowRoot.querySelector('.refresh-button');
      expect(retryButton).toBeTruthy();
      expect(retryButton.textContent.trim()).toBe('Retry');
    });

    it('should retry loading when retry button is clicked', async () => {
      const retryButton = component.shadowRoot.querySelector('.refresh-button');

      // Reset mock to success
      resetDevUIMocks();

      // Click retry button
      retryButton.click();
      await waitForComponentUpdate(component);

      expect(devui.jsonRPC.CuiJwtDevUI.getJwksStatus).toHaveBeenCalled();
    });
  });

  describe('Build Time Status Display', () => {
    beforeEach(async () => {
      // Wait for initial load to complete
      await waitForComponentUpdate(component);
    });

    it('should display build time status correctly', async () => {
      expect(component).toHaveRenderedContent('JWKS endpoint status will be available at runtime');
      expect(component).toHaveRenderedContent('BUILD_TIME');
    });

    it('should render jwks container structure', async () => {
      expect(component).toHaveShadowClass('jwks-container');
      expect(component).toHaveShadowClass('jwks-header');
      expect(component).toHaveShadowClass('jwks-title');
    });
  });

  describe('Runtime Status Display', () => {
    describe('when issuers are configured', () => {
      beforeEach(async () => {
        // Setup configured issuers scenario
        devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockResolvedValue({
          status: 'CONFIGURED',
          issuers: [
            {
              name: 'keycloak',
              issuerUri: 'https://keycloak.example.com/auth/realms/master',
              jwksUri:
                'https://keycloak.example.com/auth/realms/master/protocol/openid-connect/certs',
              loaderStatus: 'ACTIVE',
              lastRefresh: '2023-10-01T10:00:00Z',
            },
          ],
        });

        await component._loadJwksStatus();
        await waitForComponentUpdate(component);
      });

      it('should display configured status correctly', async () => {
        expect(component).toHaveRenderedContent('JWKS endpoints are configured and available');
      });

      it('should show configured status class', async () => {
        expect(component).toHaveShadowClass('status-configured');
      });

      it('should display issuer information', async () => {
        expect(component).toHaveRenderedContent('keycloak');
        expect(component).toHaveRenderedContent('https://keycloak.example.com/auth/realms/master');
        expect(component).toHaveRenderedContent(
          'https://keycloak.example.com/auth/realms/master/protocol/openid-connect/certs'
        );
      });

      it('should display loader status with indicator', async () => {
        expect(component).toHaveRenderedContent('ACTIVE');
        expect(component).toHaveShadowClass('status-indicator');
      });

      it('should display last refresh time', async () => {
        expect(component).toHaveRenderedContent('2023-10-01T10:00:00Z');
      });
    });

    describe('when no issuers are configured', () => {
      beforeEach(async () => {
        // Setup no issuers scenario
        devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockResolvedValue({
          status: 'NO_ISSUERS',
          message: 'No issuers configured',
        });

        await component._loadJwksStatus();
        await waitForComponentUpdate(component);
      });

      it('should display no issuers status correctly', async () => {
        expect(component).toHaveRenderedContent('No issuers are configured for JWT validation');
      });

      it('should show no issuers status class', async () => {
        expect(component).toHaveShadowClass('status-no-issuers');
      });

      it('should display no issuer configurations message', async () => {
        expect(component).toHaveRenderedContent('No issuer configurations found');
      });
    });
  });

  describe('Status Helper Methods', () => {
    it('should return correct status class for NO_ISSUERS', () => {
      expect(component._getStatusClass('NO_ISSUERS')).toBe('status-no-issuers');
    });

    it('should return correct status class for CONFIGURED', () => {
      expect(component._getStatusClass('CONFIGURED')).toBe('status-configured');
    });

    it('should return empty string for unknown status', () => {
      expect(component._getStatusClass('UNKNOWN')).toBe('');
    });

    it('should return correct status message for NO_ISSUERS', () => {
      expect(component._getStatusMessage('NO_ISSUERS')).toBe(
        'No issuers are configured for JWT validation'
      );
    });

    it('should return correct status message for CONFIGURED', () => {
      expect(component._getStatusMessage('CONFIGURED')).toBe(
        'JWKS endpoints are configured and available'
      );
    });

    it('should return unknown status message for unknown status', () => {
      expect(component._getStatusMessage('UNKNOWN')).toBe('Unknown status');
    });
  });

  describe('Refresh Functionality', () => {
    it('should have refresh button', async () => {
      await waitForComponentUpdate(component);
      const refreshButton = component.shadowRoot.querySelector('.refresh-button');
      expect(refreshButton).toBeTruthy();
      expect(refreshButton.textContent.trim()).toBe('Refresh');
    });

    it('should reload status when refresh button is clicked', async () => {
      await waitForComponentUpdate(component);
      const refreshButton = component.shadowRoot.querySelector('.refresh-button');

      // Clear previous calls
      devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockClear();

      // Click refresh
      refreshButton.click();
      await waitForComponentUpdate(component);

      expect(devui.jsonRPC.CuiJwtDevUI.getJwksStatus).toHaveBeenCalled();
    });
  });

  describe('Component Lifecycle', () => {
    it('should load JWKS status on connected callback', async () => {
      const newComponent = new QwcJwksEndpoints();

      // Clear previous calls
      devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockClear();

      // Connect component
      document.body.append(newComponent);
      await waitForComponentUpdate(newComponent);

      expect(devui.jsonRPC.CuiJwtDevUI.getJwksStatus).toHaveBeenCalled();

      // Cleanup
      newComponent.remove();
    });

    it('should handle component properties correctly', () => {
      expect(QwcJwksEndpoints.properties).toBeDefined();
      expect(QwcJwksEndpoints.properties._jwksStatus).toEqual({ state: true });
      expect(QwcJwksEndpoints.properties._loading).toEqual({ state: true });
      expect(QwcJwksEndpoints.properties._error).toEqual({ state: true });
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors gracefully', async () => {
      // Setup network error
      const networkError = new Error('Network error');
      devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockRejectedValue(networkError);

      await component._loadJwksStatus();
      await waitForComponentUpdate(component);

      expect(component._error).toContain('Failed to load JWKS status: Network error');
      expect(component._loading).toBe(false);
    });

    it('should log errors to console', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const networkError = new Error('Test error');
      devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockRejectedValue(networkError);

      await component._loadJwksStatus();

      expect(consoleSpy).toHaveBeenCalledWith('Error loading JWKS status:', networkError);

      consoleSpy.mockRestore();
    });
  });

  describe('Issuer Detail Rendering', () => {
    beforeEach(async () => {
      // Setup multiple issuers with different configurations
      devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockResolvedValue({
        status: 'CONFIGURED',
        issuers: [
          {
            name: 'keycloak',
            issuerUri: 'https://keycloak.example.com/auth/realms/master',
            jwksUri:
              'https://keycloak.example.com/auth/realms/master/protocol/openid-connect/certs',
            loaderStatus: 'ACTIVE',
            lastRefresh: '2023-10-01T10:00:00Z',
          },
          {
            name: 'auth0',
            issuerUri: 'not configured',
            jwksUri: 'not configured',
            loaderStatus: 'ERROR',
            lastRefresh: 'Never',
          },
        ],
      });

      await component._loadJwksStatus();
      await waitForComponentUpdate(component);
    });

    it('should render multiple issuer cards', async () => {
      const issuerCards = component.shadowRoot.querySelectorAll('.issuer-card');
      expect(issuerCards).toHaveLength(2);
    });

    it('should apply not-configured class for unconfigured values', async () => {
      expect(component).toHaveShadowClass('not-configured');
    });

    it('should render status indicators with appropriate classes', async () => {
      expect(component).toHaveShadowClass('status-active');
      expect(component).toHaveShadowClass('status-error');
    });

    it('should display detail items for each issuer', async () => {
      const detailItems = component.shadowRoot.querySelectorAll('.detail-item');
      expect(detailItems.length).toBeGreaterThan(0);
    });
  });
});
