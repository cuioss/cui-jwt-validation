/**
 * Unit tests for QwcJwtConfig component
 */

import { html, LitElement } from 'lit';
import { devui, resetDevUIMocks } from '../mocks/devui.js';

// Simplified version of the component for testing
class QwcJwtConfig extends LitElement {
  static properties = {
    _configuration: { state: true },
    _loading: { state: true },
    _error: { state: true },
  };

  constructor() {
    super();
    this._configuration = null;
    this._loading = true;
    this._error = null;
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadConfiguration();
  }

  async _loadConfiguration() {
    try {
      this._loading = true;
      this._error = null;
      this.requestUpdate();

      const response = await devui.jsonRPC.CuiJwtDevUI.getConfiguration();
      this._configuration = response;
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('Error loading configuration:', error);
      this._error = `Failed to load configuration: ${error.message}`;
    } finally {
      this._loading = false;
      this.requestUpdate();
    }
  }

  _refreshConfiguration() {
    this._loadConfiguration();
  }

  render() {
    const result = this._doRender();
    // Store result for testing
    this._lastRenderedResult = result.strings ? result.strings.join('') : result.toString();
    return result;
  }

  _doRender() {
    if (this._loading && !this._configuration) {
      return html`<div class="loading">Loading JWT configuration...</div>`;
    }

    if (this._error) {
      return html`
        <div class="error">
          ${this._error}
          <button class="refresh-button" @click="${this._refreshConfiguration}">Retry</button>
        </div>
      `;
    }

    if (!this._configuration) {
      return html`<div class="loading">No configuration data available</div>`;
    }

    const config = this._configuration;

    return html`
      <div class="config-container">
        <div class="config-header">
          <h3 class="config-title">JWT Configuration</h3>
          <button class="refresh-button" @click="${this._refreshConfiguration}">Refresh</button>
        </div>

        <div class="config-sections">
          <div class="config-section">
            <h4 class="section-title">General Configuration</h4>
            <div class="config-grid">
              <div class="config-item">
                <div class="config-label">JWT Validation Enabled</div>
                <div class="config-value ${config.enabled ? 'enabled' : 'disabled'}">
                  ${config.enabled ? 'Yes' : 'No'}
                </div>
              </div>

              <div class="config-item">
                <div class="config-label">Health Checks Enabled</div>
                <div class="config-value ${config.healthEnabled ? 'enabled' : 'disabled'}">
                  ${config.healthEnabled ? 'Yes' : 'No'}
                </div>
              </div>

              ${config.buildTime
                ? html`
                    <div class="config-item">
                      <div class="config-label">Build Time</div>
                      <div class="config-value build-time">Yes</div>
                    </div>
                  `
                : ''}
            </div>
          </div>

          ${config.parser
            ? html`
                <div class="config-section">
                  <h4 class="section-title">Parser Configuration</h4>
                  <div class="config-grid">
                    <div class="config-item">
                      <div class="config-label">Max Token Size</div>
                      <div class="config-value">${config.parser.maxTokenSizeBytes} bytes</div>
                    </div>

                    <div class="config-item">
                      <div class="config-label">Clock Leeway</div>
                      <div class="config-value">${config.parser.leewaySeconds} seconds</div>
                    </div>

                    <div class="config-item">
                      <div class="config-label">Validate Expiration</div>
                      <div class="config-value">
                        ${config.parser.validateExpiration ? 'Yes' : 'No'}
                      </div>
                    </div>

                    <div class="config-item">
                      <div class="config-label">Allowed Algorithms</div>
                      <div class="config-value algorithms">${config.parser.allowedAlgorithms}</div>
                    </div>
                  </div>
                </div>
              `
            : ''}
          ${config.health
            ? html`
                <div class="config-section">
                  <h4 class="section-title">Health Check Configuration</h4>
                  <div class="config-grid">
                    <div class="config-item">
                      <div class="config-label">Health Checks Enabled</div>
                      <div class="config-value">${config.health.enabled ? 'Yes' : 'No'}</div>
                    </div>

                    ${config.health.jwks
                      ? html`
                          <div class="config-item">
                            <div class="config-label">JWKS Health Cache</div>
                            <div class="config-value">
                              ${config.health.jwks.cacheSeconds} seconds
                            </div>
                          </div>

                          <div class="config-item">
                            <div class="config-label">JWKS Health Timeout</div>
                            <div class="config-value">
                              ${config.health.jwks.timeoutSeconds} seconds
                            </div>
                          </div>
                        `
                      : ''}
                  </div>
                </div>
              `
            : ''}
          ${config.issuers
            ? html`
                <div class="config-section">
                  <h4 class="section-title">Issuer Configuration</h4>
                  ${Object.keys(config.issuers).length > 0
                    ? html`
                        <div class="issuers-grid">
                          ${Object.entries(config.issuers).map(
                            ([name, issuer]) => html`
                              <div class="issuer-card">
                                <div class="issuer-name">${name}</div>
                                <div class="issuer-details">
                                  <div class="config-item">
                                    <div class="config-label">URL</div>
                                    <div class="config-value">${issuer.url}</div>
                                  </div>
                                  <div class="config-item">
                                    <div class="config-label">Enabled</div>
                                    <div class="config-value">${issuer.enabled ? 'Yes' : 'No'}</div>
                                  </div>
                                </div>
                              </div>
                            `
                          )}
                        </div>
                      `
                    : html` <div class="no-issuers">No issuers configured</div> `}
                </div>
              `
            : ''}
          ${config.message
            ? html`
                <div class="config-section info-section">
                  <div class="info-message">${config.message}</div>
                </div>
              `
            : ''}
        </div>
      </div>
    `;
  }
}

describe('QwcJwtConfig', () => {
  let component;
  let container;

  beforeEach(async () => {
    // Reset all mocks
    resetDevUIMocks();

    // Create container
    container = document.createElement('div');
    document.body.append(container);

    // Create component
    component = new QwcJwtConfig();
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
      expect(component._configuration).toBeNull();
      expect(component._loading).toBe(true);
      expect(component._error).toBeNull();
    });

    it('should be defined as custom element', () => {
      const tagName = `qwc-jwt-config-test-${Date.now()}`;
      if (!customElements.get(tagName)) {
        customElements.define(tagName, QwcJwtConfig);
      }
      expect('').toBeDefinedAsCustomElement(tagName);
    });

    it('should call getConfiguration on connection', async () => {
      // Create a new component and connect it to trigger lifecycle
      const testComponent = new QwcJwtConfig();

      // Clear previous calls
      devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockClear();

      await testComponent.connectedCallback();
      await waitForComponentUpdate(testComponent);

      expect(devui.jsonRPC.CuiJwtDevUI.getConfiguration).toHaveBeenCalled();
    });
  });

  describe('Loading State', () => {
    it('should show loading message initially', async () => {
      // Reset component to initial state
      component._configuration = null;
      component._loading = true;
      component._error = null;
      component.render(); // Manually trigger render to update _lastRenderedResult
      await waitForComponentUpdate(component);

      expect(component).toHaveRenderedContent('Loading JWT configuration...');
    });

    it('should have loading class when loading', async () => {
      component._configuration = null;
      component._loading = true;
      component._error = null;
      component.render(); // Manually trigger render to update _lastRenderedResult
      await waitForComponentUpdate(component);

      expect(component).toHaveShadowClass('loading');
    });
  });

  describe('Error State', () => {
    beforeEach(async () => {
      // Setup error scenario
      const networkError = new Error('Network error');
      devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockRejectedValue(networkError);
      component._error = 'Failed to load configuration: Network error';
      component._loading = false;
      await waitForComponentUpdate(component);
    });

    it('should display error message', async () => {
      component.render(); // Manually trigger render to update _lastRenderedResult
      expect(component).toHaveRenderedContent('Failed to load configuration: Network error');
    });

    it('should have error class when error occurs', async () => {
      component.render(); // Manually trigger render to update _lastRenderedResult
      expect(component).toHaveShadowClass('error');
    });

    it('should show retry button in error state', async () => {
      component.render(); // Manually trigger render to update _lastRenderedResult
      expect(component).toHaveRenderedContent('Retry');
    });

    it('should retry loading when retry button is clicked', async () => {
      // Reset mock to success
      resetDevUIMocks();

      // Directly call refresh method
      component._refreshConfiguration();
      await waitForComponentUpdate(component);

      expect(devui.jsonRPC.CuiJwtDevUI.getConfiguration).toHaveBeenCalled();
    });
  });

  describe('Build Time Configuration Display', () => {
    beforeEach(async () => {
      // Reset mocks to default build time scenario
      resetDevUIMocks();
      await component._loadConfiguration();
      await waitForComponentUpdate(component);
    });

    it('should display build time configuration correctly', async () => {
      component.render(); // Manually trigger render to update _lastRenderedResult
      expect(component).toHaveRenderedContent('Configuration details will be available at runtime');
    });

    it('should render config container structure', async () => {
      component.render(); // Manually trigger render to update _lastRenderedResult
      expect(component).toHaveShadowClass('config-container');
      expect(component).toHaveShadowClass('config-header');
      expect(component).toHaveShadowClass('config-title');
    });

    it('should display general configuration section', async () => {
      component.render(); // Manually trigger render to update _lastRenderedResult
      expect(component).toHaveRenderedContent('General Configuration');
      expect(component).toHaveRenderedContent('JWT Validation Enabled');
      expect(component).toHaveRenderedContent('Health Checks Enabled');
    });

    it('should show disabled status for build time', async () => {
      component.render();
      expect(component).toHaveShadowClass('disabled');
    });

    it('should show build time indicator', async () => {
      component.render();
      expect(component).toHaveShadowClass('build-time');
    });
  });

  describe('Runtime Configuration Display', () => {
    beforeEach(async () => {
      // Setup runtime configuration
      devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockResolvedValue({
        enabled: true,
        healthEnabled: true,
        buildTime: false,
        parser: {
          maxTokenSizeBytes: 8192,
          leewaySeconds: 30,
          validateExpiration: true,
          validateNotBefore: false,
          validateIssuedAt: false,
          allowedAlgorithms: 'RS256,RS384,RS512',
        },
        health: {
          enabled: true,
          jwks: {
            cacheSeconds: 30,
            timeoutSeconds: 5,
          },
        },
        issuers: {
          keycloak: {
            url: 'https://keycloak.example.com/auth/realms/master',
            enabled: true,
          },
          auth0: {
            url: 'https://auth0.example.com',
            enabled: false,
          },
        },
      });

      await component._loadConfiguration();
      await waitForComponentUpdate(component);
    });

    it('should display enabled configuration correctly', async () => {
      component.render();
      expect(component).toHaveRenderedContent('JWT Validation Enabled');
      expect(component).toHaveShadowClass('enabled');
    });

    it('should display parser configuration section', async () => {
      component.render();
      expect(component).toHaveRenderedContent('Parser Configuration');
      expect(component).toHaveRenderedContent('Max Token Size');
      expect(component).toHaveRenderedContent('8192 bytes');
      expect(component).toHaveRenderedContent('Clock Leeway');
      expect(component).toHaveRenderedContent('30 seconds');
      expect(component).toHaveRenderedContent('Validate Expiration');
      expect(component).toHaveRenderedContent('Allowed Algorithms');
      expect(component).toHaveRenderedContent('RS256,RS384,RS512');
    });

    it('should display health check configuration section', async () => {
      component.render();
      expect(component).toHaveRenderedContent('Health Check Configuration');
      expect(component).toHaveRenderedContent('JWKS Health Cache');
      expect(component).toHaveRenderedContent('JWKS Health Timeout');
    });

    it('should display issuer configuration section', async () => {
      component.render();
      expect(component).toHaveRenderedContent('Issuer Configuration');
      expect(component).toHaveRenderedContent('keycloak');
      expect(component).toHaveRenderedContent('auth0');
      expect(component).toHaveRenderedContent('https://keycloak.example.com/auth/realms/master');
      expect(component).toHaveRenderedContent('https://auth0.example.com');
    });

    it('should show issuer cards in grid layout', async () => {
      component.render();
      expect(component).toHaveShadowClass('issuer-card');
    });

    it('should display issuer enabled/disabled status', async () => {
      component.render();
      expect(component).toHaveRenderedContent('Yes'); // keycloak enabled
      expect(component).toHaveRenderedContent('No'); // auth0 disabled
    });
  });

  describe('Empty Configuration Display', () => {
    beforeEach(async () => {
      // Setup empty configuration
      devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockResolvedValue({
        enabled: false,
        healthEnabled: false,
        issuers: {},
      });

      await component._loadConfiguration();
      await waitForComponentUpdate(component);
    });

    it('should display no issuers message when empty', async () => {
      component.render();
      expect(component).toHaveRenderedContent('No issuers configured');
      expect(component).toHaveShadowClass('no-issuers');
    });
  });

  describe('Refresh Functionality', () => {
    beforeEach(async () => {
      // Reset mocks to default build time scenario to ensure consistent state
      resetDevUIMocks();
      await component._loadConfiguration();
      await waitForComponentUpdate(component);
    });

    it('should have refresh button', async () => {
      component.render(); // Manually trigger render to update _lastRenderedResult
      expect(component).toHaveRenderedContent('Refresh');
    });

    it('should reload configuration when refresh button is clicked', async () => {
      await waitForComponentUpdate(component);

      // Clear previous calls
      devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockClear();

      // Directly call refresh method
      component._refreshConfiguration();
      await waitForComponentUpdate(component);

      expect(devui.jsonRPC.CuiJwtDevUI.getConfiguration).toHaveBeenCalled();
    });
  });

  describe('Component Lifecycle', () => {
    it('should load configuration on connected callback', async () => {
      const newComponent = new QwcJwtConfig();

      // Clear previous calls
      devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockClear();

      // Connect component
      newComponent.connectedCallback();
      await waitForComponentUpdate(newComponent);

      expect(devui.jsonRPC.CuiJwtDevUI.getConfiguration).toHaveBeenCalled();
    });

    it('should handle component properties correctly', () => {
      expect(QwcJwtConfig.properties).toBeDefined();
      expect(QwcJwtConfig.properties._configuration).toEqual({ state: true });
      expect(QwcJwtConfig.properties._loading).toEqual({ state: true });
      expect(QwcJwtConfig.properties._error).toEqual({ state: true });
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors gracefully', async () => {
      // Setup network error
      const networkError = new Error('Network error');
      devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockRejectedValue(networkError);

      await component._loadConfiguration();
      await waitForComponentUpdate(component);

      expect(component._error).toContain('Failed to load configuration: Network error');
      expect(component._loading).toBe(false);
    });

    it('should log errors to console', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const networkError = new Error('Test error');
      devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockRejectedValue(networkError);

      await component._loadConfiguration();

      expect(consoleSpy).toHaveBeenCalledWith('Error loading configuration:', networkError);

      consoleSpy.mockRestore();
    });
  });

  describe('Configuration Sections Rendering', () => {
    beforeEach(async () => {
      // Reset mocks to default build time scenario to ensure consistent state
      resetDevUIMocks();
      await component._loadConfiguration();
      await waitForComponentUpdate(component);
    });

    it('should render config sections structure', async () => {
      component.render();

      expect(component).toHaveShadowClass('config-sections');
      expect(component).toHaveShadowClass('config-section');
    });

    it('should render section titles', async () => {
      component.render();

      expect(component).toHaveRenderedContent('General Configuration');
    });

    it('should render config grid layout', async () => {
      component.render();

      expect(component).toHaveShadowClass('config-grid');
    });

    it('should render info section when message is present', async () => {
      component.render();

      expect(component).toHaveShadowClass('info-section');
      expect(component).toHaveShadowClass('info-message');
    });
  });

  describe('CSS Classes and Styling', () => {
    it('should apply appropriate CSS classes for enabled/disabled states', async () => {
      // Mock enabled configuration
      devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockResolvedValue({
        enabled: true,
        healthEnabled: false,
        buildTime: false,
      });

      await component._loadConfiguration();
      await waitForComponentUpdate(component);
      component.render();

      expect(component).toHaveShadowClass('enabled');
      expect(component).toHaveShadowClass('disabled');
    });

    it('should apply algorithms class for algorithm display', async () => {
      devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockResolvedValue({
        enabled: true,
        parser: {
          allowedAlgorithms: 'RS256,ES256',
        },
      });

      await component._loadConfiguration();
      await waitForComponentUpdate(component);
      component.render();

      expect(component).toHaveShadowClass('algorithms');
    });
  });

  describe('Edge Cases and Additional Coverage', () => {
    it('should handle empty configuration object', () => {
      component._loading = false;
      component._configuration = {};
      component.render();
      expect(component).toHaveRenderedContent('JWT Configuration');
    });

    it('should handle configuration with null values', () => {
      component._loading = false;
      component._configuration = {
        enabled: null,
        healthEnabled: null,
        algorithms: null,
      };
      component.render();
      expect(component).toHaveRenderedContent('JWT Configuration');
    });

    it('should handle configuration with empty strings', () => {
      component._loading = false;
      component._configuration = {
        enabled: '',
        logLevel: '',
        algorithms: [],
      };
      component.render();
      expect(component).toHaveRenderedContent('JWT Configuration');
    });

    it('should handle issuers configuration edge cases', () => {
      component._loading = false;
      component._configuration = {
        enabled: true,
        issuers: {
          'test-issuer': {
            issuerUri: null,
            algorithms: [],
            clockSkew: 0,
          },
        },
      };
      component.render();
      expect(component).toHaveRenderedContent('test-issuer');
    });

    it('should handle refresh without error', () => {
      resetDevUIMocks();
      component._refreshConfiguration();
      expect(devui.jsonRPC.CuiJwtDevUI.getConfiguration).toHaveBeenCalled();
    });
  });
});
