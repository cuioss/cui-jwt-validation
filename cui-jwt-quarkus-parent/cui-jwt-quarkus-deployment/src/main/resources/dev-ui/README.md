# CUI JWT DevUI Integration

This directory contains the implementation of Quarkus DevUI integration for the
CUI JWT validation extension.

## Project Structure

```
dev-ui/
├── components/           # Web Components (JavaScript/Lit)
│   ├── qwc-jwt-validation-status.js  # JWT validation status monitoring
│   ├── qwc-jwks-endpoints.js         # JWKS endpoint status and monitoring
│   ├── qwc-jwt-debugger.js           # Token validation and debugging tools
│   └── qwc-jwt-config.js             # Configuration viewer
└── README.md            # This documentation
```

### Backend Services

- `CuiJwtDevUIJsonRPCService.java` - JSON-RPC service for runtime data access
- `CuiJwtProcessor.java` - DevUI build steps and card page registration

### Build Configuration

- DevUI build steps are implemented in `CuiJwtProcessor.java`
- Component links automatically resolve from `components/` subdirectory

## Activation Status

**✅ FULLY ACTIVATED** - DevUI integration is complete and operational.

### Dependencies

- `quarkus-vertx-http-dev-ui-spi` - Added to deployment module
- DevUI build steps registered in `CuiJwtProcessor.java`
- JSON-RPC service provider configured

### Configuration

- All required configuration interfaces implemented in `JwtValidationConfig`
- Component paths correctly configured for new directory structure
- Build-time and runtime data access properly integrated

## Features

### JWT Validation Status

- Real-time validation status monitoring
- Security event statistics
- Validator availability indicator

### JWKS Endpoint Monitoring

- Endpoint connectivity status
- Key refresh statistics
- Configuration validation

### Token Debugger

- Token validation testing
- Claims visualization
- Error diagnosis

### Configuration Viewer

- Complete configuration display
- Health status indicators
- Issue detection

## Usage

Once activated, the DevUI components will be available in the Quarkus Dev UI at:
`http://localhost:8080/q/dev-ui/`

Look for the "CUI JWT" card with the following pages:

- JWT Validation Status
- JWKS Endpoints
- Token Debugger
- Configuration

## Implementation Notes

- All DevUI components run only in development mode
- Web components use Lit Element for reactive UI
- JSON-RPC provides backend data access
- Components auto-refresh for real-time monitoring
- Security-conscious - no sensitive data exposure
