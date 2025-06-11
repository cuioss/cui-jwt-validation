# CUI JWT DevUI Integration

This directory contains the implementation of Quarkus DevUI integration for the
CUI JWT validation extension.

## Components

### Web Components (JavaScript)

- `qwc-jwt-validation-status.js` - JWT validation status monitoring
- `qwc-jwks-endpoints.js` - JWKS endpoint status and monitoring
- `qwc-jwt-debugger.js` - Token validation and debugging tools
- `qwc-jwt-config.js` - Configuration viewer

### Backend Services

- `CuiJwtDevUIJsonRPCService.java.template` - JSON-RPC service for runtime data
  (template)

### Build Configuration

- DevUI build steps are implemented in `CuiJwtProcessor.java` (currently
  commented out)

## Activation

To activate DevUI integration:

1. **Add DevUI Dependencies**:

   In `cui-jwt-quarkus-deployment/pom.xml`:

   ```xml
   <dependency>
       <groupId>io.quarkus</groupId>
       <artifactId>quarkus-devui-spi</artifactId>
       <version>${quarkus.version}</version>
   </dependency>
   ```

   In `cui-jwt-quarkus/pom.xml`:

   ```xml
   <dependency>
       <groupId>io.quarkus</groupId>
       <artifactId>quarkus-devui</artifactId>
       <version>${quarkus.version}</version>
       <scope>runtime</scope>
       <optional>true</optional>
   </dependency>
   ```

2. **Uncomment DevUI Code**:

   - Uncomment imports and build steps in `CuiJwtProcessor.java`
   - Rename `CuiJwtDevUIJsonRPCService.java.template` to
     `CuiJwtDevUIJsonRPCService.java`
   - Rename test files from `.template` back to `.java`

3. **Update Configuration Interface**: Ensure the following methods exist in
   `JwtValidationConfig`:
   - `enabled()`
   - `logLevel()`
   - `issuer()`
   - `parser()`
   - `httpJwksLoader()`

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
