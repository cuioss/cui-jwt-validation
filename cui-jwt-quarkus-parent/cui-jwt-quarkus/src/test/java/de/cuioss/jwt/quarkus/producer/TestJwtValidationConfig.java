package de.cuioss.jwt.quarkus.producer;

import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.jwt.quarkus.config.TestConfig;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Test implementation of {@link JwtValidationConfig} for use in unit tests.
 */
@ApplicationScoped
@TestConfig
public class TestJwtValidationConfig implements JwtValidationConfig {

    private final Map<String, IssuerConfig> issuers = new HashMap<>();
    private final ParserConfig parserConfig = new TestParserConfig();

    public TestJwtValidationConfig() {
        // Add default issuer to match test expectations
        issuers.put("default", new TestIssuerConfig()
                .withUrl("https://example.com/auth")
                .withEnabled(true)
                .withPublicKeyLocation(null)
                .withJwks(null));
        
        // Add keycloak issuer to match test expectations
        TestHttpJwksLoaderConfig keycloakJwksConfig = new TestHttpJwksLoaderConfig()
                .withUrl("https://keycloak.example.com/auth/realms/master/protocol/openid-connect/certs")
                .withCacheTtlSeconds(7200)
                .withRefreshIntervalSeconds(600)
                .withConnectionTimeoutMs(3000)
                .withReadTimeoutMs(3000)
                .withMaxRetries(5)
                .withUseSystemProxy(true);
                
        TestParserConfig keycloakParserConfig = new TestParserConfig()
                .withAudience("my-app")
                .withLeewaySeconds(60)
                .withMaxTokenSizeBytes(16384)
                .withValidateNotBefore(false)
                .withValidateExpiration(true)
                .withValidateIssuedAt(true)
                .withAllowedAlgorithms("RS256,ES256");
                
        issuers.put("keycloak", new TestIssuerConfig()
                .withUrl("https://keycloak.example.com/auth/realms/master")
                .withEnabled(true)
                .withPublicKeyLocation("classpath:keys/public_key.pem")
                .withJwks(keycloakJwksConfig)
                .withParser(keycloakParserConfig));
    }

    @Override
    public Map<String, IssuerConfig> issuers() {
        return issuers;
    }

    @Override
    public ParserConfig parser() {
        return parserConfig;
    }

    /**
     * Test implementation of {@link JwtValidationConfig.IssuerConfig}.
     */
    public static class TestIssuerConfig implements JwtValidationConfig.IssuerConfig {

        private String url = "https://test-issuer.example.com";
        private Optional<String> publicKeyLocation = Optional.empty();
        private Optional<HttpJwksLoaderConfig> jwks = Optional.of(new TestHttpJwksLoaderConfig());
        private Optional<ParserConfig> parser = Optional.empty();
        private boolean enabled = true;

        @Override
        public String url() {
            return url;
        }

        @Override
        public Optional<String> publicKeyLocation() {
            return publicKeyLocation;
        }

        @Override
        public Optional<HttpJwksLoaderConfig> jwks() {
            return jwks;
        }

        @Override
        public Optional<ParserConfig> parser() {
            return parser;
        }

        @Override
        public boolean enabled() {
            return enabled;
        }

        // Setters for test configuration
        public TestIssuerConfig withUrl(String url) {
            this.url = url;
            return this;
        }

        public TestIssuerConfig withPublicKeyLocation(String location) {
            this.publicKeyLocation = (location != null) ? Optional.of(location) : Optional.empty();
            return this;
        }

        public TestIssuerConfig withJwks(HttpJwksLoaderConfig jwks) {
            this.jwks = (jwks != null) ? Optional.of(jwks) : Optional.empty();
            return this;
        }

        public TestIssuerConfig withParser(ParserConfig parser) {
            this.parser = (parser != null) ? Optional.of(parser) : Optional.empty();
            return this;
        }

        public TestIssuerConfig withEnabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }
    }

    /**
     * Test implementation of {@link JwtValidationConfig.ParserConfig}.
     */
    public static class TestParserConfig implements JwtValidationConfig.ParserConfig {

        private Optional<String> audience = Optional.of("test-audience");
        private int leewaySeconds = 30;
        private int maxTokenSizeBytes = 8192;
        private boolean validateNotBefore = true;
        private boolean validateExpiration = true;
        private boolean validateIssuedAt = false;
        private String allowedAlgorithms = "RS256,RS384,RS512,ES256,ES384,ES512";

        @Override
        public Optional<String> audience() {
            return audience;
        }

        @Override
        public int leewaySeconds() {
            return leewaySeconds;
        }

        @Override
        public int maxTokenSizeBytes() {
            return maxTokenSizeBytes;
        }

        @Override
        public boolean validateNotBefore() {
            return validateNotBefore;
        }

        @Override
        public boolean validateExpiration() {
            return validateExpiration;
        }

        @Override
        public boolean validateIssuedAt() {
            return validateIssuedAt;
        }

        @Override
        public String allowedAlgorithms() {
            return allowedAlgorithms;
        }

        // Setters for test configuration
        public TestParserConfig withAudience(String audience) {
            this.audience = Optional.of(audience);
            return this;
        }

        public TestParserConfig withLeewaySeconds(int leewaySeconds) {
            this.leewaySeconds = leewaySeconds;
            return this;
        }

        public TestParserConfig withMaxTokenSizeBytes(int maxTokenSizeBytes) {
            this.maxTokenSizeBytes = maxTokenSizeBytes;
            return this;
        }

        public TestParserConfig withValidateNotBefore(boolean validateNotBefore) {
            this.validateNotBefore = validateNotBefore;
            return this;
        }

        public TestParserConfig withValidateExpiration(boolean validateExpiration) {
            this.validateExpiration = validateExpiration;
            return this;
        }

        public TestParserConfig withValidateIssuedAt(boolean validateIssuedAt) {
            this.validateIssuedAt = validateIssuedAt;
            return this;
        }

        public TestParserConfig withAllowedAlgorithms(String allowedAlgorithms) {
            this.allowedAlgorithms = allowedAlgorithms;
            return this;
        }
    }

    /**
     * Test implementation of {@link JwtValidationConfig.HttpJwksLoaderConfig}.
     */
    public static class TestHttpJwksLoaderConfig implements JwtValidationConfig.HttpJwksLoaderConfig {

        private String url = "https://test-issuer.example.com/.well-known/jwks.json";
        private int cacheTtlSeconds = 3600;
        private int refreshIntervalSeconds = 300;
        private int connectionTimeoutMs = 5000;
        private int readTimeoutMs = 5000;
        private int maxRetries = 3;
        private boolean useSystemProxy = false;

        @Override
        public String url() {
            return url;
        }

        @Override
        public int cacheTtlSeconds() {
            return cacheTtlSeconds;
        }

        @Override
        public int refreshIntervalSeconds() {
            return refreshIntervalSeconds;
        }

        @Override
        public int connectionTimeoutMs() {
            return connectionTimeoutMs;
        }

        @Override
        public int readTimeoutMs() {
            return readTimeoutMs;
        }

        @Override
        public int maxRetries() {
            return maxRetries;
        }

        @Override
        public boolean useSystemProxy() {
            return useSystemProxy;
        }

        // Setters for test configuration
        public TestHttpJwksLoaderConfig withUrl(String url) {
            this.url = url;
            return this;
        }

        public TestHttpJwksLoaderConfig withCacheTtlSeconds(int cacheTtlSeconds) {
            this.cacheTtlSeconds = cacheTtlSeconds;
            return this;
        }

        public TestHttpJwksLoaderConfig withRefreshIntervalSeconds(int refreshIntervalSeconds) {
            this.refreshIntervalSeconds = refreshIntervalSeconds;
            return this;
        }

        public TestHttpJwksLoaderConfig withConnectionTimeoutMs(int connectionTimeoutMs) {
            this.connectionTimeoutMs = connectionTimeoutMs;
            return this;
        }

        public TestHttpJwksLoaderConfig withReadTimeoutMs(int readTimeoutMs) {
            this.readTimeoutMs = readTimeoutMs;
            return this;
        }

        public TestHttpJwksLoaderConfig withMaxRetries(int maxRetries) {
            this.maxRetries = maxRetries;
            return this;
        }

        public TestHttpJwksLoaderConfig withUseSystemProxy(boolean useSystemProxy) {
            this.useSystemProxy = useSystemProxy;
            return this;
        }
    }
}