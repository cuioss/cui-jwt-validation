/**
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.quarkus.producer;

import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.jwt.quarkus.producer.TestJwtValidationConfig.TestHttpJwksLoaderConfig;
import de.cuioss.jwt.quarkus.producer.TestJwtValidationConfig.TestIssuerConfig;
import de.cuioss.jwt.quarkus.producer.TestJwtValidationConfig.TestParserConfig;
import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link IssuerConfigFactory}.
 */
@EnableTestLogger
class IssuerConfigFactoryTest {

    private static final String ISSUER_URL = "https://example.com/auth";
    private static final String JWKS_URL = "https://example.com/auth/jwks.json";
    private static final String PUBLIC_KEY_LOCATION = "classpath:keys/public_key.pem";
    private static final String AUDIENCE = "test-audience";

    /**
     * Test creating issuer configs with JWKS configuration.
     */
    @Test
    @DisplayName("Should create issuer configs with JWKS configuration")
    void shouldCreateIssuerConfigsWithJwks() {
        // Arrange
        Map<String, JwtValidationConfig.IssuerConfig> issuersConfig = new HashMap<>();
        
        // Create test JWKS config
        TestHttpJwksLoaderConfig jwksConfig = new TestHttpJwksLoaderConfig()
                .withUrl(JWKS_URL)
                .withRefreshIntervalSeconds(300)
                .withReadTimeoutMs(5000);
        
        // Create test parser config
        TestParserConfig parserConfig = new TestParserConfig()
                .withAudience(AUDIENCE);
        
        // Create test issuer config
        TestIssuerConfig issuerConfig = new TestIssuerConfig()
                .withEnabled(true)
                .withUrl(ISSUER_URL)
                .withJwks(jwksConfig)
                .withPublicKeyLocation(null)
                .withParser(parserConfig);
        
        issuersConfig.put("test-issuer", issuerConfig);

        // Act
        List<IssuerConfig> result = IssuerConfigFactory.createIssuerConfigs(issuersConfig);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertEquals(1, result.size(), "Should create one issuer config");
        IssuerConfig config = result.get(0);
        assertEquals(ISSUER_URL, config.getIssuer(), "Issuer URL should match");
        assertTrue(config.getExpectedAudience().contains(AUDIENCE), "Audience should contain expected value");
    }

    /**
     * Test creating issuer configs with public key location.
     */
    @Test
    @DisplayName("Should create issuer configs with public key location")
    void shouldCreateIssuerConfigsWithPublicKey() {
        // Arrange
        Map<String, JwtValidationConfig.IssuerConfig> issuersConfig = new HashMap<>();
        
        // Create test issuer config with public key location
        TestIssuerConfig issuerConfig = new TestIssuerConfig()
                .withEnabled(true)
                .withUrl(ISSUER_URL)
                .withJwks(null)
                .withPublicKeyLocation(PUBLIC_KEY_LOCATION)
                .withParser(null);
        
        issuersConfig.put("test-issuer", issuerConfig);

        // Act
        List<IssuerConfig> result = IssuerConfigFactory.createIssuerConfigs(issuersConfig);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertEquals(1, result.size(), "Should create one issuer config");
        IssuerConfig config = result.get(0);
        assertEquals(ISSUER_URL, config.getIssuer(), "Issuer URL should match");
    }

    /**
     * Test creating issuer configs with disabled issuer.
     */
    @Test
    @DisplayName("Should skip disabled issuers")
    void shouldSkipDisabledIssuers() {
        // Arrange
        Map<String, JwtValidationConfig.IssuerConfig> issuersConfig = new HashMap<>();
        
        // Create test issuer config that is disabled
        TestIssuerConfig issuerConfig = new TestIssuerConfig()
                .withEnabled(false)
                .withUrl(ISSUER_URL);
        
        issuersConfig.put("test-issuer", issuerConfig);

        // Act
        List<IssuerConfig> result = IssuerConfigFactory.createIssuerConfigs(issuersConfig);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isEmpty(), "Result should be empty");
    }

    /**
     * Test creating issuer configs with no JWKS configuration.
     */
    @Test
    @DisplayName("Should throw exception when issuer has no JWKS configuration")
    void shouldThrowExceptionWhenNoJwksConfig() {
        // Arrange
        Map<String, JwtValidationConfig.IssuerConfig> issuersConfig = new HashMap<>();
        
        // Create test issuer config with no JWKS and no public key
        TestIssuerConfig issuerConfig = new TestIssuerConfig()
                .withEnabled(true)
                .withUrl(ISSUER_URL)
                .withJwks(null)
                .withPublicKeyLocation(null);
        
        issuersConfig.put("test-issuer", issuerConfig);

        // Act & Assert
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> IssuerConfigFactory.createIssuerConfigs(issuersConfig));

        assertTrue(exception.getMessage().contains("has no JWKS configuration"),
                "Exception message should mention missing JWKS configuration");
    }

    /**
     * Test creating issuer configs with multiple issuers.
     */
    @Test
    @DisplayName("Should create multiple issuer configs")
    void shouldCreateMultipleIssuerConfigs() {
        // Arrange
        Map<String, JwtValidationConfig.IssuerConfig> issuersConfig = new HashMap<>();

        // First issuer with JWKS
        TestHttpJwksLoaderConfig jwks1 = new TestHttpJwksLoaderConfig()
                .withUrl("https://issuer1.example.com/jwks.json")
                .withRefreshIntervalSeconds(300)
                .withReadTimeoutMs(5000);
        
        TestIssuerConfig issuer1 = new TestIssuerConfig()
                .withEnabled(true)
                .withUrl("https://issuer1.example.com")
                .withJwks(jwks1)
                .withPublicKeyLocation(null)
                .withParser(null);

        // Second issuer with public key
        TestIssuerConfig issuer2 = new TestIssuerConfig()
                .withEnabled(true)
                .withUrl("https://issuer2.example.com")
                .withJwks(null)
                .withPublicKeyLocation("classpath:keys/issuer2_key.pem")
                .withParser(null);

        // Third issuer disabled
        TestIssuerConfig issuer3 = new TestIssuerConfig()
                .withEnabled(false)
                .withUrl("https://issuer3.example.com");

        issuersConfig.put("issuer1", issuer1);
        issuersConfig.put("issuer2", issuer2);
        issuersConfig.put("issuer3", issuer3);

        // Act
        List<IssuerConfig> result = IssuerConfigFactory.createIssuerConfigs(issuersConfig);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertEquals(2, result.size(), "Should create two issuer configs");

        // Verify issuers are correctly configured
        assertTrue(result.stream().anyMatch(config -> "https://issuer1.example.com".equals(config.getIssuer())),
                "Should contain issuer1");
        assertTrue(result.stream().anyMatch(config -> "https://issuer2.example.com".equals(config.getIssuer())),
                "Should contain issuer2");
    }
}