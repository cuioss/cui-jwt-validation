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
import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link IssuerConfigFactory}.
 */
@EnableTestLogger
@ExtendWith(MockitoExtension.class)
class IssuerConfigFactoryTest {

    private static final String ISSUER_URL = "https://example.com/auth";
    private static final String JWKS_URL = "https://example.com/auth/jwks.json";
    private static final String PUBLIC_KEY_LOCATION = "classpath:keys/public_key.pem";
    private static final String AUDIENCE = "test-audience";

    @Mock
    private JwtValidationConfig.IssuerConfig issuerConfig;

    @Mock
    private JwtValidationConfig.ParserConfig parserConfig;

    @Mock
    private JwtValidationConfig.HttpJwksLoaderConfig jwksConfig;

    /**
     * Test creating issuer configs with JWKS configuration.
     */
    @Test
    @DisplayName("Should create issuer configs with JWKS configuration")
    void shouldCreateIssuerConfigsWithJwks() {
        // Arrange
        Map<String, JwtValidationConfig.IssuerConfig> issuersConfig = new HashMap<>();
        issuersConfig.put("test-issuer", issuerConfig);

        lenient().when(issuerConfig.enabled()).thenReturn(true);
        lenient().when(issuerConfig.url()).thenReturn(ISSUER_URL);
        lenient().when(issuerConfig.jwks()).thenReturn(Optional.of(jwksConfig));
        lenient().when(issuerConfig.publicKeyLocation()).thenReturn(Optional.empty());
        lenient().when(issuerConfig.parser()).thenReturn(Optional.of(parserConfig));
        lenient().when(parserConfig.audience()).thenReturn(Optional.of(AUDIENCE));
        lenient().when(jwksConfig.url()).thenReturn(JWKS_URL);
        lenient().when(jwksConfig.refreshIntervalSeconds()).thenReturn(300);
        lenient().when(jwksConfig.readTimeoutMs()).thenReturn(5000);

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
        issuersConfig.put("test-issuer", issuerConfig);

        lenient().when(issuerConfig.enabled()).thenReturn(true);
        lenient().when(issuerConfig.url()).thenReturn(ISSUER_URL);
        lenient().when(issuerConfig.jwks()).thenReturn(Optional.empty());
        lenient().when(issuerConfig.publicKeyLocation()).thenReturn(Optional.of(PUBLIC_KEY_LOCATION));
        lenient().when(issuerConfig.parser()).thenReturn(Optional.empty());

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
        issuersConfig.put("test-issuer", issuerConfig);

        lenient().when(issuerConfig.enabled()).thenReturn(false);

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
        issuersConfig.put("test-issuer", issuerConfig);

        lenient().when(issuerConfig.enabled()).thenReturn(true);
        lenient().when(issuerConfig.url()).thenReturn(ISSUER_URL);
        lenient().when(issuerConfig.jwks()).thenReturn(Optional.empty());
        lenient().when(issuerConfig.publicKeyLocation()).thenReturn(Optional.empty());

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
        JwtValidationConfig.IssuerConfig issuer1 = mock(JwtValidationConfig.IssuerConfig.class);
        JwtValidationConfig.HttpJwksLoaderConfig jwks1 = mock(JwtValidationConfig.HttpJwksLoaderConfig.class);

        // Configure issuer1
        lenient().when(issuer1.enabled()).thenReturn(true);
        lenient().when(issuer1.url()).thenReturn("https://issuer1.example.com");
        lenient().when(issuer1.jwks()).thenReturn(Optional.of(jwks1));
        lenient().when(issuer1.publicKeyLocation()).thenReturn(Optional.empty());
        lenient().when(issuer1.parser()).thenReturn(Optional.empty());

        // Configure jwks1
        lenient().when(jwks1.url()).thenReturn("https://issuer1.example.com/jwks.json");
        lenient().when(jwks1.refreshIntervalSeconds()).thenReturn(300);
        lenient().when(jwks1.readTimeoutMs()).thenReturn(5000);

        // Second issuer with public key
        JwtValidationConfig.IssuerConfig issuer2 = mock(JwtValidationConfig.IssuerConfig.class);
        lenient().when(issuer2.enabled()).thenReturn(true);
        lenient().when(issuer2.url()).thenReturn("https://issuer2.example.com");
        lenient().when(issuer2.jwks()).thenReturn(Optional.empty());
        lenient().when(issuer2.publicKeyLocation()).thenReturn(Optional.of("classpath:keys/issuer2_key.pem"));
        lenient().when(issuer2.parser()).thenReturn(Optional.empty());

        // Third issuer disabled
        JwtValidationConfig.IssuerConfig issuer3 = mock(JwtValidationConfig.IssuerConfig.class);
        lenient().when(issuer3.enabled()).thenReturn(false);

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
