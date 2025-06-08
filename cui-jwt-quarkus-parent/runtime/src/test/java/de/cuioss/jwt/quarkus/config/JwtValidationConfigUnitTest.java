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
package de.cuioss.jwt.quarkus.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link JwtValidationConfig} using a manually created configuration.
 * This approach avoids the issues with ConfigMapping in tests by not using Quarkus CDI.
 */
@DisplayName("Tests JwtValidationConfig with manual configuration")
class JwtValidationConfigUnitTest {

    private JwtValidationConfig jwtConfig;

    @BeforeEach
    void setUp() {
        TestJwtValidationConfig testConfig = new TestJwtValidationConfig();
        jwtConfig = testConfig.createTestConfig();
    }

    @Test
    @DisplayName("Should load configuration with default values")
    void shouldLoadConfigWithDefaults() {
        // Assert
        assertNotNull(jwtConfig);
        assertNotNull(jwtConfig.issuers());
        assertTrue(jwtConfig.issuers().containsKey("default"));

        JwtValidationConfig.IssuerConfig issuerConfig = jwtConfig.issuers().get("default");
        assertEquals("https://example.com/auth", issuerConfig.url());
        assertTrue(issuerConfig.enabled());
        assertEquals(Optional.empty(), issuerConfig.publicKeyLocation());
        assertEquals(Optional.empty(), issuerConfig.jwks());

        JwtValidationConfig.ParserConfig parserConfig = jwtConfig.parser();
        assertNotNull(parserConfig);
        assertEquals(30, parserConfig.leewaySeconds());
        assertEquals(8192, parserConfig.maxTokenSizeBytes());
        assertTrue(parserConfig.validateNotBefore());
        assertTrue(parserConfig.validateExpiration());
        assertFalse(parserConfig.validateIssuedAt());
        assertEquals("RS256,RS384,RS512,ES256,ES384,ES512", parserConfig.allowedAlgorithms());
    }

    @Test
    @DisplayName("Should load keycloak configuration with custom values")
    void shouldLoadKeycloakConfig() {
        // Assert
        assertNotNull(jwtConfig);
        assertNotNull(jwtConfig.issuers());
        assertTrue(jwtConfig.issuers().containsKey("keycloak"));

        // Check issuer config
        JwtValidationConfig.IssuerConfig issuerConfig = jwtConfig.issuers().get("keycloak");
        assertEquals("https://keycloak.example.com/auth/realms/master", issuerConfig.url());
        assertTrue(issuerConfig.enabled());
        assertEquals(Optional.of("classpath:keys/public_key.pem"), issuerConfig.publicKeyLocation());

        // Check JWKS config
        assertTrue(issuerConfig.jwks().isPresent());
        JwtValidationConfig.HttpJwksLoaderConfig jwksConfig = issuerConfig.jwks().get();
        assertEquals("https://keycloak.example.com/auth/realms/master/protocol/openid-connect/certs", jwksConfig.url());
        assertEquals(7200, jwksConfig.cacheTtlSeconds());
        assertEquals(600, jwksConfig.refreshIntervalSeconds());
        assertEquals(3000, jwksConfig.connectionTimeoutMs());
        assertEquals(3000, jwksConfig.readTimeoutMs());
        assertEquals(5, jwksConfig.maxRetries());
        assertTrue(jwksConfig.useSystemProxy());

        // Check issuer-specific parser config
        assertTrue(issuerConfig.parser().isPresent());
        JwtValidationConfig.ParserConfig issuerParserConfig = issuerConfig.parser().get();
        assertEquals(Optional.of("my-app"), issuerParserConfig.audience());
        assertEquals(60, issuerParserConfig.leewaySeconds());
        assertEquals(16384, issuerParserConfig.maxTokenSizeBytes());
        assertFalse(issuerParserConfig.validateNotBefore());
        assertTrue(issuerParserConfig.validateExpiration());
        assertTrue(issuerParserConfig.validateIssuedAt());
        assertEquals("RS256,ES256", issuerParserConfig.allowedAlgorithms());
    }
}