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
package de.cuioss.jwt.validation.security;

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for validating protection against embedded JWK attacks.
 * <p>
 * The embedded JWK attack (CVE-2018-0114) is a security vulnerability where
 * attackers include their own public key in the token header to bypass signature
 * verification.
 * <p>
 * This test verifies that the library correctly rejects tokens with embedded JWK
 * headers.
 */
@EnableTestLogger
@DisplayName("Tests for Embedded JWK Attack Protection")
class EmbeddedJwkAttackTest {

    private static final CuiLogger LOGGER = new CuiLogger(EmbeddedJwkAttackTest.class);

    private TokenValidator tokenValidator;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {
        // Create issuer config with JWKS content
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer("Token-Test-testIssuer")
                .expectedAudience("test-client")
                .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                .build();

        // Initialize security event counter
        securityEventCounter = new SecurityEventCounter();
        issuerConfig.initSecurityEventCounter(securityEventCounter);

        // Create validation factory
        ParserConfig config = ParserConfig.builder().build();
        tokenValidator = new TokenValidator(config, issuerConfig);
    }

    @Test
    @DisplayName("Should reject tokens with embedded JWK in header")
    void shouldRejectTokenWithEmbeddedJwk() {
        // Generate a valid token
        String validToken = TestTokenGenerators.accessTokens().next().getRawToken();

        // Split the token into its parts
        String[] parts = validToken.split("\\.");

        // Decode the header
        String header = parts[0];
        byte[] headerBytes = Base64.getUrlDecoder().decode(header);
        String headerJson = new String(headerBytes);

        // Modify the header to include an embedded JWK
        String embeddedJwk = "\"jwk\":{\"kty\":\"RSA\",\"n\":\"attackerModulus\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"attacker-key\"}";
        String tamperedHeaderJson = headerJson.substring(0, headerJson.length() - 1) + "," + embeddedJwk + "}";

        // Encode the tampered header
        String tamperedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(tamperedHeaderJson.getBytes());

        // Reconstruct the token (without signature since it would be invalid)
        String tamperedToken = tamperedHeader + "." + parts[1] + ".";

        LOGGER.debug("Created token with embedded JWK: %s", tamperedToken);

        // Verify that the token is rejected
        var exception = assertThrows(TokenValidationException.class, 
                () -> tokenValidator.createAccessToken(tamperedToken));

        // Verify the exception details
        LOGGER.debug("Exception message: %s", exception.getMessage());

        // Verify that the security event counter was incremented
        assertTrue(securityEventCounter.getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED) > 0 ||
                   securityEventCounter.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM) > 0,
                "Security event counter should be incremented for embedded JWK attack");
    }
}
