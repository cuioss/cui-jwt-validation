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
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for validating protection against JKU/X5U header abuse attacks.
 * <p>
 * This attack allows attackers to host their own key sets and instruct the token
 * validator to fetch and trust those keys by including JKU (JWK Set URL) or X5U
 * (X.509 URL) headers pointing to attacker-controlled URLs.
 * <p>
 * This test verifies that the library correctly rejects tokens with JKU or X5U
 * headers pointing to malicious URLs.
 */
@EnableTestLogger
@DisplayName("Tests for JKU/X5U Header Abuse Protection")
class JkuX5uAttackTest {

    private static final CuiLogger LOGGER = new CuiLogger(JkuX5uAttackTest.class);

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

        // Create validation factory
        ParserConfig config = ParserConfig.builder().build();
        tokenValidator = new TokenValidator(config, issuerConfig);

        // Get the security event counter from the TokenValidator
        securityEventCounter = tokenValidator.getSecurityEventCounter();
    }

    @Test
    @DisplayName("Should reject tokens with JKU header pointing to malicious URL")
    void shouldRejectTokenWithJkuHeader() {
        // Log initial counter state
        LOGGER.debug("Initial SIGNATURE_VALIDATION_FAILED count: %s",
                securityEventCounter.getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED));
        LOGGER.debug("Initial UNSUPPORTED_ALGORITHM count: %s",
                securityEventCounter.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM));

        // Generate a valid token
        String validToken = TestTokenGenerators.accessTokens().next().getRawToken();

        // Split the token into its parts
        String[] parts = validToken.split("\\.");

        // Decode the header
        String header = parts[0];
        byte[] headerBytes = Base64.getUrlDecoder().decode(header);
        String headerJson = new String(headerBytes);

        // Modify the header to include a JKU header pointing to a malicious URL
        String maliciousJku = "\"jku\":\"https://attacker-controlled-site.com/jwks.json\"";
        String tamperedHeaderJson = headerJson.substring(0, headerJson.length() - 1) + "," + maliciousJku + "}";

        // Encode the tampered header
        String tamperedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(tamperedHeaderJson.getBytes());

        // Reconstruct the token with the original signature
        String tamperedToken = tamperedHeader + "." + parts[1] + "." + parts[2];

        LOGGER.debug("Created token with malicious JKU header: %s", tamperedToken);

        // Verify that the token is rejected
        var exception = assertThrows(TokenValidationException.class,
                () -> tokenValidator.createAccessToken(tamperedToken));

        // Verify the exception details
        LOGGER.debug("Exception message: %s", exception.getMessage());

        // Log the security event counter values
        LOGGER.debug("Final SIGNATURE_VALIDATION_FAILED count: %s",
                securityEventCounter.getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED));
        LOGGER.debug("Final UNSUPPORTED_ALGORITHM count: %s",
                securityEventCounter.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM));

        // Log all counter values
        securityEventCounter.getCounters().forEach((type, count) ->
                LOGGER.debug("Counter %s: %s", type, count));

        // Verify that the security event counter was incremented
        assertTrue(securityEventCounter.getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED) > 0 ||
                securityEventCounter.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM) > 0,
                "Security event counter should be incremented for JKU header attack");
    }

    @Test
    @DisplayName("Should reject tokens with X5U header pointing to malicious URL")
    void shouldRejectTokenWithX5uHeader() {
        // Log initial counter state
        LOGGER.debug("Initial SIGNATURE_VALIDATION_FAILED count: %s",
                securityEventCounter.getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED));
        LOGGER.debug("Initial UNSUPPORTED_ALGORITHM count: %s",
                securityEventCounter.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM));

        // Generate a valid token
        String validToken = TestTokenGenerators.accessTokens().next().getRawToken();

        // Split the token into its parts
        String[] parts = validToken.split("\\.");

        // Decode the header
        String header = parts[0];
        byte[] headerBytes = Base64.getUrlDecoder().decode(header);
        String headerJson = new String(headerBytes);

        // Modify the header to include an X5U header pointing to a malicious URL
        String maliciousX5u = "\"x5u\":\"https://attacker-controlled-site.com/keys.pem\"";
        String tamperedHeaderJson = headerJson.substring(0, headerJson.length() - 1) + "," + maliciousX5u + "}";

        // Encode the tampered header
        String tamperedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(tamperedHeaderJson.getBytes());

        // Reconstruct the token with the original signature
        String tamperedToken = tamperedHeader + "." + parts[1] + "." + parts[2];

        LOGGER.debug("Created token with malicious X5U header: %s", tamperedToken);

        // Verify that the token is rejected
        var exception = assertThrows(TokenValidationException.class,
                () -> tokenValidator.createAccessToken(tamperedToken));

        // Verify the exception details
        LOGGER.debug("Exception message: %s", exception.getMessage());

        // Log the security event counter values
        LOGGER.debug("Final SIGNATURE_VALIDATION_FAILED count: %s",
                securityEventCounter.getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED));
        LOGGER.debug("Final UNSUPPORTED_ALGORITHM count: %s",
                securityEventCounter.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM));

        // Log all counter values
        securityEventCounter.getCounters().forEach((type, count) ->
                LOGGER.debug("Counter %s: %s", type, count));

        // Verify that the security event counter was incremented
        assertTrue(securityEventCounter.getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED) > 0 ||
                securityEventCounter.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM) > 0,
                "Security event counter should be incremented for X5U header attack");
    }
}