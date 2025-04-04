/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.token;

import de.cuioss.jwt.token.jwks.JwksLoader;
import de.cuioss.jwt.token.jwks.JwksLoaderFactory;
import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.jwt.token.test.generator.IDTokenGenerator;
import de.cuioss.jwt.token.util.NonValidatingJwtParser;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the client confusion attack prevention feature.
 */
class ClientConfusionAttackTest {
    
    private static final CuiLogger LOGGER = new CuiLogger(ClientConfusionAttackTest.class);

    /**
     * The JWKS loader used for testing.
     */
    private JwksLoader jwksLoader;

    /**
     * Set up the test environment.
     */
    @BeforeEach
    void setUp() {
        // Use the JWKSFactory to create a proper JWKS document with the default key ID
        String jwksContent = JWKSFactory.createDefaultJwks();
        jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent);
        
        // Print the JWKS content for debugging
        LOGGER.debug("JWKS content: " + jwksContent);
    }

    @Test
    @DisplayName("Token with valid azp claim should be accepted")
    void verify_azp_validation() {
        // Generate a token with the default client ID
        String token = new IDTokenGenerator(false).next();
        LOGGER.debug("Token: " + token);
        
        // Print the token headers using NonValidatingJwtParser to debug
        try {
            var decoder = NonValidatingJwtParser.builder().build();
            var decoded = decoder.decode(token);
            decoded.ifPresent(jwt -> {
                LOGGER.debug("Token headers: " + jwt.getHeader().orElse(null));
                LOGGER.debug("Token kid: " + jwt.getKid().orElse("null"));
                LOGGER.debug("Token body: " + jwt.getBody().orElse(null));
            });
        } catch (Exception e) {
            System.err.println("Error decoding token: " + e.getMessage());
        }

        // Create a parser with the correct client ID
        var parser = JwksAwareTokenParserImpl.builder()
                .jwksLoader(jwksLoader)
                .issuer(TestTokenProducer.ISSUER)
                .expectedAudience(Set.of(IDTokenGenerator.DEFAULT_CLIENT_ID))
                .expectedClientId(IDTokenGenerator.DEFAULT_CLIENT_ID)
                .build();

        // Verify the token is accepted
        Optional<?> result = parser.parseToken(token); // Use parseToken instead of parse
        assertTrue(result.isPresent(), "Token with valid azp claim should be accepted");
    }

    @Test
    @DisplayName("Token with invalid azp claim should be rejected")
    void verify_azp_validation_failure() {
        // Generate a token with the default client ID
        String token = new IDTokenGenerator(false).next();

        // Create a parser with an incorrect client ID
        var parser = JwksAwareTokenParserImpl.builder()
                .jwksLoader(jwksLoader)
                .issuer(TestTokenProducer.ISSUER)
                .expectedAudience(Set.of(IDTokenGenerator.DEFAULT_CLIENT_ID))
                .expectedClientId("wrong-client-id")
                .build();

        // Verify the token is rejected
        Optional<?> result = parser.parseToken(token);
        assertTrue(result.isEmpty(), "Token with invalid azp claim should be rejected");
    }

    @Test
    @DisplayName("Token from a different client should be rejected")
    void verify_different_client_token_rejected() {
        // Generate a token with the alternative client ID
        String token = new IDTokenGenerator(true).next();

        // Create a parser with the default client ID
        var parser = JwksAwareTokenParserImpl.builder()
                .jwksLoader(jwksLoader)
                .issuer(TestTokenProducer.ISSUER)
                .expectedAudience(Set.of(IDTokenGenerator.DEFAULT_CLIENT_ID))
                .expectedClientId(IDTokenGenerator.DEFAULT_CLIENT_ID)
                .build();

        // Verify the token is rejected
        Optional<?> result = parser.parseToken(token);
        assertTrue(result.isEmpty(), "Token from a different client should be rejected");
    }

    @Test
    @DisplayName("Audience validation without azp validation should work")
    void verify_audience_validation_without_azp() {
        // Generate a token with the default client ID
        String token = new IDTokenGenerator(false).next();

        // Create a parser with the correct audience but no client ID
        var parser = JwksAwareTokenParserImpl.builder()
                .jwksLoader(jwksLoader)
                .issuer(TestTokenProducer.ISSUER)
                .expectedAudience(Set.of(IDTokenGenerator.DEFAULT_CLIENT_ID))
                .build();

        // Verify the token is accepted
        Optional<?> result = parser.parseToken(token);
        assertTrue(result.isPresent(), "Token with valid audience should be accepted");
    }

    @Test
    @DisplayName("AZP validation without audience validation should work")
    void verify_azp_validation_without_audience() {
        // Generate a token with the default client ID
        String token = new IDTokenGenerator(false).next();

        // Create a parser with the correct client ID but no audience
        var parser = JwksAwareTokenParserImpl.builder()
                .jwksLoader(jwksLoader)
                .issuer(TestTokenProducer.ISSUER)
                .expectedClientId(IDTokenGenerator.DEFAULT_CLIENT_ID)
                .build();

        // Verify the token is accepted
        Optional<?> result = parser.parseToken(token);
        assertTrue(result.isPresent(), "Token with valid azp should be accepted");
    }

    @Test
    @DisplayName("Token with missing azp claim should be rejected when validation is enabled")
    void verify_missing_azp_rejected() {
        // Generate a token with a specific client ID that has no azp claim
        String token = new IDTokenGenerator(false, null).next();

        // Create a parser that requires azp validation
        var parser = JwksAwareTokenParserImpl.builder()
                .jwksLoader(jwksLoader)
                .issuer(TestTokenProducer.ISSUER)
                .expectedClientId(IDTokenGenerator.DEFAULT_CLIENT_ID)
                .build();

        // Verify the token is rejected
        Optional<?> result = parser.parseToken(token);
        assertTrue(result.isEmpty(), "Token with missing azp claim should be rejected");
    }
}