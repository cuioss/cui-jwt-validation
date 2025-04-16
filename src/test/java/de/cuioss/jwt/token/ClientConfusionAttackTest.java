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

import de.cuioss.jwt.token.domain.token.IdTokenContent;
import de.cuioss.jwt.token.flow.IssuerConfig;
import de.cuioss.jwt.token.flow.NonValidatingJwtParser;
import de.cuioss.jwt.token.jwks.key.JWKSKeyLoader;
import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.jwt.token.test.generator.IDTokenGenerator;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the client confusion attack prevention feature.
 */
class ClientConfusionAttackTest {

    private static final CuiLogger LOGGER = new CuiLogger(ClientConfusionAttackTest.class);

    /**
     * The JWKS key loader used for testing.
     */
    private JWKSKeyLoader jwksKeyLoader;

    /**
     * The token factory used for testing.
     */
    private TokenFactory tokenFactory;

    /**
     * Set up the test environment.
     */
    @BeforeEach
    void setUp() {
        // Use the JWKSFactory to create a proper JWKS document with the default key ID
        String jwksContent = JWKSFactory.createDefaultJwks();
        jwksKeyLoader = new JWKSKeyLoader(jwksContent);

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

                // Add more detailed debugging for audience claim
                jwt.getBody().ifPresent(body -> {
                    if (body.containsKey("aud")) {
                        LOGGER.debug("[DEBUG_LOG] Audience claim found: " + body.get("aud"));
                        LOGGER.debug("[DEBUG_LOG] Audience claim type: " + body.get("aud").getValueType());
                    } else {
                        LOGGER.debug("[DEBUG_LOG] No audience claim found in token");
                    }

                    if (body.containsKey("azp")) {
                        LOGGER.debug("[DEBUG_LOG] AZP claim found: " + body.get("azp"));
                    } else {
                        LOGGER.debug("[DEBUG_LOG] No azp claim found in token");
                    }
                });
            });
        } catch (Exception e) {
            System.err.println("Error decoding token: " + e.getMessage());
        }

        // Create an IssuerConfig with the correct client ID
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(TestTokenProducer.ISSUER)
                .expectedAudience(IDTokenGenerator.DEFAULT_CLIENT_ID)
                .expectedClientId(IDTokenGenerator.DEFAULT_CLIENT_ID)
                .jwksKeyLoader(jwksKeyLoader)
                .build();

        LOGGER.debug("[DEBUG_LOG] IssuerConfig: issuer=" + issuerConfig.getIssuer() +
                     ", expectedAudience=" + issuerConfig.getExpectedAudience() +
                     ", expectedClientId=" + issuerConfig.getExpectedClientId());

        // Create a token factory with the issuer config
        tokenFactory = TokenFactory.builder()
                .issuerConfigs(List.of(issuerConfig))
                .build();

        // Verify the token is accepted
        Optional<IdTokenContent> result = tokenFactory.createIdToken(token);
        assertTrue(result.isPresent(), "Token with valid azp claim should be accepted");
    }

    @Test
    @DisplayName("Token with invalid azp claim should be rejected")
    void verify_azp_validation_failure() {
        // Generate a token with the default client ID
        String token = new IDTokenGenerator(false).next();

        // Create an IssuerConfig with an incorrect client ID
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(TestTokenProducer.ISSUER)
                .expectedAudience(IDTokenGenerator.DEFAULT_CLIENT_ID)
                .expectedClientId("wrong-client-id")
                .jwksKeyLoader(jwksKeyLoader)
                .build();

        // Create a token factory with the issuer config
        tokenFactory = TokenFactory.builder()
                .issuerConfigs(List.of(issuerConfig))
                .build();

        // Verify the token is rejected
        Optional<IdTokenContent> result = tokenFactory.createIdToken(token);
        assertTrue(result.isEmpty(), "Token with invalid azp claim should be rejected");
    }

    @Test
    @DisplayName("Token from a different client should be rejected")
    void verify_different_client_token_rejected() {
        // Generate a token with the alternative client ID
        String token = new IDTokenGenerator(true).next();

        // Create an IssuerConfig with the default client ID
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(TestTokenProducer.ISSUER)
                .expectedAudience(IDTokenGenerator.DEFAULT_CLIENT_ID)
                .expectedClientId(IDTokenGenerator.DEFAULT_CLIENT_ID)
                .jwksKeyLoader(jwksKeyLoader)
                .build();

        // Create a token factory with the issuer config
        tokenFactory = TokenFactory.builder()
                .issuerConfigs(List.of(issuerConfig))
                .build();

        // Verify the token is rejected
        Optional<IdTokenContent> result = tokenFactory.createIdToken(token);
        assertTrue(result.isEmpty(), "Token from a different client should be rejected");
    }

    @Test
    @DisplayName("Audience validation without azp validation should work")
    void verify_audience_validation_without_azp() {
        // Generate a token with the default client ID
        String token = new IDTokenGenerator(false).next();
        LOGGER.debug("[DEBUG_LOG] Generated token: " + token);

        // Print the token headers using NonValidatingJwtParser to debug
        try {
            var decoder = NonValidatingJwtParser.builder().build();
            var decoded = decoder.decode(token);
            decoded.ifPresent(jwt -> {
                LOGGER.debug("[DEBUG_LOG] Token headers: " + jwt.getHeader().orElse(null));
                LOGGER.debug("[DEBUG_LOG] Token kid: " + jwt.getKid().orElse("null"));
                LOGGER.debug("[DEBUG_LOG] Token body: " + jwt.getBody().orElse(null));

                // Add more detailed debugging for audience claim
                jwt.getBody().ifPresent(body -> {
                    if (body.containsKey("aud")) {
                        LOGGER.debug("[DEBUG_LOG] Audience claim found: " + body.get("aud"));
                        LOGGER.debug("[DEBUG_LOG] Audience claim type: " + body.get("aud").getValueType());
                    } else {
                        LOGGER.debug("[DEBUG_LOG] No audience claim found in token");
                    }

                    if (body.containsKey("azp")) {
                        LOGGER.debug("[DEBUG_LOG] AZP claim found: " + body.get("azp"));
                    } else {
                        LOGGER.debug("[DEBUG_LOG] No azp claim found in token");
                    }
                });
            });
        } catch (Exception e) {
            System.err.println("[DEBUG_LOG] Error decoding token: " + e.getMessage());
        }

        // Create an IssuerConfig with the correct audience but no client ID
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(TestTokenProducer.ISSUER)
                .expectedAudience(IDTokenGenerator.DEFAULT_CLIENT_ID)
                .jwksKeyLoader(jwksKeyLoader)
                .build();

        LOGGER.debug("[DEBUG_LOG] IssuerConfig: issuer=" + issuerConfig.getIssuer() +
                     ", expectedAudience=" + issuerConfig.getExpectedAudience() +
                     ", expectedClientId=" + issuerConfig.getExpectedClientId());

        // Create a token factory with the issuer config
        tokenFactory = TokenFactory.builder()
                .issuerConfigs(List.of(issuerConfig))
                .build();

        // Verify the token is accepted
        Optional<IdTokenContent> result = tokenFactory.createIdToken(token);
        assertTrue(result.isPresent(), "Token with valid audience should be accepted");
    }

    @Test
    @DisplayName("AZP validation without audience validation should work")
    void verify_azp_validation_without_audience() {
        // Generate a token with the default client ID
        String token = new IDTokenGenerator(false).next();

        // Create an IssuerConfig with the correct client ID but no audience
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(TestTokenProducer.ISSUER)
                .expectedClientId(IDTokenGenerator.DEFAULT_CLIENT_ID)
                .jwksKeyLoader(jwksKeyLoader)
                .build();

        // Create a token factory with the issuer config
        tokenFactory = TokenFactory.builder()
                .issuerConfigs(List.of(issuerConfig))
                .build();

        // Verify the token is accepted
        Optional<IdTokenContent> result = tokenFactory.createIdToken(token);
        assertTrue(result.isPresent(), "Token with valid azp should be accepted");
    }

    @Test
    @DisplayName("Token with missing azp claim should be rejected when validation is enabled")
    void verify_missing_azp_rejected() {
        // Generate a token with a specific client ID that has no azp claim
        String token = new IDTokenGenerator(false, null).next();

        // Create an IssuerConfig that requires azp validation
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(TestTokenProducer.ISSUER)
                .expectedClientId(IDTokenGenerator.DEFAULT_CLIENT_ID)
                .jwksKeyLoader(jwksKeyLoader)
                .build();

        // Create a token factory with the issuer config
        tokenFactory = TokenFactory.builder()
                .issuerConfigs(List.of(issuerConfig))
                .build();

        // Verify the token is rejected
        Optional<IdTokenContent> result = tokenFactory.createIdToken(token);
        assertTrue(result.isEmpty(), "Token with missing azp claim should be rejected");
    }
}
