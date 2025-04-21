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
package de.cuioss.jwt.token.test.generator;

import de.cuioss.jwt.token.TokenFactory;
import de.cuioss.jwt.token.domain.token.AccessTokenContent;
import de.cuioss.jwt.token.domain.token.IdTokenContent;
import de.cuioss.jwt.token.flow.IssuerConfig;
import de.cuioss.jwt.token.flow.TokenFactoryConfig;
import de.cuioss.jwt.token.security.AlgorithmPreferences;
import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.jwt.token.test.generator.JwtTokenTamperingUtil.TamperingStrategy;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test class for {@link JwtTokenTamperingUtil}.
 * Demonstrates how to use the utility with AccessTokenGenerator and IDTokenGenerator.
 */
@EnableGeneratorController
@EnableTestLogger
class JwtTokenTamperingUtilTest {

    private static final String ISSUER = TestTokenProducer.ISSUER;
    private static final String CLIENT_ID = AccessTokenGenerator.DEFAULT_CLIENT_ID;
    private static final String AUDIENCE = CLIENT_ID;

    private TokenFactory tokenFactory;
    private AccessTokenGenerator accessTokenGenerator;
    private IDTokenGenerator idTokenGenerator;

    @BeforeEach
    void setUp() {
        // Create token factory with default configuration
        TokenFactoryConfig config = TokenFactoryConfig.builder().build();
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(ISSUER)
                .expectedAudience(AUDIENCE)
                .expectedClientId(CLIENT_ID)
                .jwksContent(JWKSFactory.createDefaultJwks())
                .algorithmPreferences(new AlgorithmPreferences())
                .build();
        tokenFactory = new TokenFactory(config, issuerConfig);

        // Create token generators
        accessTokenGenerator = new AccessTokenGenerator();
        idTokenGenerator = new IDTokenGenerator(false);
    }

    @Test
    @DisplayName("Should validate untampered access token")
    void shouldValidateUntamperedAccessToken() {
        // Given
        String token = accessTokenGenerator.next();

        // When
        Optional<AccessTokenContent> result = tokenFactory.createAccessToken(token);

        // Then
        assertTrue(result.isPresent(), "Untampered token should be valid");
    }

    @Test
    @DisplayName("Should validate untampered ID token")
    void shouldValidateUntamperedIdToken() {
        // Given
        String token = idTokenGenerator.next();

        // When
        Optional<IdTokenContent> result = tokenFactory.createIdToken(token);

        // Then
        assertTrue(result.isPresent(), "Untampered token should be valid");
    }

    @ParameterizedTest
    @EnumSource(TamperingStrategy.class)
    @DisplayName("Should reject tampered access token")
    void shouldRejectTamperedAccessToken(TamperingStrategy strategy) {
        // Given
        String originalToken = accessTokenGenerator.next();
        String tamperedToken = JwtTokenTamperingUtil.applyTamperingStrategy(originalToken, strategy);

        // Verify that the token was actually tampered
        assertNotEquals(originalToken, tamperedToken,
                "Token should be tampered using strategy: " + strategy.getDescription());

        // When
        Optional<AccessTokenContent> result = tokenFactory.createAccessToken(tamperedToken);

        // Then
        assertFalse(result.isPresent(),
                "Tampered token should be rejected. Strategy: " + strategy.getDescription());
    }

    @ParameterizedTest
    @EnumSource(TamperingStrategy.class)
    @DisplayName("Should reject tampered ID token")
    void shouldRejectTamperedIdToken(TamperingStrategy strategy) {
        // Given
        String originalToken = idTokenGenerator.next();
        String tamperedToken = JwtTokenTamperingUtil.applyTamperingStrategy(originalToken, strategy);

        // Verify that the token was actually tampered
        assertNotEquals(originalToken, tamperedToken,
                "Token should be tampered using strategy: " + strategy.getDescription());

        // When
        Optional<IdTokenContent> result = tokenFactory.createIdToken(tamperedToken);

        // Then
        assertFalse(result.isPresent(),
                "Tampered token should be rejected. Strategy: " + strategy.getDescription());
    }

    @Test
    @DisplayName("Should apply all tampering strategies to a token")
    void shouldApplyAllTamperingStrategiesToToken() {
        // Given
        String originalToken = accessTokenGenerator.next();

        // When/Then
        for (TamperingStrategy strategy : TamperingStrategy.values()) {
            String tamperedToken = JwtTokenTamperingUtil.applyTamperingStrategy(originalToken, strategy);
            assertNotEquals(originalToken, tamperedToken,
                    "Token should be tampered using strategy: " + strategy.getDescription());
        }
    }
}