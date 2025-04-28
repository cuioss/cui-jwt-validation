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
package de.cuioss.jwt.validation.test;

import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.domain.token.IdTokenContent;
import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.security.AlgorithmPreferences;
import de.cuioss.jwt.validation.test.JwtTokenTamperingUtil.TamperingStrategy;
import de.cuioss.jwt.validation.test.generator.AccessTokenGenerator;
import de.cuioss.jwt.validation.test.generator.IDTokenGenerator;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

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

    private TokenValidator tokenValidator;
    private AccessTokenGenerator accessTokenGenerator;
    private IDTokenGenerator idTokenGenerator;

    @BeforeEach
    void setUp() {
        // Create validation factory with default configuration
        ParserConfig config = ParserConfig.builder().build();
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(ISSUER)
                .expectedAudience(AUDIENCE)
                .expectedClientId(CLIENT_ID)
                .jwksContent(JWKSFactory.createDefaultJwks())
                .algorithmPreferences(new AlgorithmPreferences())
                .build();
        tokenValidator = new TokenValidator(config, issuerConfig);

        // Create validation generators
        accessTokenGenerator = new AccessTokenGenerator();
        idTokenGenerator = new IDTokenGenerator(false);
    }

    @Test
    @DisplayName("Should validate untampered access validation")
    void shouldValidateUntamperedAccessToken() {
        // Given
        String token = accessTokenGenerator.next();

        // When
        Optional<AccessTokenContent> result = tokenValidator.createAccessToken(token);

        // Then
        assertTrue(result.isPresent(), "Untampered validation should be valid");
    }

    @Test
    @DisplayName("Should validate untampered ID validation")
    void shouldValidateUntamperedIdToken() {
        // Given
        String token = idTokenGenerator.next();

        // When
        Optional<IdTokenContent> result = tokenValidator.createIdToken(token);

        // Then
        assertTrue(result.isPresent(), "Untampered validation should be valid");
    }

    @ParameterizedTest
    @EnumSource(TamperingStrategy.class)
    @DisplayName("Should reject tampered access validation")
    void shouldRejectTamperedAccessToken(TamperingStrategy strategy) {
        // Given
        String originalToken = accessTokenGenerator.next();
        String tamperedToken = JwtTokenTamperingUtil.applyTamperingStrategy(originalToken, strategy);

        // Verify that the validation was actually tampered
        assertNotEquals(originalToken, tamperedToken,
                "Token should be tampered using strategy: " + strategy.getDescription());

        // When
        Optional<AccessTokenContent> result = tokenValidator.createAccessToken(tamperedToken);

        // Then
        assertFalse(result.isPresent(),
                "Tampered validation should be rejected. Strategy: " + strategy.getDescription());
    }

    @ParameterizedTest
    @EnumSource(TamperingStrategy.class)
    @DisplayName("Should reject tampered ID validation")
    void shouldRejectTamperedIdToken(TamperingStrategy strategy) {
        // Given
        String originalToken = idTokenGenerator.next();
        String tamperedToken = JwtTokenTamperingUtil.applyTamperingStrategy(originalToken, strategy);

        // Verify that the validation was actually tampered
        assertNotEquals(originalToken, tamperedToken,
                "Token should be tampered using strategy: " + strategy.getDescription());

        // When
        Optional<IdTokenContent> result = tokenValidator.createIdToken(tamperedToken);

        // Then
        assertFalse(result.isPresent(),
                "Tampered validation should be rejected. Strategy: " + strategy.getDescription());
    }

    @Test
    @DisplayName("Should apply all tampering strategies to a validation")
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