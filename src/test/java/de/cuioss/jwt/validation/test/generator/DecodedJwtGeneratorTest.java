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
package de.cuioss.jwt.validation.test.generator;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.flow.DecodedJwt;
import de.cuioss.test.generator.Generators;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link DecodedJwtGenerator}.
 */
@DisplayName("Tests DecodedJwtGenerator")
class DecodedJwtGeneratorTest {

    @Test
    @DisplayName("Should create valid DecodedJwt with default constructor")
    void shouldCreateValidDecodedJwtWithDefaultConstructor() {
        // Given a generator with default constructor
        var generator = new DecodedJwtGenerator();

        // When generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should be valid
        assertNotNull(jwt, "Generated JWT should not be null");
        assertTrue(jwt.getHeader().isPresent(), "JWT header should be present");
        assertTrue(jwt.getBody().isPresent(), "JWT body should be present");
        assertTrue(jwt.getSignature().isPresent(), "JWT signature should be present");
        assertTrue(jwt.getIssuer().isPresent(), "JWT issuer should be present");
        assertTrue(jwt.getKid().isPresent(), "JWT kid should be present");
        assertTrue(jwt.getAlg().isPresent(), "JWT algorithm should be present");
        assertEquals("RS256", jwt.getAlg().get(), "JWT algorithm should be RS256");

        // And it should have the correct validation type
        jwt.getBody().ifPresent(body -> {
            assertTrue(body.containsKey("typ"), "JWT body should contain typ claim");
            assertEquals(TokenType.ACCESS_TOKEN.getTypeClaimName(), body.getString("typ"),
                    "JWT typ claim should match ACCESS_TOKEN type");
        });
    }

    @ParameterizedTest
    @EnumSource(TokenType.class)
    @DisplayName("Should create valid DecodedJwt with specified validation type")
    void shouldCreateValidDecodedJwtWithSpecifiedTokenType(TokenType tokenType) {
        // Given a generator with specified validation type
        var generator = new DecodedJwtGenerator(tokenType);

        // When generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should be valid
        assertNotNull(jwt, "Generated JWT should not be null");
        assertTrue(jwt.getHeader().isPresent(), "JWT header should be present");
        assertTrue(jwt.getBody().isPresent(), "JWT body should be present");
        assertTrue(jwt.getSignature().isPresent(), "JWT signature should be present");
        assertTrue(jwt.getIssuer().isPresent(), "JWT issuer should be present");
        assertTrue(jwt.getKid().isPresent(), "JWT kid should be present");
        assertTrue(jwt.getAlg().isPresent(), "JWT algorithm should be present");

        // And it should have the correct validation type
        jwt.getBody().ifPresent(body -> {
            assertTrue(body.containsKey("typ"), "JWT body should contain typ claim");
            assertEquals(tokenType.getTypeClaimName(), body.getString("typ"),
                    "JWT typ claim should match specified validation type");

            // Check for validation-type specific claims
            switch (tokenType) {
                case ACCESS_TOKEN:
                    assertTrue(body.containsKey("scope"), "ACCESS_TOKEN should contain scope claim");
                    break;
                case ID_TOKEN:
                    assertTrue(body.containsKey("aud"), "ID_TOKEN should contain aud claim");
                    assertTrue(body.containsKey("email"), "ID_TOKEN should contain email claim");
                    break;
                case REFRESH_TOKEN:
                    // No specific claims required for REFRESH_TOKEN
                    break;
                default:
                    // No specific claims required for UNKNOWN
                    break;
            }
        });
    }

    @Test
    @DisplayName("Should generate different DecodedJwt instances on each call")
    void shouldGenerateDifferentDecodedJwtInstancesOnEachCall() {
        // Given a generator
        var generator = new DecodedJwtGenerator();

        // When generating multiple DecodedJwt instances
        DecodedJwt jwt1 = generator.next();
        DecodedJwt jwt2 = generator.next();
        DecodedJwt jwt3 = generator.next();

        // Then they should all be different
        assertNotEquals(jwt1.getRawToken(), jwt2.getRawToken(), "Generated JWTs should be different");
        assertNotEquals(jwt1.getRawToken(), jwt3.getRawToken(), "Generated JWTs should be different");
        assertNotEquals(jwt2.getRawToken(), jwt3.getRawToken(), "Generated JWTs should be different");
    }

    @Test
    @DisplayName("Should work with Generators utility")
    void shouldWorkWithGeneratorsUtility() {
        // Given a generator created through Generators utility
        var generator = Generators.fixedValues(new DecodedJwtGenerator().next());

        // When generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should be valid
        assertNotNull(jwt, "Generated JWT should not be null");
        assertTrue(jwt.getHeader().isPresent(), "JWT header should be present");
        assertTrue(jwt.getBody().isPresent(), "JWT body should be present");
        assertTrue(jwt.getSignature().isPresent(), "JWT signature should be present");
    }
}
