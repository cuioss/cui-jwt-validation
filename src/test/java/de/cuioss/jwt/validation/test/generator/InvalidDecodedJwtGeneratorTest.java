/*
 * Copyright 2025 the original author or authors.
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
import de.cuioss.jwt.validation.pipeline.DecodedJwt;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link InvalidDecodedJwtGenerator}.
 */
@DisplayName("Tests InvalidDecodedJwtGenerator")
class InvalidDecodedJwtGeneratorTest {

    @Test
    @DisplayName("Should create DecodedJwt with default constructor")
    void shouldCreateDecodedJwtWithDefaultConstructor() {
        // Given a generator with default constructor
        var generator = new InvalidDecodedJwtGenerator();

        // When generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should be valid (since no mutations were applied)
        assertNotNull(jwt, "Generated JWT should not be null");
        assertTrue(jwt.getHeader().isPresent(), "JWT header should be present");
        assertTrue(jwt.getBody().isPresent(), "JWT body should be present");
        assertTrue(jwt.getSignature().isPresent(), "JWT signature should be present");
        assertTrue(jwt.getIssuer().isPresent(), "JWT issuer should be present");
        assertTrue(jwt.getKid().isPresent(), "JWT kid should be present");
        assertTrue(jwt.getAlg().isPresent(), "JWT algorithm should be present");
    }

    @ParameterizedTest
    @EnumSource(TokenType.class)
    @DisplayName("Should create DecodedJwt with specified validation type")
    void shouldCreateDecodedJwtWithSpecifiedTokenType(TokenType tokenType) {
        // Given a generator with specified validation type
        var generator = new InvalidDecodedJwtGenerator(tokenType);

        // When generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should be valid (since no mutations were applied)
        assertNotNull(jwt, "Generated JWT should not be null");
        assertTrue(jwt.getHeader().isPresent(), "JWT header should be present");
        assertTrue(jwt.getBody().isPresent(), "JWT body should be present");
        assertTrue(jwt.getSignature().isPresent(), "JWT signature should be present");
        assertTrue(jwt.getIssuer().isPresent(), "JWT issuer should be present");

        // And it should have the correct validation type
        jwt.getBody().ifPresent(body -> {
            assertTrue(body.containsKey("typ"), "JWT body should contain typ claim");
            assertEquals(tokenType.getTypeClaimName(), body.getString("typ"),
                    "JWT typ claim should match specified validation type");
        });
    }

    @Test
    @DisplayName("Should create DecodedJwt with missing issuer")
    void shouldCreateDecodedJwtWithMissingIssuer() {
        // Given a generator with missing issuer mutation
        var generator = new InvalidDecodedJwtGenerator().withMissingIssuer();

        // When generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should have a missing issuer
        assertNotNull(jwt, "Generated JWT should not be null");
        assertFalse(jwt.getIssuer().isPresent(), "JWT issuer should not be present");
    }

    @Test
    @DisplayName("Should create DecodedJwt with missing subject")
    void shouldCreateDecodedJwtWithMissingSubject() {
        // Given a generator with missing subject mutation
        var generator = new InvalidDecodedJwtGenerator().withMissingSubject();

        // When generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should have a missing subject
        assertNotNull(jwt, "Generated JWT should not be null");
        jwt.getBody().ifPresent(body -> {
            assertFalse(body.containsKey("sub"), "JWT body should not contain sub claim");
        });
    }

    @Test
    @DisplayName("Should create DecodedJwt with missing expiration")
    void shouldCreateDecodedJwtWithMissingExpiration() {
        // Given a generator with missing expiration mutation
        var generator = new InvalidDecodedJwtGenerator().withMissingExpiration();

        // When generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should have a missing expiration
        assertNotNull(jwt, "Generated JWT should not be null");
        jwt.getBody().ifPresent(body -> {
            assertFalse(body.containsKey("exp"), "JWT body should not contain exp claim");
        });
    }

    @Test
    @DisplayName("Should create DecodedJwt with expired validation")
    void shouldCreateDecodedJwtWithExpiredToken() {
        // Given a generator with expired validation mutation
        var generator = new InvalidDecodedJwtGenerator().withExpiredToken();

        // When generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should have an expired validation
        assertNotNull(jwt, "Generated JWT should not be null");
        jwt.getBody().ifPresent(body -> {
            assertTrue(body.containsKey("exp"), "JWT body should contain exp claim");
            // The validation is expired if the expiration time is in the past
            long expTime = body.getJsonNumber("exp").longValue();
            long currentTime = System.currentTimeMillis() / 1000;
            assertTrue(expTime < currentTime, "Token should be expired (exp < current time)");
        });
    }

    @Test
    @DisplayName("Should create DecodedJwt with missing key ID")
    void shouldCreateDecodedJwtWithMissingKeyId() {
        // Given a generator with missing key ID mutation
        var generator = new InvalidDecodedJwtGenerator().withMissingKeyId();

        // When generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should have a missing key ID
        assertNotNull(jwt, "Generated JWT should not be null");
        assertFalse(jwt.getKid().isPresent(), "JWT kid should not be present");
    }

    @Test
    @DisplayName("Should create DecodedJwt with missing validation type")
    void shouldCreateDecodedJwtWithMissingTokenType() {
        // Given a generator with missing validation type mutation
        var generator = new InvalidDecodedJwtGenerator().withMissingTokenType();

        // When generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should have a missing validation type
        assertNotNull(jwt, "Generated JWT should not be null");
        jwt.getBody().ifPresent(body -> {
            assertFalse(body.containsKey("typ"), "JWT body should not contain typ claim");
        });
    }

    @Test
    @DisplayName("Should create DecodedJwt with custom issuer")
    void shouldCreateDecodedJwtWithCustomIssuer() {
        // Given a generator with custom issuer mutation
        String customIssuer = "custom-issuer";
        var generator = new InvalidDecodedJwtGenerator().withCustomIssuer(customIssuer);

        // When generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should have the custom issuer
        assertNotNull(jwt, "Generated JWT should not be null");
        assertTrue(jwt.getIssuer().isPresent(), "JWT issuer should be present");
        assertEquals(customIssuer, jwt.getIssuer().get(), "JWT issuer should match custom issuer");
    }

    @Test
    @DisplayName("Should create DecodedJwt with missing audience for ID validation")
    void shouldCreateDecodedJwtWithMissingAudienceForIdToken() {
        // Given a generator for ID validation with missing audience mutation
        var generator = new InvalidDecodedJwtGenerator(TokenType.ID_TOKEN).withMissingAudience();

        // When generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should have a missing audience
        assertNotNull(jwt, "Generated JWT should not be null");
        jwt.getBody().ifPresent(body -> {
            assertFalse(body.containsKey("aud"), "JWT body should not contain aud claim");
        });
    }

    @Test
    @DisplayName("Should reset mutations")
    void shouldResetMutations() {
        // Given a generator with multiple mutations
        var generator = new InvalidDecodedJwtGenerator()
                .withMissingIssuer()
                .withMissingSubject()
                .withMissingExpiration();

        // When resetting the mutations
        generator.reset();

        // And generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should be valid (since mutations were reset)
        assertNotNull(jwt, "Generated JWT should not be null");
        assertTrue(jwt.getIssuer().isPresent(), "JWT issuer should be present");
        jwt.getBody().ifPresent(body -> {
            assertTrue(body.containsKey("sub"), "JWT body should contain sub claim");
            assertTrue(body.containsKey("exp"), "JWT body should contain exp claim");
        });
    }

    @Test
    @DisplayName("Should chain multiple mutations")
    void shouldChainMultipleMutations() {
        // Given a generator with multiple chained mutations
        var generator = new InvalidDecodedJwtGenerator()
                .withMissingIssuer()
                .withMissingSubject()
                .withMissingExpiration();

        // When generating a DecodedJwt
        DecodedJwt jwt = generator.next();

        // Then it should have all the specified mutations
        assertNotNull(jwt, "Generated JWT should not be null");
        assertFalse(jwt.getIssuer().isPresent(), "JWT issuer should not be present");
        jwt.getBody().ifPresent(body -> {
            assertFalse(body.containsKey("sub"), "JWT body should not contain sub claim");
            assertFalse(body.containsKey("exp"), "JWT body should not contain exp claim");
        });
    }
}