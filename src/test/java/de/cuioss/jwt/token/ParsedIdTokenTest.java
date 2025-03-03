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

import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger
@DisplayName("Tests ParsedIdToken functionality")
class ParsedIdTokenTest {


    @Nested
    @DisplayName("Token Parsing Tests")
    class TokenParsingTests {

        @Test
        @DisplayName("Should handle valid token")
        void shouldHandleValidToken() {
            String initialTokenString = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_ID_TOKEN);

            var parsedIdToken = ParsedIdToken.fromTokenString(initialTokenString, TestTokenProducer.DEFAULT_TOKEN_PARSER);

            assertTrue(parsedIdToken.isPresent(), "Token should be parsed successfully");
            assertEquals(initialTokenString, parsedIdToken.get().getTokenString(), "Token string should match original");
            assertFalse(parsedIdToken.get().isExpired(), "Token should not be expired");
            assertEquals(TokenType.ID_TOKEN, parsedIdToken.get().getType(), "Token type should be ID_TOKEN");
        }

        @Test
        @DisplayName("Should handle invalid token")
        void shouldHandleInvalidToken() {
            var parsedIdToken = ParsedIdToken.fromTokenString("invalid-token", TestTokenProducer.DEFAULT_TOKEN_PARSER);
            assertFalse(parsedIdToken.isPresent(), "Invalid token should not be parsed");
        }
    }

    @Nested
    @DisplayName("Token Claims Tests")
    class TokenClaimsTests {

        @Test
        @DisplayName("Should handle email claim")
        void shouldHandleEmail() {
            String initialTokenString = TestTokenProducer.validSignedJWTWithClaims(TestTokenProducer.SOME_ID_TOKEN);

            var parsedIdToken = ParsedIdToken.fromTokenString(initialTokenString, TestTokenProducer.DEFAULT_TOKEN_PARSER);
            assertTrue(parsedIdToken.isPresent(), "Token should be parsed successfully");
            assertTrue(parsedIdToken.get().getEmail().isPresent(), "Email should be present");
            assertEquals("hello@world.com", parsedIdToken.get().getEmail().get(), "Email should match expected value");
        }
    }
}
