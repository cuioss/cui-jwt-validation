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
import de.cuioss.test.valueobjects.junit5.contracts.ShouldBeSerializable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static de.cuioss.jwt.token.test.TestTokenProducer.REFRESH_TOKEN;
import static de.cuioss.jwt.token.test.TestTokenProducer.validSignedJWTWithClaims;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@EnableTestLogger
@DisplayName("Tests ParsedRefreshToken functionality")
class ParsedRefreshTokenTest implements ShouldBeSerializable<ParsedRefreshToken> {


    @Nested
    @DisplayName("Token Parsing Tests")
    class TokenParsingTests {

        @Test
        @DisplayName("Should handle valid token")
        void shouldHandleValidToken() {
            String initialToken = validSignedJWTWithClaims(REFRESH_TOKEN);
            var parsedRefreshToken = ParsedRefreshToken.fromTokenString(initialToken);

            assertEquals(initialToken, parsedRefreshToken.getTokenString(), "Token string should match original");
            assertFalse(parsedRefreshToken.isEmpty(), "Token should be present");
            assertEquals(TokenType.REFRESH_TOKEN, parsedRefreshToken.getType(), "Token type should be REFRESH_TOKEN");
        }

        @Test
        @DisplayName("Should handle invalid token")
        void shouldHandleInvalidToken() {
            var parsedRefreshToken = ParsedRefreshToken.fromTokenString("invalid-token");
            assertFalse(parsedRefreshToken.isEmpty(), "Invalid token should still be wrapped");
            assertEquals("invalid-token", parsedRefreshToken.getTokenString(), "Token string should match original");
        }
    }

    @Override
    public ParsedRefreshToken getUnderTest() {
        return ParsedRefreshToken.fromTokenString(validSignedJWTWithClaims(REFRESH_TOKEN));
    }
}
