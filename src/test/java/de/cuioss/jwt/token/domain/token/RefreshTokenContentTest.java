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
package de.cuioss.jwt.token.domain.token;

import de.cuioss.jwt.token.TokenType;
import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.valueobjects.ValueObjectTest;
import de.cuioss.test.valueobjects.api.contracts.VerifyConstructor;
import de.cuioss.test.valueobjects.api.property.PropertyConfig;
import de.cuioss.test.valueobjects.api.property.PropertyReflectionConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link RefreshTokenContent}.
 */
@PropertyReflectionConfig(skip = true)
@PropertyConfig(name = "rawToken", propertyClass = String.class, required = true)
@VerifyConstructor(of = "rawToken")
@DisplayName("Tests RefreshTokenContent functionality")
class RefreshTokenContentTest extends ValueObjectTest<RefreshTokenContent> {

    private static final String SAMPLE_TOKEN = TestTokenProducer.validSignedEmptyJWT();

    @Test
    @DisplayName("Should create RefreshTokenContent with valid token")
    void shouldCreateRefreshTokenContentWithValidToken() {
        // Given a valid token
        var token = SAMPLE_TOKEN;

        // When creating a RefreshTokenContent
        var refreshTokenContent = new RefreshTokenContent(token);

        // Then the content should be correctly initialized
        assertNotNull(refreshTokenContent, "RefreshTokenContent should not be null");
        assertEquals(token, refreshTokenContent.getRawToken(), "Raw token should match");
        assertEquals(TokenType.REFRESH_TOKEN, refreshTokenContent.getTokenType(), "Token type should be REFRESH_TOKEN");
    }

    @Test
    @DisplayName("Should throw NullPointerException when token is null")
    void shouldThrowExceptionWhenTokenIsNull() {
        // When creating a RefreshTokenContent with null token
        // Then an exception should be thrown
        assertThrows(NullPointerException.class, () -> new RefreshTokenContent(null),
                "Should throw NullPointerException for null token");
    }

    @Override
    protected RefreshTokenContent anyValueObject() {
        return new RefreshTokenContent(Generators.nonEmptyStrings().next());
    }
}