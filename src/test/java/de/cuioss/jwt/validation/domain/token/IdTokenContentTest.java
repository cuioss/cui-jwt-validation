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
package de.cuioss.jwt.validation.domain.token;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link IdTokenContent}.
 */
@DisplayName("Tests IdTokenContent functionality")
class IdTokenContentTest {

    private static final String SAMPLE_TOKEN = TestTokenGenerators.idTokens().next().getRawToken();
    private static final String TEST_NAME = "Test User";
    private static final String TEST_EMAIL = "test@example.com";
    private static final List<String> TEST_AUDIENCE = Arrays.asList("client1", "client2");

    @Test
    @DisplayName("Should create IdTokenContent with valid parameters")
    void shouldCreateIdTokenContentWithValidParameters() {
        // Given valid parameters
        Map<String, ClaimValue> claims = new HashMap<>();
        String rawToken = SAMPLE_TOKEN;

        // When creating an IdTokenContent
        var idTokenContent = new IdTokenContent(claims, rawToken);

        // Then the content should be correctly initialized
        assertNotNull(idTokenContent, "IdTokenContent should not be null");
        assertEquals(claims, idTokenContent.getClaims(), "Claims should match");
        assertEquals(rawToken, idTokenContent.getRawToken(), "Raw validation should match");
        assertEquals(TokenType.ID_TOKEN, idTokenContent.getTokenType(), "Token type should be ID_TOKEN");
    }

    @Test
    @DisplayName("Should return audience correctly when present")
    void shouldReturnAudienceCorrectlyWhenPresent() {
        // Given an IdTokenContent with audience claim
        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.AUDIENCE.getName(), ClaimValue.forList(TEST_AUDIENCE.toString(), TEST_AUDIENCE));
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        // When getting the audience
        List<String> audience = idTokenContent.getAudience();

        // Then the audience should contain the correct values
        assertEquals(TEST_AUDIENCE, audience, "Audience should match");
    }

    @Test
    @DisplayName("Should throw exception when audience not present")
    void shouldThrowExceptionWhenAudienceNotPresent() {
        // Given an IdTokenContent without audience claim
        Map<String, ClaimValue> claims = new HashMap<>();
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        // When getting the audience
        // Then an exception should be thrown
        assertThrows(IllegalStateException.class, idTokenContent::getAudience,
                "Should throw IllegalStateException for missing audience claim");
    }

    @Test
    @DisplayName("Should return name when present")
    void shouldReturnNameWhenPresent() {
        // Given an IdTokenContent with name claim
        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.NAME.getName(), ClaimValue.forPlainString(TEST_NAME));
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        // When getting the name
        Optional<String> name = idTokenContent.getName();

        // Then the name should be present and contain the correct value
        assertTrue(name.isPresent(), "Name should be present");
        assertEquals(TEST_NAME, name.get(), "Name should match");
    }

    @Test
    @DisplayName("Should return empty name when not present")
    void shouldReturnEmptyNameWhenNotPresent() {
        // Given an IdTokenContent without name claim
        Map<String, ClaimValue> claims = new HashMap<>();
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        // When getting the name
        Optional<String> name = idTokenContent.getName();

        // Then the name should be empty
        assertTrue(name.isEmpty(), "Name should be empty");
    }

    @Test
    @DisplayName("Should return email when present")
    void shouldReturnEmailWhenPresent() {
        // Given an IdTokenContent with email claim
        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.EMAIL.getName(), ClaimValue.forPlainString(TEST_EMAIL));
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        // When getting the email
        Optional<String> email = idTokenContent.getEmail();

        // Then the email should be present and contain the correct value
        assertTrue(email.isPresent(), "Email should be present");
        assertEquals(TEST_EMAIL, email.get(), "Email should match");
    }

    @Test
    @DisplayName("Should return empty email when not present")
    void shouldReturnEmptyEmailWhenNotPresent() {
        // Given an IdTokenContent without email claim
        Map<String, ClaimValue> claims = new HashMap<>();
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        // When getting the email
        Optional<String> email = idTokenContent.getEmail();

        // Then the email should be empty
        assertTrue(email.isEmpty(), "Email should be empty");
    }

}
