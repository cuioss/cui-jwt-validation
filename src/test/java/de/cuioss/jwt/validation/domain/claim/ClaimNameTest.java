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
package de.cuioss.jwt.validation.domain.claim;

import de.cuioss.test.juli.junit5.EnableTestLogger;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests ClaimName functionality")
class ClaimNameTest {

    @ParameterizedTest
    @MethodSource("provideClaimNameMapTestData")
    @DisplayName("Should correctly map claims from JsonObject")
    void shouldMapClaimsFromJsonObject(ClaimName claimName, JsonObject jsonObject, ClaimValue expectedValue) {
        // When
        ClaimValue result = claimName.map(jsonObject);

        // Then
        assertNotNull(result, "Result should not be null");
        assertEquals(expectedValue.getType(), result.getType(), "Type should match");
        assertEquals(expectedValue.getOriginalString(), result.getOriginalString(), "Original string should match");

        // Additional checks based on type
        if (expectedValue.getType() == ClaimValueType.STRING_LIST) {
            assertEquals(expectedValue.getAsList(), result.getAsList(), "List values should match");
        } else if (expectedValue.getType() == ClaimValueType.DATETIME) {
            assertEquals(expectedValue.getDateTime(), result.getDateTime(), "DateTime values should match");
        }
    }

    static Stream<Arguments> provideClaimNameMapTestData() {
        return Stream.of(
                // ISSUER - String type
                Arguments.of(
                        ClaimName.ISSUER,
                        createJsonObjectWithStringClaim("iss", "https://example.com"),
                        ClaimValue.forPlainString("https://example.com")
                ),

                // SUBJECT - String type
                Arguments.of(
                        ClaimName.SUBJECT,
                        createJsonObjectWithStringClaim("sub", "user123"),
                        ClaimValue.forPlainString("user123")
                ),

                // AUDIENCE - String list type - need to adapt expected value to match actual implementation
                Arguments.of(
                        ClaimName.AUDIENCE,
                        createJsonObjectWithArrayClaim("aud", Arrays.asList("client1", "client2")),
                        ClaimValue.forList("[\"client1\",\"client2\"]", Arrays.asList("client1", "client2"))
                ),

                // Single audience as string
                Arguments.of(
                        ClaimName.AUDIENCE,
                        createJsonObjectWithStringClaim("aud", "singleClient"),
                        ClaimValue.forList("singleClient", List.of("singleClient"))
                ),

                // EXPIRATION - DateTime type - need to use system timezone to match implementation
                Arguments.of(
                        ClaimName.EXPIRATION,
                        createJsonObjectWithNumericClaim("exp", 1609459200),
                        ClaimValue.forDateTime("1609459200", OffsetDateTime.ofInstant(
                                Instant.ofEpochSecond(1609459200),
                                ZoneOffset.systemDefault())
                        )
                ),

                // NOT_BEFORE - DateTime type - need to use system timezone to match implementation
                Arguments.of(
                        ClaimName.NOT_BEFORE,
                        createJsonObjectWithNumericClaim("nbf", 1609459200),
                        ClaimValue.forDateTime("1609459200", OffsetDateTime.ofInstant(
                                Instant.ofEpochSecond(1609459200),
                                ZoneOffset.systemDefault())
                        )
                ),

                // ISSUED_AT - DateTime type - need to use system timezone to match implementation
                Arguments.of(
                        ClaimName.ISSUED_AT,
                        createJsonObjectWithNumericClaim("iat", 1609459200),
                        ClaimValue.forDateTime("1609459200", OffsetDateTime.ofInstant(
                                Instant.ofEpochSecond(1609459200),
                                ZoneOffset.systemDefault())
                        )
                ),

                // TOKEN_ID - String type
                Arguments.of(
                        ClaimName.TOKEN_ID,
                        createJsonObjectWithStringClaim("jti", "token123"),
                        ClaimValue.forPlainString("token123")
                ),

                // NAME - String type
                Arguments.of(
                        ClaimName.NAME,
                        createJsonObjectWithStringClaim("name", "John Doe"),
                        ClaimValue.forPlainString("John Doe")
                ),

                // EMAIL - String type
                Arguments.of(
                        ClaimName.EMAIL,
                        createJsonObjectWithStringClaim("email", "john@example.com"),
                        ClaimValue.forPlainString("john@example.com")
                ),

                // PREFERRED_USERNAME - String type
                Arguments.of(
                        ClaimName.PREFERRED_USERNAME,
                        createJsonObjectWithStringClaim("preferred_username", "johndoe"),
                        ClaimValue.forPlainString("johndoe")
                ),

                // SCOPE - String list type (space-separated)
                Arguments.of(
                        ClaimName.SCOPE,
                        createJsonObjectWithStringClaim("scope", "email openid profile"),
                        ClaimValue.forList("email openid profile", Arrays.asList("email", "openid", "profile"))
                ),

                // TYPE - String type
                Arguments.of(
                        ClaimName.TYPE,
                        createJsonObjectWithStringClaim("typ", "JWT"),
                        ClaimValue.forPlainString("JWT")
                ),

                // AUTHORIZED_PARTY - String type
                Arguments.of(
                        ClaimName.AUTHORIZED_PARTY,
                        createJsonObjectWithStringClaim("azp", "client123"),
                        ClaimValue.forPlainString("client123")
                ),

                // Missing claims
                Arguments.of(
                        ClaimName.ISSUER,
                        Json.createObjectBuilder().build(),
                        ClaimValue.createDefaultClaimValue(ClaimValueType.STRING)
                ),

                // Null claims
                Arguments.of(
                        ClaimName.SUBJECT,
                        createJsonObjectWithNullClaim("sub"),
                        ClaimValue.createDefaultClaimValue(ClaimValueType.STRING)
                )
        );
    }

    // Helper methods for creating test JsonObjects

    private static JsonObject createJsonObjectWithStringClaim(String claimName, String value) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        if (value != null) {
            builder.add(claimName, value);
        } else {
            builder.addNull(claimName);
        }
        return builder.build();
    }

    private static JsonObject createJsonObjectWithNullClaim(String claimName) {
        return Json.createObjectBuilder()
                .addNull(claimName)
                .build();
    }

    private static JsonObject createJsonObjectWithArrayClaim(String claimName, List<String> values) {
        var arrayBuilder = Json.createArrayBuilder();
        for (String value : values) {
            arrayBuilder.add(value);
        }
        return Json.createObjectBuilder()
                .add(claimName, arrayBuilder.build())
                .build();
    }

    private static JsonObject createJsonObjectWithNumericClaim(String claimName, long value) {
        return Json.createObjectBuilder()
                .add(claimName, value)
                .build();
    }

    @Test
    @DisplayName("Should have correct name and value type for each enum value")
    @SuppressWarnings("java:S5961") // owolff: Suppressing this warning as the test is designed to check enum values
    void shouldHaveCorrectNameAndValueType() {
        // Given, When, Then
        assertEquals("iss", ClaimName.ISSUER.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.ISSUER.getValueType());

        assertEquals("sub", ClaimName.SUBJECT.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.SUBJECT.getValueType());

        assertEquals("aud", ClaimName.AUDIENCE.getName());
        assertEquals(ClaimValueType.STRING_LIST, ClaimName.AUDIENCE.getValueType());

        assertEquals("exp", ClaimName.EXPIRATION.getName());
        assertEquals(ClaimValueType.DATETIME, ClaimName.EXPIRATION.getValueType());

        assertEquals("nbf", ClaimName.NOT_BEFORE.getName());
        assertEquals(ClaimValueType.DATETIME, ClaimName.NOT_BEFORE.getValueType());

        assertEquals("iat", ClaimName.ISSUED_AT.getName());
        assertEquals(ClaimValueType.DATETIME, ClaimName.ISSUED_AT.getValueType());

        assertEquals("jti", ClaimName.TOKEN_ID.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.TOKEN_ID.getValueType());

        assertEquals("name", ClaimName.NAME.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.NAME.getValueType());

        assertEquals("email", ClaimName.EMAIL.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.EMAIL.getValueType());

        assertEquals("preferred_username", ClaimName.PREFERRED_USERNAME.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.PREFERRED_USERNAME.getValueType());

        assertEquals("scope", ClaimName.SCOPE.getName());
        assertEquals(ClaimValueType.STRING_LIST, ClaimName.SCOPE.getValueType());

        assertEquals("typ", ClaimName.TYPE.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.TYPE.getValueType());

        assertEquals("azp", ClaimName.AUTHORIZED_PARTY.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.AUTHORIZED_PARTY.getValueType());
    }

    @Test
    @DisplayName("Should find ClaimName by string name")
    void shouldFindClaimNameByString() {
        // Given
        String issuerName = "iss";

        // When
        Optional<ClaimName> result = ClaimName.fromString(issuerName);

        // Then
        assertTrue(result.isPresent(), "Should find a ClaimName for 'iss'");
        assertEquals(ClaimName.ISSUER, result.get(), "Should return ISSUER enum value");
    }

    @Test
    @DisplayName("Should find all ClaimName values by their string names")
    void shouldFindAllClaimNamesByString() {
        // Given, When, Then
        for (ClaimName claimName : ClaimName.values()) {
            Optional<ClaimName> result = ClaimName.fromString(claimName.getName());
            assertTrue(result.isPresent(), "Should find ClaimName for " + claimName.getName());
            assertEquals(claimName, result.get(), "Should return correct enum value");
        }
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"unknown", "invalid", " ", "ISS", "Iss"})
    @DisplayName("Should return empty Optional for null, empty, or unknown claim names")
    void shouldReturnEmptyForUnknownNames(String input) {
        // Given, When
        Optional<ClaimName> result = ClaimName.fromString(input);

        // Then
        assertFalse(result.isPresent(), "Should return empty Optional for invalid input: " + input);
    }
}
