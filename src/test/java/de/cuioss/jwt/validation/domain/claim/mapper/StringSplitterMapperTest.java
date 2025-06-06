/**
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.validation.domain.claim.mapper;

import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.domain.claim.ClaimValueType;
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

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests StringSplitterMapper functionality")
class StringSplitterMapperTest {

    private static final String CLAIM_NAME = "roles";
    private final StringSplitterMapper commaMapper = new StringSplitterMapper(',');

    @ParameterizedTest
    @MethodSource("provideSeparatorTestCases")
    @DisplayName("Should correctly map values with different separators")
    void shouldMapValuesWithDifferentSeparators(char separator, String input, List<String> expected) {
        // Given
        StringSplitterMapper mapper = new StringSplitterMapper(separator);
        JsonObject jsonObject = createJsonObjectWithStringClaim(CLAIM_NAME, input);

        // When
        ClaimValue result = mapper.map(jsonObject, CLAIM_NAME);

        // Then
        assertNotNull(result, "Result should not be null");
        assertEquals(input, result.getOriginalString(), "Original string should be preserved");
        assertEquals(ClaimValueType.STRING_LIST, result.getType(), "Type should be STRING_LIST");
        assertEquals(expected, result.getAsList(), "Values should be correctly parsed");
    }

    static Stream<Arguments> provideSeparatorTestCases() {
        return Stream.of(
                // separator, input string, expected list
                Arguments.of(',', "admin,user,manager", Arrays.asList("admin", "user", "manager")),
                Arguments.of(':', "admin:user:manager", Arrays.asList("admin", "user", "manager")),
                Arguments.of(';', "admin;user;manager", Arrays.asList("admin", "user", "manager")),
                Arguments.of('|', "admin|user|manager", Arrays.asList("admin", "user", "manager"))
        );
    }

    @ParameterizedTest
    @MethodSource("provideInputFormatTestCases")
    @DisplayName("Should handle different input formats")
    void shouldHandleDifferentInputFormats(String input, List<String> expected, String testDescription) {
        // Given
        JsonObject jsonObject = createJsonObjectWithStringClaim(CLAIM_NAME, input);

        // When
        ClaimValue result = commaMapper.map(jsonObject, CLAIM_NAME);

        // Then
        assertNotNull(result, "Result should not be null");
        assertEquals(input, result.getOriginalString(), "Original string should be preserved");
        assertEquals(ClaimValueType.STRING_LIST, result.getType(), "Type should be STRING_LIST");
        assertEquals(expected, result.getAsList(), testDescription);
    }

    static Stream<Arguments> provideInputFormatTestCases() {
        return Stream.of(
                // input string, expected list, test description
                Arguments.of("  admin  ,  user  ,  manager  ",
                        Arrays.asList("admin", "user", "manager"),
                        "Values should be correctly parsed with whitespace trimmed"),
                Arguments.of("admin,,user,,manager",
                        Arrays.asList("admin", "user", "manager"),
                        "Empty segments should be omitted"),
                Arguments.of("role1,role-with-dash,role_with_underscore,role.with.dots,role@with@at",
                        Arrays.asList("role1", "role-with-dash", "role_with_underscore", "role.with.dots", "role@with@at"),
                        "Values with special characters should be correctly parsed")
        );
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t", "\n"})
    @DisplayName("Should handle null, empty, and whitespace inputs")
    void shouldHandleSpecialInputs(String input) {
        // Given
        JsonObject jsonObject = input == null
                ? createJsonObjectWithNullClaim(CLAIM_NAME)
                : createJsonObjectWithStringClaim(CLAIM_NAME, input);

        // When
        ClaimValue result = commaMapper.map(jsonObject, CLAIM_NAME);

        // Then
        assertNotNull(result, "Result should not be null");
        assertEquals(input, result.getOriginalString(), "Original string should be preserved");
        assertEquals(ClaimValueType.STRING_LIST, result.getType(), "Type should be STRING_LIST");
        assertTrue(result.getAsList().isEmpty(), "Value list should be empty");
    }

    @Test
    @DisplayName("Should handle missing claim")
    void shouldHandleMissingClaim() {
        // Given
        JsonObject jsonObject = Json.createObjectBuilder().build();

        // When
        ClaimValue result = commaMapper.map(jsonObject, CLAIM_NAME);

        // Then
        assertNotNull(result, "Result should not be null");
        assertNull(result.getOriginalString(), "Original string should be null");
        assertEquals(ClaimValueType.STRING_LIST, result.getType(), "Type should be STRING_LIST");
        assertTrue(result.getAsList().isEmpty(), "Value list should be empty");
    }

    @ParameterizedTest
    @MethodSource("provideUnsupportedValueTypes")
    @DisplayName("Should throw exception for unsupported value types")
    void shouldThrowExceptionForUnsupportedValueTypes(JsonObject jsonObject, String valueTypeName) {
        // When, Then
        assertThrows(IllegalArgumentException.class, () -> commaMapper.map(jsonObject, CLAIM_NAME),
                "Should throw IllegalArgumentException for " + valueTypeName + " value type");
    }

    static Stream<Arguments> provideUnsupportedValueTypes() {
        return Stream.of(
                // JsonObject, value type name
                Arguments.of(
                        Json.createObjectBuilder()
                                .add(CLAIM_NAME, Json.createArrayBuilder()
                                        .add("admin")
                                        .add("user")
                                        .add("manager")
                                        .build())
                                .build(),
                        "array"
                ),
                Arguments.of(
                        Json.createObjectBuilder()
                                .add(CLAIM_NAME, 123)
                                .build(),
                        "number"
                ),
                Arguments.of(
                        Json.createObjectBuilder()
                                .add(CLAIM_NAME, true)
                                .build(),
                        "boolean"
                ),
                Arguments.of(
                        Json.createObjectBuilder()
                                .add(CLAIM_NAME, Json.createObjectBuilder().add("key", "value").build())
                                .build(),
                        "object"
                )
        );
    }

    @Test
    @DisplayName("Should throw exception when constructor is called with null")
    void shouldThrowExceptionForNullSplitChar() {
        // When, Then
        assertThrows(NullPointerException.class, () -> new StringSplitterMapper(null),
                "Should throw NullPointerException when constructor is called with null");
    }

    // Helper methods

    private JsonObject createJsonObjectWithStringClaim(String claimName, String value) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        if (value != null) {
            builder.add(claimName, value);
        } else {
            builder.addNull(claimName);
        }
        return builder.build();
    }

    private JsonObject createJsonObjectWithNullClaim(String claimName) {
        return Json.createObjectBuilder()
                .addNull(claimName)
                .build();
    }
}
