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
package de.cuioss.jwt.validation.domain.claim.mapper;

import de.cuioss.test.juli.junit5.EnableTestLogger;
import jakarta.json.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests ClaimMapperUtils functionality")
class ClaimMapperUtilsTest {

    private static final String CLAIM_NAME = "testClaim";

    @Test
    @DisplayName("doesNotContainClaim should return true when claim is missing")
    void doesNotContainClaimShouldReturnTrueWhenClaimIsMissing() {
        // Given
        JsonObject jsonObject = Json.createObjectBuilder().build();

        // When
        boolean result = ClaimMapperUtils.doesNotContainClaim(jsonObject, CLAIM_NAME);

        // Then
        assertTrue(result, "Should return true when claim is missing");
    }

    @Test
    @DisplayName("doesNotContainClaim should return false when claim exists")
    void doesNotContainClaimShouldReturnFalseWhenClaimExists() {
        // Given
        JsonObject jsonObject = Json.createObjectBuilder()
                .add(CLAIM_NAME, "value")
                .build();

        // When
        boolean result = ClaimMapperUtils.doesNotContainClaim(jsonObject, CLAIM_NAME);

        // Then
        assertFalse(result, "Should return false when claim exists");
    }

    @Test
    @DisplayName("doesNotContainClaim should return false when claim exists but is null")
    void doesNotContainClaimShouldReturnFalseWhenClaimExistsButIsNull() {
        // Given
        JsonObject jsonObject = Json.createObjectBuilder()
                .addNull(CLAIM_NAME)
                .build();

        // When
        boolean result = ClaimMapperUtils.doesNotContainClaim(jsonObject, CLAIM_NAME);

        // Then
        assertFalse(result, "Should return false when claim exists but is null");
    }

    @Test
    @DisplayName("getJsonValue should return empty Optional when claim is missing")
    void getJsonValueShouldReturnEmptyOptionalWhenClaimIsMissing() {
        // Given
        JsonObject jsonObject = Json.createObjectBuilder().build();

        // When
        Optional<JsonValue> result = ClaimMapperUtils.getJsonValue(jsonObject, CLAIM_NAME);

        // Then
        assertFalse(result.isPresent(), "Should return empty Optional when claim is missing");
    }

    @Test
    @DisplayName("getJsonValue should return empty Optional when claim is null")
    void getJsonValueShouldReturnEmptyOptionalWhenClaimIsNull() {
        // Given
        JsonObject jsonObject = Json.createObjectBuilder()
                .addNull(CLAIM_NAME)
                .build();

        // When
        Optional<JsonValue> result = ClaimMapperUtils.getJsonValue(jsonObject, CLAIM_NAME);

        // Then
        assertFalse(result.isPresent(), "Should return empty Optional when claim is null");
    }

    @Test
    @DisplayName("getJsonValue should return Optional with value when claim exists and is not null")
    void getJsonValueShouldReturnOptionalWithValueWhenClaimExistsAndIsNotNull() {
        // Given
        String value = "test-value";
        JsonObject jsonObject = Json.createObjectBuilder()
                .add(CLAIM_NAME, value)
                .build();

        // When
        Optional<JsonValue> result = ClaimMapperUtils.getJsonValue(jsonObject, CLAIM_NAME);

        // Then
        assertTrue(result.isPresent(), "Should return Optional with value when claim exists and is not null");
        assertEquals(JsonValue.ValueType.STRING, result.get().getValueType(), "Value type should be STRING");
    }

    @Test
    @DisplayName("isNullValue should return true when JsonValue is null")
    void isNullValueShouldReturnTrueWhenJsonValueIsNull() {
        // When
        boolean result = ClaimMapperUtils.isNullValue(null);

        // Then
        assertTrue(result, "Should return true when JsonValue is null");
    }

    @Test
    @DisplayName("isNullValue should return true when JsonValue is JSON null")
    void isNullValueShouldReturnTrueWhenJsonValueIsJsonNull() {
        // Given
        JsonValue jsonValue = JsonValue.NULL;

        // When
        boolean result = ClaimMapperUtils.isNullValue(jsonValue);

        // Then
        assertTrue(result, "Should return true when JsonValue is JSON null");
    }

    @Test
    @DisplayName("isNullValue should return false when JsonValue is not null")
    void isNullValueShouldReturnFalseWhenJsonValueIsNotNull() {
        // Given
        JsonValue jsonValue = Json.createObjectBuilder()
                .add("key", "value")
                .build();

        // When
        boolean result = ClaimMapperUtils.isNullValue(jsonValue);

        // Then
        assertFalse(result, "Should return false when JsonValue is not null");
    }

    @ParameterizedTest
    @ValueSource(strings = {"string", "123", "true"})
    @DisplayName("isNullValue should return false for various non-null JSON values")
    void isNullValueShouldReturnFalseForVariousNonNullJsonValues(String value) {
        // Given
        JsonValue jsonValue = Json.createObjectBuilder()
                .add("key", value)
                .build()
                .get("key");

        // When
        boolean result = ClaimMapperUtils.isNullValue(jsonValue);

        // Then
        assertFalse(result, "Should return false for non-null JSON value: " + value);
    }

    @Test
    @DisplayName("extractStringFromJsonValue should extract string from STRING value")
    void extractStringFromJsonValueShouldExtractStringFromStringValue() {
        // Given
        String value = "test-string";
        JsonObject jsonObject = Json.createObjectBuilder()
                .add(CLAIM_NAME, value)
                .build();
        JsonValue jsonValue = jsonObject.get(CLAIM_NAME);

        // When
        String result = ClaimMapperUtils.extractStringFromJsonValue(jsonObject, CLAIM_NAME, jsonValue);

        // Then
        assertEquals(value, result, "Should extract string value correctly");
    }

    @Test
    @DisplayName("extractStringFromJsonValue should extract string from NUMBER value")
    void extractStringFromJsonValueShouldExtractStringFromNumberValue() {
        // Given
        int value = 12345;
        JsonObject jsonObject = Json.createObjectBuilder()
                .add(CLAIM_NAME, value)
                .build();
        JsonValue jsonValue = jsonObject.get(CLAIM_NAME);

        // When
        String result = ClaimMapperUtils.extractStringFromJsonValue(jsonObject, CLAIM_NAME, jsonValue);

        // Then
        assertEquals(String.valueOf(value), result, "Should extract number as string correctly");
    }

    @Test
    @DisplayName("extractStringFromJsonValue should extract string from BOOLEAN value")
    void extractStringFromJsonValueShouldExtractStringFromBooleanValue() {
        // Given
        boolean value = true;
        JsonObject jsonObject = Json.createObjectBuilder()
                .add(CLAIM_NAME, value)
                .build();
        JsonValue jsonValue = jsonObject.get(CLAIM_NAME);

        // When
        String result = ClaimMapperUtils.extractStringFromJsonValue(jsonObject, CLAIM_NAME, jsonValue);

        // Then
        assertEquals(String.valueOf(value), result, "Should extract boolean as string correctly");
    }

    @Test
    @DisplayName("extractStringFromJsonValue should extract string from OBJECT value")
    void extractStringFromJsonValueShouldExtractStringFromObjectValue() {
        // Given
        JsonObject nestedObject = Json.createObjectBuilder()
                .add("key", "value")
                .build();
        JsonObject jsonObject = Json.createObjectBuilder()
                .add(CLAIM_NAME, nestedObject)
                .build();
        JsonValue jsonValue = jsonObject.get(CLAIM_NAME);

        // When
        String result = ClaimMapperUtils.extractStringFromJsonValue(jsonObject, CLAIM_NAME, jsonValue);

        // Then
        assertEquals(nestedObject.toString(), result, "Should extract object as string correctly");
    }

    @Test
    @DisplayName("extractStringsFromJsonArray should extract strings from array of strings")
    void extractStringsFromJsonArrayShouldExtractStringsFromArrayOfStrings() {
        // Given
        List<String> expectedValues = Arrays.asList("value1", "value2", "value3");
        JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
        for (String value : expectedValues) {
            arrayBuilder.add(value);
        }
        JsonArray jsonArray = arrayBuilder.build();

        // When
        List<String> result = ClaimMapperUtils.extractStringsFromJsonArray(jsonArray);

        // Then
        assertEquals(expectedValues.size(), result.size(), "Result size should match expected");
        for (int i = 0; i < expectedValues.size(); i++) {
            assertEquals(expectedValues.get(i), result.get(i), "Element at index " + i + " should match");
        }
    }

    @Test
    @DisplayName("extractStringsFromJsonArray should handle mixed types in array")
    void extractStringsFromJsonArrayShouldHandleMixedTypesInArray() {
        // Given
        JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
        arrayBuilder.add("string-value");
        arrayBuilder.add(123);
        arrayBuilder.add(true);
        arrayBuilder.add(Json.createObjectBuilder().add("key", "value").build());
        JsonArray jsonArray = arrayBuilder.build();

        // When
        List<String> result = ClaimMapperUtils.extractStringsFromJsonArray(jsonArray);

        // Then
        assertEquals(4, result.size(), "Result size should be 4");
        assertEquals("string-value", result.get(0), "First element should be string-value");
        // Note: The exact string representation of non-string values may vary depending on the JSON implementation
    }

    @Test
    @DisplayName("extractStringsFromJsonArray should handle empty array")
    void extractStringsFromJsonArrayShouldHandleEmptyArray() {
        // Given
        JsonArray jsonArray = Json.createArrayBuilder().build();

        // When
        List<String> result = ClaimMapperUtils.extractStringsFromJsonArray(jsonArray);

        // Then
        assertTrue(result.isEmpty(), "Result should be empty");
    }
}
